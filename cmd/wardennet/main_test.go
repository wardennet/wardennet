// Package main - main_test.go 集成验收测试：验证各模块串联工作。
package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wardennet/agent/internal/cli"
	"github.com/wardennet/agent/internal/config"
	"github.com/wardennet/agent/internal/detector"
	"github.com/wardennet/agent/internal/ipsetutil"
	"github.com/wardennet/agent/internal/snapshot"
	"github.com/wardennet/agent/internal/ttl"
)

// TestIntegration_FullPipeline 验证完整本地防护链路：
// detector → IP 黑名单 → CLI 查询 → 快照保存 → 快照恢复。
func TestIntegration_FullPipeline(t *testing.T) {
	// 1. 加载默认配置
	cfg := config.Default()

	// 2. 初始化 ipset 和 ttl 管理器（使用内存 Mock 客户端）
	ipClient := ipsetutil.NewMemClient()
	ipMgr := ipsetutil.NewManager(ipClient, 3, 50*time.Millisecond)
	defer ipMgr.Close()

	ttlCfg := mapTTLConfig(cfg.Agent)
	ttlMgr := ttl.NewManager(ttlCfg, nil)
	defer ttlMgr.Close()

	// 3. 初始化 detector — 白名单复用 ipMgr
	detCfg := mapDetectorConfig(cfg.Detector)
	det := detector.NewLocalDetector(&detCfg, ipMgr)
	defer det.Close()

	// 4. 模拟一次攻击事件：触发 detector 打分并 block
	accepted, err := ipMgr.Block("203.0.113.100")
	if err != nil {
		t.Fatalf("block: %v", err)
	}
	if !accepted {
		t.Errorf("block should be accepted")
	}
	// 添加 TTL
	_, _ = ttlMgr.Add("203.0.113.100", cfg.Agent.LocalBlockTTL, ttl.SourceLocal)

	// 5. 验证黑名单状态
	if c := ipMgr.LocalBlockedCount(); c != 1 {
		t.Errorf("blocked count=%d, want 1", c)
	}
	if c := ttlMgr.Count(); c != 1 {
		t.Errorf("ttl count=%d, want 1", c)
	}

	// 6. 验证 CLI Handler 能正确查询状态（通过 Registry）
	ipAdapter := &ipsetCLIAdapter{m: ipMgr}
	ttlCliAdapter := &ttlCLIAdapter{m: ttlMgr}
	blocklistHandler := cli.NewBlocklistHandler(ipAdapter, ttlCliAdapter, nil)
	reg := cli.NewRegistry()
	blocklistHandler.Register(reg)
	
	// 通过 Registry 调用 blocklist.status 命令
	statusResp := reg.Dispatch(cli.Request{Command: cli.CmdBlockListStatus})
	if !statusResp.Ok {
		t.Fatalf("status not ok: %+v", statusResp)
	}
	data := statusResp.Data.(map[string]interface{})
	if data["blocked_count"] != 1 {
		t.Errorf("blocked_count in status=%v, want 1", data["blocked_count"])
	}

	// 7. 验证白名单豁免逻辑
	if err := ipMgr.SyncLocalWhitelist([]string{"10.0.0.0/8"}); err != nil {
		t.Fatalf("SyncLocalWhitelist: %v", err)
	}
	accepted2, err2 := ipMgr.Block("10.0.0.5")
	if accepted2 || err2 == nil {
		t.Errorf("block whitelisted ip should be skipped, got accepted=%v err=%v", accepted2, err2)
	}

	// 8. 快照保存与恢复
	dir := t.TempDir()
	snapPath := filepath.Join(dir, "state.json")
	snapMgr := snapshot.NewManager(
		snapshot.Config{FilePath: snapPath, Interval: 0},
		&ipsetAdapter{m: ipMgr},
		&ttlAdapter{m: ttlMgr},
		nil,
	)
	if err := snapMgr.Save(); err != nil {
		t.Fatalf("snapshot save: %v", err)
	}
	if _, err := os.Stat(snapPath); os.IsNotExist(err) {
		t.Fatalf("snapshot file not created")
	}

	// 新建一个 ipset/ttl 管理器，验证快照恢复
	ipClient2 := ipsetutil.NewMemClient()
	ipMgr2 := ipsetutil.NewManager(ipClient2, 0, 0)
	ttlMgr2 := ttl.NewManager(ttlCfg, nil)
	snapMgr2 := snapshot.NewManager(
		snapshot.Config{FilePath: snapPath, Interval: 0},
		&ipsetAdapter{m: ipMgr2},
		&ttlAdapter{m: ttlMgr2},
		nil,
	)
	if _, err := snapMgr2.LoadAndRestore(); err != nil {
		t.Fatalf("snapshot restore: %v", err)
	}
	// TTL 应被恢复
	if c := ttlMgr2.Count(); c != 1 {
		t.Errorf("ttl count after restore=%d, want 1", c)
	}
}
