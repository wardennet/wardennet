// Package main - adapter.go 提供各独立模块的适配与转换辅助。
// 因内部各包为规避 Go module 远程解析问题采用镜像结构，集成时通过本文件完成类型桥接。
package main

import (
	"fmt"
	"log"
	"time"

	"github.com/wardennet/agent/internal/cli"
	"github.com/wardennet/agent/internal/config"
	"github.com/wardennet/agent/internal/detector"
	"github.com/wardennet/agent/internal/ipsetutil"
	"github.com/wardennet/agent/internal/snapshot"
	"github.com/wardennet/agent/internal/stats"
	"github.com/wardennet/agent/internal/ttl"
)

// ----- ipsetutil <-> snapshot Provider 适配 -----

// ipsetAdapter 包装 ipsetutil.Manager 为 snapshot.IPSetProvider。
type ipsetAdapter struct {
	m *ipsetutil.Manager
}

func (a *ipsetAdapter) Snapshot() (snapshot.IPSetSnapshot, error) {
	// ipsetutil.Manager 目前未提供 Snapshot/RestoreIPSet，本适配器返回空占位。
	// Phase 1 集成验收不涉及真实数据恢复，后续版本补齐。
	return snapshot.IPSetSnapshot{}, nil
}

func (a *ipsetAdapter) RestoreIPSet(s snapshot.IPSetSnapshot) error {
	// Phase 1 占位：忽略快照恢复
	return nil
}

// ttlAdapter 包装 ttl.Manager 为 snapshot.TTLProvider。
type ttlAdapter struct {
	m *ttl.Manager
}

func (a *ttlAdapter) SnapshotTTL() (snapshot.TTLSnapshot, error) {
	// ttl.Manager 已有 Snapshot/MarshalSnapshot 方法，这里仅做结构转换占位。
	snap, err := a.m.Snapshot()
	if err != nil {
		return snapshot.TTLSnapshot{}, err
	}
	out := make([]snapshot.TTLEntry, 0, len(snap))
	for _, e := range snap {
		out = append(out, snapshot.TTLEntry{
			IP:        e.IP,
			Source:    int(e.Source),
			ExpiresAt: e.ExpiresAt,
			CreatedAt: e.CreatedAt,
			TTL:       e.TTL,
		})
	}
	return snapshot.TTLSnapshot{Entries: out}, nil
}

func (a *ttlAdapter) RestoreTTL(s snapshot.TTLSnapshot) (int, error) {
	entries := make([]ttl.Entry, 0, len(s.Entries))
	for _, e := range s.Entries {
		entries = append(entries, ttl.Entry{
			IP:        e.IP,
			Source:    ttl.Source(e.Source),
			ExpiresAt: e.ExpiresAt,
			CreatedAt: e.CreatedAt,
			TTL:       e.TTL,
		})
	}
	return a.m.Restore(entries)
}

// ----- detector 配置映射 -----

// mapDetectorConfig 将 config.DetectorSection 映射到 detector.DetectorCfg。
func mapDetectorConfig(s config.DetectorSection) detector.DetectorCfg {
	cfg := detector.DefaultDetectorCfg()
	cfg.Enabled = s.Enabled
	cfg.ScoreHigh = s.ScoreHigh
	cfg.ScoreMedium = s.ScoreMedium
	cfg.ScoreLow = s.ScoreLow
	if s.Mode == "report" {
		cfg.Mode = 1
	} else {
		cfg.Mode = 0
	}
	cfg.Weights = detector.ScoreWeights{
		DangerousPattern: s.Weights.DangerousPattern,
		DangerousMethod:  s.Weights.DangerousMethod,
		FileUpload:       s.Weights.FileUpload,
	}
	for i := 0; i < 3 && i < len(s.Windows); i++ {
		cfg.Windows[i] = detector.WindowCfg{
			Size: s.Windows[i].Size,
		}
	}
	// 可配置特征列表：三段式合并（内置默认 + 本地配置 + 云端拉取）
	// 当前仅合并内置默认 + 本地配置；云端拉取由 Detector 初始化时异步完成
	cfg.KnownHTTPClients = detector.ResolveFeatureList(
		detector.DefaultKnownHTTPClients(),
		featureListConfigFromFlex(s.KnownHTTPClients),
		nil,
	).Items
	cfg.SensitivePaths = detector.ResolveFeatureList(
		detector.DefaultSensitivePaths(),
		featureListConfigFromFlex(s.SensitivePaths),
		nil,
	).Items
	cfg.DangerousPatterns = detector.ResolveFeatureList(
		detector.DefaultDangerousPatterns(),
		featureListConfigFromFlex(s.DangerousPatterns),
		nil,
	).Items
	// 跳过路径映射：空切片时使用默认值（DefaultSkipPaths）
	if len(s.SkipPaths) > 0 {
		cfg.SkipPaths = s.SkipPaths
	}
	// v1.2 新增：Consistency 5 维评分参数
	// config 层用 yaml.Node 接收原始 YAML，这里 Unmarshal 到 detector.ConsistencyThresholds
	// nil 表示用户未声明，cfg.Consistency 保持 nil，detector 内部用 DefaultConsistencyThresholds 兜底
	if s.Consistency != nil {
		var ct detector.ConsistencyThresholds
		if err := s.Consistency.Decode(&ct); err != nil {
			log.Printf("WARN: invalid detector.consistency config: %v, using defaults", err)
		} else {
			cfg.Consistency = &ct
		}
	}
	// v1.2 新增：可信内网网段（默认空 → 不启用）
	cfg.TrustedSubnets = s.TrustedSubnets
	// v1.3 新增：蜜罐路径（默认空 → 不启用）
	cfg.HoneypotPaths = s.HoneypotPaths
	return cfg
}

// mapIPSetItems 将 config.IPSetSection 转换为 []string。
func mapIPSetItems(s config.IPSetSection) (wl []string) {
	wl = append(wl, s.Whitelist...)
	return
}

// ----- ttl 配置映射 -----

// mapTTLConfig 将 config.AgentSection 映射到 ttl.Config。
func mapTTLConfig(a config.AgentSection) ttl.Config {
	return ttl.Config{
		LocalBlockTTL: a.LocalBlockTTL,
		CloudBlockTTL: a.CloudBlockTTL,
	}
}

// ----- cli Handler 需要的适配器 -----

// ipsetCLIAdapter 实现 cli.IPSetProvider 接口，底层使用 ipsetutil.Manager。
type ipsetCLIAdapter struct {
	m *ipsetutil.Manager
}

func (a *ipsetCLIAdapter) Block(ip string) (bool, error) { return a.m.Block(ip) }
func (a *ipsetCLIAdapter) ForceBlock(ip string) (bool, error) { return a.m.ForceBlock(ip) }
func (a *ipsetCLIAdapter) Unblock(ip string) error      { return a.m.Unblock(ip) }
func (a *ipsetCLIAdapter) IsLocalWhitelisted(ip string) bool {
	return a.m.IsLocalWhitelisted(ip)
}
func (a *ipsetCLIAdapter) LocalBlockedCount() int   { return a.m.LocalBlockedCount() }
func (a *ipsetCLIAdapter) LocalWhitelistCount() int { return a.m.LocalWhitelistCount() }
func (a *ipsetCLIAdapter) ApplyCloud(entries []cli.CloudEntry) ([]cli.CloudEntry, error) {
	// 将 cli.CloudEntry 转换为 ipsetutil.Entry
	cs := make([]ipsetutil.Entry, 0, len(entries))
	for _, e := range entries {
		cs = append(cs, ipsetutil.Entry{
			Set: e.Set,
			IP:  e.IP,
			Op:  ipsetutil.Op(e.Op),
		})
	}
	filtered, err := a.m.ApplyCloud(cs)
	out := make([]cli.CloudEntry, 0, len(filtered))
	for _, f := range filtered {
		out = append(out, cli.CloudEntry{Set: f.Set, IP: f.IP, Op: cli.OpType(f.Op)})
	}
	return out, err
}
func (a *ipsetCLIAdapter) SyncLocalWhitelist(items []string) error {
	return a.m.SyncLocalWhitelist(items)
}

// ttlCLIAdapter 实现 cli.TTLManager 接口，底层使用 ttl.Manager。
type ttlCLIAdapter struct {
	m *ttl.Manager
}

func (a *ttlCLIAdapter) Add(ip string, ttlSec int, source int) (int, error) {
	return a.m.Add(ip, ttlSec, ttl.Source(source))
}
func (a *ttlCLIAdapter) Remove(ip string) *cli.TTLEntry {
	e := a.m.Remove(ip)
	if e == nil {
		return nil
	}
	return &cli.TTLEntry{
		IP:        e.IP,
		Source:    int(e.Source),
		ExpiresAt: e.ExpiresAt,
		CreatedAt: e.CreatedAt,
		TTL:       e.TTL,
	}
}
func (a *ttlCLIAdapter) Count() int { return a.m.Count() }

// featureListConfigFromFlex 将 config.FlexibleFeatureList 转为 detector.FeatureListConfig。
// 用于三段式特征列表合并的中间转换步骤。
func featureListConfigFromFlex(f config.FlexibleFeatureList) detector.FeatureListConfig {
	return detector.FeatureListConfig{
		Local:          f.Local,
		Excludes:       f.Excludes,
		DisableBuiltin: f.DisableBuiltin,
		DisableCloud:   f.DisableCloud,
	}
}

// ----- StatusInfo 聚合适配器 -----

// statusInfoAdapter 实现 cli.StatusInfo 接口，聚合各模块运行状态。
// 注入给 StatusHandler，让 wardennet status 返回完整的运行数据。
type statusInfoAdapter struct {
	startTime time.Time
	ipMgr     *ipsetutil.Manager
	ttlMgr    *ttl.Manager
	stats     *stats.Collector
	detCfg    config.DetectorSection
}

// newStatusInfoAdapter 创建状态适配器，startTime 用于计算 uptime。
func newStatusInfoAdapter(
	startTime time.Time,
	ipMgr *ipsetutil.Manager,
	ttlMgr *ttl.Manager,
	stats *stats.Collector,
	detCfg config.DetectorSection,
) *statusInfoAdapter {
	return &statusInfoAdapter{
		startTime: startTime,
		ipMgr:     ipMgr,
		ttlMgr:    ttlMgr,
		stats:     stats,
		detCfg:    detCfg,
	}
}

// GetStatus 聚合各模块状态为 map[string]interface{}。
func (s *statusInfoAdapter) GetStatus() map[string]interface{} {
	out := make(map[string]interface{})

	// 运行时长
	uptime := time.Since(s.startTime)
	out["uptime"] = formatUptime(uptime)
	out["uptime_seconds"] = int(uptime.Seconds())

	// 黑白名单计数
	if s.ipMgr != nil {
		out["blocked_count"] = s.ipMgr.LocalBlockedCount()
		out["whitelist_count"] = s.ipMgr.LocalWhitelistCount()
	}

	// TTL 条目
	if s.ttlMgr != nil {
		out["ttl_entries"] = s.ttlMgr.Count()
	}

	// 检测引擎状态
	out["detector_enabled"] = s.detCfg.Enabled
	out["score_high"] = s.detCfg.ScoreHigh

	// 统计收集器（有数据时才填充，避免零值噪音）
	if s.stats != nil {
		report := s.stats.GenerateReport()
		if report.ProcessedEvents > 0 {
			out["processed_events"] = report.ProcessedEvents
		}
		if report.TotalEvents > 0 {
			out["total_events"] = report.TotalEvents
			out["total_ips"] = report.TotalIPs
			out["high_score_count"] = report.HighScoreCount
			out["medium_count"] = report.MediumCount
			out["low_score_count"] = report.LowScoreCount
			out["status_4xx"] = report.Status4xx
			out["status_5xx"] = report.Status5xx
			out["sensitive_path_hits"] = report.SensitivePathHits
			out["bot_ua_hits"] = report.BotUAHits
			out["empty_referer_hits"] = report.EmptyRefererHits
			if len(report.TopBlocked) > 0 {
				out["top_blocked"] = report.TopBlocked
			}
		}
	}

	return out
}

// formatUptime 把 time.Duration 格式化为可读字符串 "Xd Yh Zm"。
func formatUptime(d time.Duration) string {
	total := int(d.Seconds())
	days := total / 86400
	hours := (total % 86400) / 3600
	mins := (total % 3600) / 60
	secs := total % 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm %ds", days, hours, mins, secs)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, mins, secs)
	}
	if mins > 0 {
		return fmt.Sprintf("%dm %ds", mins, secs)
	}
	return fmt.Sprintf("%ds", secs)
}
