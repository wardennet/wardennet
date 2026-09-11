// Package cloudsync 负责 Agent 与云端 SaaS 的双层 Diff 同步调度。
//
//  核心设计：**本包只做调度，不持有任何云端凭证或 HTTP 客户端**。
//  所有 HTTP/鉴权/签名逻辑委托给闭源插件（libcloudplugin.so）的 plugin.Plugin 实现。
//  NoopPlugin（无插件）时引擎自动跳过，Agent 退化为纯本地运行。
//
//  职责清单：
//  1. 调用 Plugin.Init + Auth 完成 Agent 注册/鉴权
//  2. 定时循环：Heartbeat → Diff → Command
//  3. 追踪本地版本号（global_base / global_seq / tenant_seq）
//  4. 将 DiffResult 解析后应用到 ipsetutil.Manager（ApplyCloud）
//  5. 处理 full_sync / need_base 场景（触发 Plugin.FetchFullGlobalSnapshot / FetchTenantSnapshot）
//
//  绝对禁止：
//   - 直接 import cloudclient 或发 HTTP 请求
//   - 持有 tenant_secret / agent_secret 之外的凭证
//   - 跨包访问 detector / ttl 等内部模块

package cloudsync

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"sync"
	"time"

	"github.com/wardennet/agent/internal/config"
	"github.com/wardennet/agent/internal/ipsetutil"
	"github.com/wardennet/agent/internal/logger"
	"github.com/wardennet/agent/internal/plugin"
	"github.com/wardennet/agent/internal/ttl"
)

// SyncEngine 云端同步调度器。
// 生命周期：Init → Start → Stop。所有方法线程安全。
type SyncEngine struct {
	p     plugin.Plugin
	ipMgr *ipsetutil.Manager
	cfg   config.CloudSection
	lg    *logger.Logger

	// 本地状态追踪（Diff 所需）
	mu         sync.Mutex
	globalBase string // base-YYYYMMDD
	globalSeq  int64  // 当前已消费到的全局增量序号
	tenantSeq  int64  // 当前已消费到的租户序号
	agentID    string // Auth 后从云端获得

	authOK bool // 是否已完成鉴权

	stopCh chan struct{}
	wg     sync.WaitGroup
	closed bool

	// v1.2 新增：本地评分回调。
	// 由 main.go 注入 detector 的查询方法，实现"云端评分 + 本地检测"综合决策。
	// 返回 Freq=0, Detector=0 表示"本地从未见过这个 IP"（Agent 否决云端评分）。
	// nil 时 DecideAll 会用 Freq=50, Detector=50 的中性占位值（向后兼容）。
	localScoreFn func(ip string) LocalScoreResult

	// v1.2 新增：TTL 管理器，为云端下发的 BLOCK 注册 SourceCloud 级别自动解封。
	// 云端封锁（含联防快速通道）必须带 TTL，否则威胁池评分过期后 Agent 仍永封。
	// nil 时跳过 TTL 注册（降级但保留 ApplyCloud 封锁，由 kernel timeout 兜底）。
	ttlMgr *ttl.Manager
}

// SetLocalScoreFn 注入本地评分回调。nil 时 DecideAll 用 Freq=50, Detector=50 中性占位值。
func (e *SyncEngine) SetLocalScoreFn(fn func(ip string) LocalScoreResult) {
	e.localScoreFn = fn
}

// SetTTLManager 注入 TTL 管理器。为云端下发的 BLOCK 注册 SourceCloud 自动解封。
// nil 时 applyDecisions 跳过 TTL 注册（降级，仅由 kernel timeout 兜底）。
func (e *SyncEngine) SetTTLManager(tm *ttl.Manager) {
	e.ttlMgr = tm
}

// New 创建 SyncEngine。
// p 为 NoopPlugin 时，Start 会立即返回 nil，不启动任何 goroutine（零开销）。
// ipMgr 为 nil 时引擎无法应用云端变更（仍可跑 Auth/Heartbeat/Diff 调度）。
func New(p plugin.Plugin, ipMgr *ipsetutil.Manager, cfg config.CloudSection, lg *logger.Logger) *SyncEngine {
	if p == nil {
		p = &plugin.NoopPlugin{}
	}
	if cfg.SyncInterval <= 0 {
		cfg.SyncInterval = 600
	}
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = 300
	}
	if cfg.CommandInterval <= 0 {
		cfg.CommandInterval = 120
	}
	return &SyncEngine{
		p:      p,
		ipMgr:  ipMgr,
		cfg:    cfg,
		lg:     lg,
		stopCh: make(chan struct{}),
	}
}

// Start 启动后台同步循环。
// NoopPlugin 或 cloud.enabled=false 时立即返回，不启动 goroutine。
// 返回的 error 仅针对 Auth 失败这类"硬错误"；一般同步失败在 goroutine 内降级重试。
func (e *SyncEngine) Start() error {
	// 快速路径：无插件或未启用 → 静默跳过
	if _, noop := e.p.(*plugin.NoopPlugin); noop {
		if e.lg != nil {
			e.lg.Info("cloudsync skipped — no plugin loaded (offline mode)")
		}
		return nil
	}
	if !e.cfg.Enabled {
		if e.lg != nil {
			e.lg.Info("cloudsync skipped — cloud.enabled=false in config")
		}
		return nil
	}

	// 1. 调用 Plugin.Init（传入云端连接参数，插件内部决定如何用）
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}
	version := "dev" // main.go 注入；插件内部用 version 做兼容性判断

	// 传入 config 中所有云端参数的 JSON 字符串（不限制插件如何解析）
	cfgJSON, _ := json.Marshal(e.cfg)
	if err := e.p.Init(string(cfgJSON), version); err != nil {
		return fmt.Errorf("plugin init: %w", err)
	}

	// 2. 鉴权循环（失败重试，指数退避，最多 10 分钟后放弃）
	if err := e.authenticate(hostname, version); err != nil {
		return fmt.Errorf("cloud auth failed: %w", err)
	}

	// 3. 启动后台循环
	e.wg.Add(3)
	go e.heartbeatLoop()
	go e.diffLoop()
	go e.commandLoop()

	if e.lg != nil {
		e.lg.Info("cloudsync started",
			"tenant_id", e.cfg.TenantID,
			"agent_id", e.agentID,
			"sync_interval_s", e.cfg.SyncInterval,
		)
	}
	return nil
}

// authenticate 执行 Plugin.Auth，失败时指数退避重试。
func (e *SyncEngine) authenticate(hostname, version string) error {
	ctx := plugin.AuthContext{
		AgentID:   "",        // 插件内部可用 config 里的 base_url/agent_secret 自行管理
		Secret:    e.cfg.AgentSecret,
		Timestamp: time.Now().Unix(),
		Hostname:  hostname,
		Version:   version,
	}

	backoff := 3 * time.Second
	deadline := time.Now().Add(10 * time.Minute)

	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("auth timeout after 10min")
		}
		result, err := e.p.Auth(ctx)
		if err == nil && result.OK {
			e.mu.Lock()
			e.agentID = result.AgentID
			e.authOK = true
			e.mu.Unlock()
			if e.lg != nil {
				e.lg.Info("cloud auth success", "agent_id", result.AgentID, "expires", result.Expires)
			}
			return nil
		}
		if e.lg != nil {
			e.lg.Warn("cloud auth failed, retrying",
				"err", err, "plugin_err", result.Err, "backoff", backoff)
		}
		select {
		case <-e.stopCh:
			return fmt.Errorf("engine stopped during auth")
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > 60*time.Second {
			backoff = 60 * time.Second
		}
	}
}

// Stop 优雅关闭所有后台 goroutine。幂等。
func (e *SyncEngine) Stop() {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	e.closed = true
	close(e.stopCh)
	e.mu.Unlock()

	e.wg.Wait()

	if err := e.p.Shutdown(); err != nil && e.lg != nil {
		e.lg.Warn("plugin shutdown error", "err", err)
	}
	if e.lg != nil {
		e.lg.Info("cloudsync stopped")
	}
}

// ===== 后台循环 =====

// heartbeatLoop 定时心跳。插件内部可在心跳里感知云端通知（V1.0 wait-notify 升级）。
// 加入 0~60s jitter 防止多 Agent 同时请求云端 API 产生惊群效应。
func (e *SyncEngine) heartbeatLoop() {
	defer e.wg.Done()
	interval := time.Duration(e.cfg.HeartbeatInterval) * time.Second
	maxJitter := 60 * time.Second

	for {
		jitter := time.Duration(rand.Int63n(int64(maxJitter)))
		next := time.After(interval + jitter)
		select {
		case <-e.stopCh:
			return
		case <-next:
			e.doHeartbeat()
		}
	}
}

func (e *SyncEngine) doHeartbeat() {
	needDiff, err := e.p.Heartbeat()
	if err != nil {
		if e.lg != nil {
			e.lg.Warn("cloud heartbeat failed", "err", err)
		}
		return
	}
	if needDiff {
		// 云端提示有变更，立即触发一次 Diff（不等下一个周期）
		e.doDiff()
	}
}

// diffLoop 定时拉取双层 Diff 并应用到 ipset。
// 加入 0~60s jitter 防止多 Agent 同时请求云端 API 产生惊群效应。
// 首次启动时立即执行一次（保持冷启动消除逻辑），后续每次循环使用 jitter。
func (e *SyncEngine) diffLoop() {
	defer e.wg.Done()
	interval := time.Duration(e.cfg.SyncInterval) * time.Second
	maxJitter := 60 * time.Second

	// 启动时立即拉一次，避免冷启动延迟
	e.doDiff()

	for {
		jitter := time.Duration(rand.Int63n(int64(maxJitter)))
		next := time.After(interval + jitter)
		select {
		case <-e.stopCh:
			return
		case <-next:
			e.doDiff()
		}
	}
}

func (e *SyncEngine) doDiff() {
	e.mu.Lock()
	req := plugin.DiffRequest{
		AgentID:    e.agentID,
		TenantID:   e.cfg.TenantID,
		GlobalBase: e.globalBase,
		GlobalSeq:  e.globalSeq,
		TenantSeq:  e.tenantSeq,
		LastSyncAt: time.Now().Unix(),
	}
	e.mu.Unlock()

	result, err := e.p.Diff(req)
	if err != nil {
		if e.lg != nil {
			e.lg.Warn("cloud diff failed", "err", err)
		}
		return
	}
	if !result.OK {
		if e.lg != nil {
			e.lg.Warn("cloud diff returned not ok", "err", result.Err)
		}
		return
	}

	// v1.2 新增：应用云端下发的决策引擎权重（可选，DiffResult.DecisionWeights）
	// 安全校验在 SetDecisionWeights 内部完成（三项之和 ∈ [0.5, 1.5]）。
	if result.DecisionWeights != nil {
		ok := SetDecisionWeights(result.DecisionWeights)
		if e.lg != nil {
			if ok {
				e.lg.Info("decision weights applied",
					"cloud", result.DecisionWeights.Cloud,
					"local", result.DecisionWeights.Local,
					"detector", result.DecisionWeights.Detector)
			} else {
				e.lg.Warn("decision weights rejected by safety check",
					"cloud", result.DecisionWeights.Cloud,
					"local", result.DecisionWeights.Local,
					"detector", result.DecisionWeights.Detector)
			}
		}
	}

	// ---- 处理全局层 need_base ----
	if result.Global.NeedBase {
		if e.lg != nil {
			e.lg.Info("diff need_base=true, fetching full global snapshot",
				"current", req.GlobalBase, "server", result.Global.BaseName)
		}
		e.applyGlobalSnapshot()
	}

	// ---- 应用全局增量 ----
	var maxGlobalSeq int64 = e.globalSeq
	for _, incr := range result.Global.IncrList {
		e.applyGlobalIncr(incr)
		if incr.IncrSeq > maxGlobalSeq {
			maxGlobalSeq = incr.IncrSeq
		}
	}

	// ---- 处理租户层 full_sync ----
	if result.Tenant.FullSync {
		if e.lg != nil {
			e.lg.Info("diff tenant.full_sync=true, fetching tenant snapshot",
				"local_seq", req.TenantSeq)
		}
		e.applyTenantSnapshot()
	} else {
		// ---- 应用租户增量 ----
		e.applyTenantDiff(result)
	}

	// ---- 更新本地版本号 ----
	e.mu.Lock()
	if result.Global.NeedBase {
		e.globalBase = result.Global.BaseName
	}
	e.globalSeq = maxGlobalSeq
	e.tenantSeq = result.Tenant.TenantSeq
	e.mu.Unlock()

	if e.lg != nil {
		e.lg.Debug("cloud diff applied",
			"global_base", result.Global.BaseName,
			"global_seq", e.globalSeq,
			"tenant_seq", e.tenantSeq,
			"incr_count", len(result.Global.IncrList),
		)
	}
}

// commandLoop 定时拉取远程指令并执行。
func (e *SyncEngine) commandLoop() {
	defer e.wg.Done()
	ticker := time.NewTicker(time.Duration(e.cfg.CommandInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-e.stopCh:
			return
		case <-ticker.C:
			e.doCommands()
		}
	}
}

func (e *SyncEngine) doCommands() {
	cmds, err := e.p.FetchPendingCommands()
	if err != nil {
		if e.lg != nil {
			e.lg.Warn("fetch pending commands failed", "err", err)
		}
		return
	}
	for _, cmd := range cmds {
		e.executeCommand(cmd)
	}
}

func (e *SyncEngine) executeCommand(cmd plugin.RemoteCommand) {
	if e.lg != nil {
		e.lg.Info("executing cloud command", "id", cmd.ID, "command", cmd.Command)
	}
	result, err := e.p.HandleCommand(cmd)
	if err != nil {
		if e.lg != nil {
			e.lg.Warn("cloud command error", "id", cmd.ID, "err", err)
		}
		return
	}
	if e.lg != nil {
		e.lg.Info("cloud command result",
			"id", cmd.ID, "ok", result.Ok, "err", result.Err)
	}
}

// ===== Diff → ipset 应用（V2：先走决策引擎再写 ipset）=====
//
// 核心变更：云端只下发 threat_scoring（威胁评分 0-100），**不直接拉黑**。
// Agent 收到评分后调用 DecideAll 做综合决策：
//   1. 合并 global + tenant 两层评分 + incr 增量评分
//   2. DecideAll: 云端×0.4 + 本地频率×0.3 + detector×0.3 → composite
//   3. ≥ 80 → block（写 ipset）
//   4. ≥ 50 → alert（仅日志）
//   5. < 50 → ignore
//
// 白名单仍然直接从云端下发直接应用（租户自己管理的）。

func (e *SyncEngine) applyGlobalSnapshot() {
	snap, err := e.p.FetchFullGlobalSnapshot()
	if err != nil {
		if e.lg != nil {
			e.lg.Warn("fetch global snapshot failed", "err", err)
		}
		return
	}
	if e.ipMgr == nil {
		return
	}

	blocks, alerts := DecideAll(snap.ThreatScoring, e.localScoreFn)
	e.applyDecisions(blocks, alerts, "global_snapshot")

	e.mu.Lock()
	e.globalBase = snap.BaseName
	e.mu.Unlock()
}

func (e *SyncEngine) applyGlobalIncr(incr plugin.GlobalIncr) {
	if e.ipMgr == nil {
		return
	}

	blocks, alerts := DecideAll(incr.ThreatAdd, e.localScoreFn)
	e.applyDecisions(blocks, alerts, "global_incr")
}

func (e *SyncEngine) applyTenantSnapshot() {
	snap, err := e.p.FetchTenantSnapshot()
	if err != nil {
		if e.lg != nil {
			e.lg.Warn("fetch tenant snapshot failed", "err", err)
		}
		return
	}
	if e.ipMgr == nil {
		return
	}

	blocks, alerts := DecideAll(snap.ThreatScoring, e.localScoreFn)
	e.applyDecisions(blocks, alerts, "tenant_snapshot")

	// 白名单直接应用（租户自己管理的，不经过决策）
	var wlEntries []ipsetutil.Entry
	for _, ip := range snap.WhiteAdd {
		wlEntries = append(wlEntries, ipsetutil.Entry{
			Set: ipsetutil.SetWhitelist, IP: ip, Op: ipsetutil.OpAdd,
		})
	}
	for _, ip := range snap.WhiteDel {
		wlEntries = append(wlEntries, ipsetutil.Entry{
			Set: ipsetutil.SetWhitelist, IP: ip, Op: ipsetutil.OpDel,
		})
	}
	if len(wlEntries) > 0 {
		_, _ = e.ipMgr.ApplyCloud(wlEntries)
	}
}

func (e *SyncEngine) applyTenantDiff(result plugin.DiffResult) {
	if e.ipMgr == nil {
		return
	}

	blocks, alerts := DecideAll(result.Tenant.ThreatScoring, e.localScoreFn)
	e.applyDecisions(blocks, alerts, "tenant_diff")

	// 白名单直接应用
	var wlEntries []ipsetutil.Entry
	for _, ip := range result.Tenant.WhiteAdd {
		wlEntries = append(wlEntries, ipsetutil.Entry{
			Set: ipsetutil.SetWhitelist, IP: ip, Op: ipsetutil.OpAdd,
		})
	}
	for _, ip := range result.Tenant.WhiteDel {
		wlEntries = append(wlEntries, ipsetutil.Entry{
			Set: ipsetutil.SetWhitelist, IP: ip, Op: ipsetutil.OpDel,
		})
	}
	if len(wlEntries) > 0 {
		_, _ = e.ipMgr.ApplyCloud(wlEntries)
	}
}

// applyDecisions 将决策结果应用到 ipset。
// blocks → 写 blacklist（带 kernel timeout）+ 注册 SourceCloud TTL；alerts → 仅记日志。
//
// 云端封锁解封双通道（防永久化）：
//   - 通道 1: TTL Sweep → onExpire → ipMgr.Unblock（ttlMgr.Add 注册，每轮 diff 刷新）
//   - 通道 2: ipset kernel timeout（add --timeout，进程崩溃/快照丢失时兜底）
//   - 下轮 diff 云端评分仍高 → 重新 Block + 刷新 TTL
//   - 云端评分下降或 threat pool TTL 到期 → 双通道触发自动解封
//   - SyncEngine.ttlMgr 未注入时两通道都不可用（降级为无自动解封，仅测试环境）
func (e *SyncEngine) applyDecisions(blocks, alerts []Decision, source string) {
	if len(blocks) > 0 && e.ipMgr != nil {
		// 云端封锁带 kernel timeout（与 TTL Sweep 双通道冗余）：
		// 进程崩溃导致 TTL 快照丢失时，内核 timeout 仍能自动解封，
		// 避免云端封锁永久化
		cloudTimeout := 0
		if e.ttlMgr != nil {
			cloudTimeout = e.ttlMgr.CloudTTLSeconds()
		}
		var entries []ipsetutil.Entry
		for _, d := range blocks {
			entries = append(entries, ipsetutil.Entry{
				Set: ipsetutil.SetBlacklist, IP: d.IP, Op: ipsetutil.OpAdd,
				Timeout: cloudTimeout,
			})
		}
		filtered, err := e.ipMgr.ApplyCloud(entries)

		// 为成功受理的云端 BLOCK 注册 SourceCloud TTL——
		// 联防快速通道 Block 的 IP 必须能自动解封（云端评分过期/误报消除后），
		// 否则等于把"云端永远不能独立 BLOCK"的安全边界打穿成"云端下发即永久封锁"。
		if e.ttlMgr != nil {
			filteredSet := make(map[string]struct{}, len(filtered))
			for _, f := range filtered {
				filteredSet[f.IP] = struct{}{}
			}
			for _, d := range blocks {
				if _, blocked := filteredSet[d.IP]; blocked {
					continue // 被本地白名单豁免的不注册 TTL
				}
				if _, ttlErr := e.ttlMgr.Add(d.IP, 0, ttl.SourceCloud); ttlErr != nil {
					if e.lg != nil {
						e.lg.Warn("cloud block ttl register failed", "ip", d.IP, "err", ttlErr)
					}
				}
			}
		}

		if e.lg != nil {
			e.lg.Info("threat_scoring decided BLOCK",
				"source", source,
				"count", len(blocks),
				"composite_min", minScore(blocks),
				"composite_max", maxScore(blocks),
				"filtered_by_local_wl", len(filtered),
				"err", err,
			)
			for _, d := range blocks {
				e.lg.Debug("BLOCK decision detail",
					"ip", d.IP,
					"cloud", d.CloudScore,
					"vote", d.VoteCount,
					"conf", d.CloudConfidence,
					"eff", d.EffectiveCloud,
					"freq", d.LocalFreqScore,
					"detector", d.DetectorScore,
					"final", d.FinalScore,
					"fast_path", d.FastPath,
					"reason", d.Reason,
				)
			}
		}
	}

	if len(alerts) > 0 && e.lg != nil {
		e.lg.Info("threat_scoring decided ALERT (not blocking)",
			"source", source, "count", len(alerts),
		)
		for _, d := range alerts {
			e.lg.Debug("ALERT decision detail",
				"ip", d.IP, "cloud", d.CloudScore,
				"vote", d.VoteCount, "conf", d.CloudConfidence, "eff", d.EffectiveCloud,
				"freq", d.LocalFreqScore, "detector", d.DetectorScore,
				"final", d.FinalScore,
			)
		}
	}
}

// ===== 工具函数 =====

func minScore(ds []Decision) float64 {
	if len(ds) == 0 {
		return 0
	}
	m := ds[0].FinalScore
	for _, d := range ds[1:] {
		if d.FinalScore < m {
			m = d.FinalScore
		}
	}
	return m
}

func maxScore(ds []Decision) float64 {
	if len(ds) == 0 {
		return 0
	}
	m := ds[0].FinalScore
	for _, d := range ds[1:] {
		if d.FinalScore > m {
			m = d.FinalScore
		}
	}
	return m
}

// GetAgentID 返回当前 agent_id（供 threatreporter 等需要上报身份的模块使用）。
func (e *SyncEngine) GetAgentID() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.agentID
}

// IsAuthed 返回是否已完成云端鉴权。
func (e *SyncEngine) IsAuthed() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.authOK
}
