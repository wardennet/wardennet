// Package detector - detector.go 集成 Window + Scorer + Whitelist，
// 提供 Detector 接口：输入 Event，输出回填 LocalRiskScore 的 Event。
// 命中本地白名单 IP 跳过计数与打分（返回 score=0），符合 spec §5.3。
package detector

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"sort"
	"sync"
	"time"
)

// WhitelistChecker 判断 IP 是否在本地白名单中。命中时跳过检测与拉黑。
type WhitelistChecker interface {
	Contains(ip string) bool
}

// staticWhitelist 基于配置的静态 IP/CIDR 白名单实现。
type staticWhitelist struct {
	ips   map[string]struct{}
	cidrs []*net.IPNet
}

// NewStaticWhitelist 从配置字符串列表构建白名单。非法条目静默忽略。
func NewStaticWhitelist(items []string) WhitelistChecker {
	w := &staticWhitelist{
		ips: make(map[string]struct{}),
	}
	for _, s := range items {
		if s == "" {
			continue
		}
		if ip := net.ParseIP(s); ip != nil {
			w.ips[ip.String()] = struct{}{}
			continue
		}
		if _, n, err := net.ParseCIDR(s); err == nil {
			w.cidrs = append(w.cidrs, n)
		}
	}
	return w
}

func (w *staticWhitelist) Contains(ip string) bool {
	if ip == "" {
		return false
	}
	if _, ok := w.ips[ip]; ok {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range w.cidrs {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// BlockTrigger 当高分事件命中时的回调函数（由 TTL/ipset 模块注册实现）。
type BlockTrigger func(ev Event) (accepted bool)

// observation 观察名单条目。多事件确认机制使用。
//
//   firstSeen — 首次进入观察的时间
//   lastSeen  — 最近一次触发高分的时间
//   count     — 已记录的独立高分事件数（排除 MergeWindowSec 内合并的重复）
//   path      — 上一次触发 isHigh 的请求路径（用于判断是否同一次攻击）
type observation struct {
	firstSeen time.Time
	lastSeen  time.Time
	count     int
	path      string
}

// ThreatReportTrigger 当检测到风险（score > 0）时的威胁上报回调。
// 与 BlockTrigger 平行设计：BlockTrigger 关注"是否封禁"，ThreatReportTrigger 关注"是否上报云端"。
// fire-and-forget 语义：返回值不影响 detector 主流程。
// 注意：即使 score 不达到封禁阈值（isHigh=false），只要 score > 0 就会上报告知云端——
// 云端可以跨 Agent 交叉验证完整攻击画像（某个 IP 可能先 medium 再 high）。
type ThreatReportTrigger func(ev Event)

// Detector 本地检测引擎接口。
type Detector interface {
	Process(ev Event) Event
	RegisterBlockTrigger(t BlockTrigger) BlockTrigger
	RegisterThreatReportTrigger(t ThreatReportTrigger) ThreatReportTrigger
	SetDetailLogger(l DetailLogger)
	Close()
}

// LocalDetector 本地产出实现。
//
// v1.0 增强：集成 BodyScanner（请求体扫描 + 文件上传拦截）
// 和 ResourceBaseline（IDOR/BOLA 越权检测）。两者均为可选增强：
//   - BodyScanner: 空值短路（Body/FileName 都空时零开销）
//   - ResourceBaseline: 默认关闭，enabled=false 时零开销
// 向后兼容：Set 方法未调用时这两个模块自动跳过。
type LocalDetector struct {
	cfg    *DetectorCfg // v1.2: 改为指针——Scorer 共享同一份配置，便于权重热更
	window *SlidingWindow
	scorer *Scorer
	wl     WhitelistChecker

	bodyScanner      *BodyScanner       // v1.0 新增
	resourceBaseline *ResourceBaseline  // v1.0 新增

	mu           sync.RWMutex
	trigger      BlockTrigger
	reportTrigger ThreatReportTrigger
	logger       DetailLogger
	closed       bool

	// 基线自学习引擎的三档基线（供 PreloadFromLogFile 和 goroutine 更新使用）
	baselines [3]*Baseline
	// 定时更新 goroutine 停止信号
	baselineStop chan struct{}
	baselineOnce sync.Once

	// --- 多事件确认：观察名单 ---
	// 普通 map + 互斥锁（IP 数量有限，锁开销可忽略）
	observMu    sync.Mutex
	observations map[string]*observation
	observStop  chan struct{}
	observOnce  sync.Once

	// v1.2 新增：可信内网网段（CIDR）解析结果。
	// 命中列表的 IP 正常参与计数但跳过 Consistency BENIGN 降权 gate。
	// 空列表表示不启用。
	trustedSubnets []*net.IPNet
}

// DefaultDetectorCfg 返回默认配置。
// 相对特征基于基线偏差评分，绝对特征使用固定权重。
func DefaultDetectorCfg() DetectorCfg {
	return DetectorCfg{
		Enabled:     true,
		Mode:        0,
		ScoreHigh:   50,
		ScoreMedium: 30,
		ScoreLow:    10,
		Sensitivity: 2,
		Weights: ScoreWeights{
			DangerousPattern: 5,
			DangerousMethod:  3,
			HeadMethod:       1,
			FileUpload:       20,
		},
		Windows: [3]WindowCfg{
			{Size: 10},
			{Size: 30},
			{Size: 60},
		},
		KnownHTTPClients:  DefaultKnownHTTPClients(),
		BotUserAgents:     DefaultBotUserAgents(),
		SensitivePaths:    DefaultSensitivePaths(),
		DangerousPatterns: DefaultDangerousPatterns(),
		SkipPaths:         DefaultSkipPaths(),

		// 多事件确认默认：观察窗口 30 秒、合并窗口 5 秒、2 次独立高分才封
		ConfirmCount:     2,
		ObserveWindowSec: 30,
		MergeWindowSec:   5,
	}
}

// NewLocalDetector 基于配置指针与白名单构建检测器。
// cfg 必须为非 nil（由调用方保证）。Scorer 和 SlidingWindow 共享同一份 cfg 指针——
// 便于权重/特征等配置项热更（v1.2 SetWeights 等方法）。
// wl 为 nil 时使用空白名单（所有 IP 参与检测）。
// 内部自动创建三档基线引擎（各窗口大小对应一个），并启动后台 goroutine 每 10 秒更新一次。
func NewLocalDetector(cfg *DetectorCfg, wl WhitelistChecker) *LocalDetector {
	if cfg == nil {
		// nil cfg 兜底：用 DefaultDetectorCfg 避免 nil pointer panic
		c := DefaultDetectorCfg()
		cfg = &c
	}
	if wl == nil {
		wl = NewStaticWhitelist(nil)
	}
	var baselines [3]*Baseline
	for i := 0; i < 3; i++ {
		size := cfg.Windows[i].Size
		if size <= 0 {
			size = 1
		}
		baselines[i] = NewBaseline(size)
	}
	stopChan := make(chan struct{})
	observStop := make(chan struct{})

	// v1.2：解析 TrustedSubnets CIDR 列表（初始化时做一次，运行时只做 O(k) 前缀检查）
	var trustedNets []*net.IPNet
	for _, s := range cfg.TrustedSubnets {
		if s == "" {
			continue
		}
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			continue // 非法 CIDR 静默跳过（不阻塞启动）
		}
		trustedNets = append(trustedNets, n)
	}

	d := &LocalDetector{
		cfg:            cfg,
		window:         NewSlidingWindow(cfg.Windows, cfg.KnownHTTPClients, cfg.SensitivePaths, cfg.DangerousPatterns, cfg.SkipPaths, cfg.HoneypotPaths, cfg.Consistency),
		scorer:         NewScorer(cfg, baselines),
		wl:             wl,
		logger:         NopDetailLogger{},
		baselines:      baselines,
		baselineStop:   stopChan,
		observations:   make(map[string]*observation),
		observStop:     observStop,
		trustedSubnets: trustedNets,
	}
	// 用户配置优先级高于程序默认：cfg.BotUserAgents 已在 DefaultDetectorCfg 中赋值为 DefaultBotUserAgents()，
	// 若用户覆盖了它则通过 SetBotUserAgents 注入。后续云端同步会再次覆盖。
	if cfg.BotUserAgents != nil {
		d.window.SetBotUserAgents(cfg.BotUserAgents)
	}
	// 启动基线定时更新 goroutine（每 10 秒）
	go d.baselineUpdateLoop(stopChan)
	// 启动观察名单过期清理 goroutine（每 10 秒）
	go d.observEvictLoop(observStop)
	return d
}

// baselineUpdateLoop 后台 goroutine，每 10 秒收集 SlidingWindow 的活跃 IP 计数器，
// 更新三档 Baseline 的分位数。退出信号：stopChan 关闭。
func (d *LocalDetector) baselineUpdateLoop(stopChan chan struct{}) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stopChan:
			return
		case <-ticker.C:
			allCounters := d.window.AllCounters()
			for i := 0; i < 3; i++ {
				d.baselines[i].Update(allCounters[i])
			}
		}
	}
}

// observEvictLoop 后台 goroutine，每 10 秒清理观察名单中过期的条目。
// 过期判定：now - lastSeen > ObserveWindowSec。
func (d *LocalDetector) observEvictLoop(stopChan chan struct{}) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stopChan:
			return
		case <-ticker.C:
			d.observMu.Lock()
			if d.cfg.ObserveWindowSec <= 0 {
				d.observations = make(map[string]*observation)
				d.observMu.Unlock()
				continue
			}
			cutoff := time.Now().Add(-time.Duration(d.cfg.ObserveWindowSec) * time.Second)
			for ip, obs := range d.observations {
				if obs.lastSeen.Before(cutoff) {
					delete(d.observations, ip)
				}
			}
			d.observMu.Unlock()
		}
	}
}

// shouldBlock 多事件确认核心逻辑。
//
// highConfidence=true 表示本次 isHigh 有"致命攻击特征"（DangerousPattern / DangerousMethod /
// FileUpload / 非 legit 场景的 BotUA），直接封禁，跳过观察名单。
// highConfidence=false 表示仅有 4xx/QPS 偏离等相对特征，走多事件确认流程。
//
// path: 本次触发 isHigh 的请求路径（用于判断是否"同一次攻击"）。
//   合并逻辑仅对"同一路径在短时间内重复命中"生效——
//   不同路径的独立试探属于真正的多维度攻击，不能被 MergeWindowSec 吞掉。
//
// 返回 true 表示本次 isHigh 应该触发 BlockTrigger；false 表示仅记入观察名单。
// 当 cfg.ConfirmCount <= 1 时直接返回 true（关闭确认，向后兼容）。
func (d *LocalDetector) shouldBlock(ip, path string, highConfidence bool, nowSec int64) bool {
	cfg := d.cfg
	if cfg.ConfirmCount <= 1 {
		return true // 关闭确认
	}

	if highConfidence {
		d.observMu.Lock()
		delete(d.observations, ip)
		d.observMu.Unlock()
		return true
	}

	now := time.Unix(nowSec, 0)
	if nowSec <= 0 {
		now = time.Now()
	}
	d.observMu.Lock()
	defer d.observMu.Unlock()

	if cfg.ObserveWindowSec <= 0 {
		return true
	}

	obs, exists := d.observations[ip]
	if !exists {
		// 首次进入观察
		d.observations[ip] = &observation{
			firstSeen: now,
			lastSeen:  now,
			count:     1,
			path:      path,
		}
		return false
	}

	// 已存在 → 判定是否在合并窗口内
	// 规则：
	//   1. 同一路径 + 间隔 ≤ MergeWindowSec → 同一次攻击 → 合并
	//   2. 不同路径但时间戳相同（同一秒内爆发） → 同一次 burst → 合并
	//   3. 不同路径 + 间隔已超合并窗口 → 独立试探 → 计数（修复核心漏封）
	mergeWindow := time.Duration(cfg.MergeWindowSec) * time.Second
	if mergeWindow > 0 && now.Sub(obs.lastSeen) <= mergeWindow {
		sameSecond := (nowSec > 0 && nowSec == obs.lastSeen.Unix())
		sameAttack := (obs.path == path) || sameSecond
		if sameAttack {
			obs.lastSeen = now
			return false
		}
		// 不同路径且间隔已超合并窗口 → 不合并，走计数
	}

	// 观察窗口过期 → 重置（视为一过性噪声已过去，重新开始）
	observeWindow := time.Duration(cfg.ObserveWindowSec) * time.Second
	if now.Sub(obs.firstSeen) > observeWindow {
		d.observations[ip] = &observation{
			firstSeen: now,
			lastSeen:  now,
			count:     1,
			path:      path,
		}
		return false
	}

	// 独立事件（不同路径 或 间隔已超合并窗口）→ 计数 +1
	obs.lastSeen = now
	obs.path = path
	obs.count++
	if obs.count >= cfg.ConfirmCount {
		// 凑够次数，清除观察记录，本次触发封禁
		delete(d.observations, ip)
		return true
	}
	return false
}

// computeHighConfidence 从三档窗口的 ScoreDetail 判断是否存在"致命攻击特征"。
//
// 致命特征：
//   - DangerousPatternHit  任一窗口 >= 2（SQLi/XSS/RCE 等攻击正则重复命中）
//   - DangerousMethodScore  > 0  （PUT/DELETE/TRACE 等危险方法）
//   - FileUploadBlockedCount> 0  （文件上传拦截）
//   - BotUAScore > 0 且 !LegitimateUserContext （扫描器 UA 且非合法用户场景）
//
// 合法用户场景（LegitimateUserContext=true）即使有 BotUAScore 也不算高置信度，
// 因为某些正常 APP 内部 UA 可能被误判为 BotUA。
//
// DangerousPatternHit >= 2 的语义（v1.2 二次修正）：
//   三档窗口（10s/30s/60s）是"并行尺寸视图"——同一事件会同时写入全部三档
//   （见 window.go Record 的 for i:=0;i<3 循环），因此"跨窗口计数 >= 2"是无效
//   实现：单次命中会同时点亮三窗口，等于单次直封（回归到 v1.0 的 hit>=1 行为）。
//   正确语义是"任一窗口内 hit >= 2"：
//     - 10s 窗口 hit=2：同一请求命中 2 个 pattern，或 10s 内两次命中
//     - 30s/60s 窗口 hit=2：跨时间两个独立事件各命中一次（间隔 > 10s 时仅长窗口计数）
//   单次单 pattern 误匹配（三窗口各 hit=1）不触发，进入多事件确认流程。
//
// 注意：DangerousPatternScore 仍计入 ScoreHigh 叠加流程（多维度叠加到 80 分以上），
// 单次 DangerousPatternHit=1 不再独立触发 highConfidence 立即封锁。
func computeHighConfidence(details [3]ScoreDetail) bool {
	// DangerousPatternHit：任一窗口内 hit >= 2 才算高置信度
	// （跨窗口计数无效——三档窗口是并行视图，单事件同时点亮三窗口）
	for i := 0; i < 3; i++ {
		if details[i].DangerousPatternHit >= 2 {
			return true
		}
	}
	// 其他致命特征：任一 bucket 命中即触发
	for i := 0; i < 3; i++ {
		d := details[i]
		if d.DangerousMethodScore > 0 {
			return true
		}
		if d.FileUploadBlockedCount > 0 {
			return true
		}
		if d.BotUAScore > 0 && !d.LegitimateUserContext {
			return true
		}
	}
	return false
}

// SetDetailLogger 设置详情日志记录器。
func (d *LocalDetector) SetDetailLogger(l DetailLogger) {
	if l == nil {
		l = NopDetailLogger{}
	}
	d.logger = l
}

// SetBodyScanner 注入 BodyScanner（请求体扫描 + 文件上传拦截）。
// 传入 nil 时禁用 Body 扫描（默认行为，向后兼容）。
func (d *LocalDetector) SetBodyScanner(bs *BodyScanner) {
	d.bodyScanner = bs
	if d.window != nil {
		d.window.SetBodyScanner(bs)
	}
}

// SetResourceBaseline 注入 ResourceBaseline（IDOR/BOLA 越权检测）。
// 传入 nil 时禁用 IDOR 检测（默认行为，向后兼容）。
func (d *LocalDetector) SetResourceBaseline(rb *ResourceBaseline) {
	d.resourceBaseline = rb
}

// Process 处理 Event 并回填 LocalRiskScore。
//
// 流程：
//  1. SourceIP 命中白名单 → 直接返回 ev, score=0（不计数、不拉黑）
//  2. 若 detector 未启用 → 返回原 ev, score=0
//  3. 请求路径命中 SkipPaths → 直接返回 ev, score=0（浏览器常规行为不检测）
//  4. Window.Record 记一次计数（内部调用 BodyScanner 如果已注入）
//  5. ResourceBaseline.Check 执行 IDOR 越权检测（如果已注入且启用）
//  6. Scorer.ScoreWithDetail 取当前三档最高分 → scoreHTTP
//  7. finalScore = min(ScoreHigh, scoreHTTP + scoreIDOR)
//  8. isHigh → 先算 highConfidence → 调 shouldBlock(ip, path, highConf) 拿到封禁决策
//  9. LogDetail(ev, details, finalScore, isHigh, blocked) — blocked 传给日志做 WARN 分级
// 10. blocked=true 且非 report-only → 同步回调 BlockTrigger
func (d *LocalDetector) Process(ev Event) Event {
	if d.wl.Contains(ev.SourceIP) {
		ev.LocalRiskScore = 0
		return ev
	}
	if !d.cfg.Enabled {
		ev.LocalRiskScore = 0
		return ev
	}

	// P1-3: 本地回环 IP 跳过检测。
	// 这些是主机自流量（健康检查探针、运维脚本、cron 定时任务等），
	// 永远不是外部扫描威胁。不进 Window 计数、不记基线、不打分。
	//
	// 注意：只跳 loopback（127.0.0.0/8 + ::1），不跳 10.x/192.168.x。
	// 因为 10.x/192.168.x 可能是 NAT 后经反向代理 forward-for 进来的
	// 合法客户端 IP，在 Process 里全跳会误伤。
	if isLoopbackIP(ev.SourceIP) || isLoopbackIP(ev.EdgeIP) {
		ev.LocalRiskScore = 0
		return ev
	}

	// 统一路径规范化：URL decode + Unicode/Hex/HTML实体解码 + path.Clean + 反斜杠转正斜杠
	// 返回 hasTraversal 标记表示原始路径中包含穿越攻击意图（clean 前捕获，防止 clean 后消弭信号）
	ev.Path, ev.PathTraversal = normalizeRequestPath(ev.Path)

	// v1.3: 蜜罐路径短路 — 触之必死
	// 用户自定义的蜜罐路径是绝对判定：
	//   - 正常用户不可能访问你故意放在那里的陷阱路径
	//   - 命中即判定为恶意扫描，直接给 ceiling 分
	//   - 绕过多事件确认机制（shouldBlock）——单次即封
	//   - 绕过 Consistency 降权 gate——不可能是 BENIGN
	//   - 绕过 Scorer/Record 整个评分链路——零额外开销
	// 注意：report-only 模式下尊重用户选择，只上报不封禁。
	if d.window.IsHoneypotPath(ev.Path) {
		finalScore := d.cfg.ScoreHigh * 2 // 顶到 ceiling
		ev.LocalRiskScore = finalScore
		blocked := (d.cfg.Mode != 1) // report-only 不封
		if d.logger != nil {
			detail := ScoreDetail{HoneypotHit: true}
			d.logger.LogDetail(ev, [3]ScoreDetail{detail}, finalScore, true, blocked)
		}
		// 威胁上报：必须上报云端（蜜罐命中是扫描行为的硬证据）
		d.mu.RLock()
		rt := d.reportTrigger
		d.mu.RUnlock()
		if rt != nil {
			rt(ev)
		}
		if blocked {
			d.mu.RLock()
			t := d.trigger
			d.mu.RUnlock()
			if t != nil {
				_ = t(ev)
			}
		}
		return ev
	}

	// 跳过路径：浏览器/爬虫的常规行为（favicon、robots.txt 等）完全不参与检测
	if d.window.ShouldSkipPath(ev.Path) {
		ev.LocalRiskScore = 0
		return ev
	}
	d.window.Record(&ev)

	// IDOR/BOLA 越权检测（v1.0 新增，可选）
	var scoreIDOR int
	if d.resourceBaseline != nil {
		if _, s := d.resourceBaseline.Check(ev.SourceIP, ev.Path); s > 0 {
			scoreIDOR = s
		}
	}

	c := d.window.Counters(ev.SourceIP)
	ipQpsEMA, ipSeenCount := d.window.GetIPBaseline(ev.SourceIP)
	result := d.scorer.ScoreWithDetail(c, ipQpsEMA, ipSeenCount)

	// 叠加 IDOR 分数，上限 ScoreHigh
	finalScore := result.FinalScore + scoreIDOR
	if finalScore > d.cfg.ScoreHigh {
		finalScore = d.cfg.ScoreHigh
	}

	// v1.2: Consistency 行为降权 gate（在 Scorer 之后、isHigh 之前）
	// 核心思想：如果一个 IP 的行为序列形状明显是正常用户（BENIGN），
	// 但 Scorer 因为基线偏差给了高分，把它降权到 ScoreMedium——
	// 让多事件确认机制去处理，真正的攻击会持续触发 shouldBlock，
	// 合法 API 客户端的突发会被时间窗口稀释。
	//
	// 跳过条件：IP 命中 TrustedSubnets（内网 API 网关/K8s Pod 等，
	// 路径极集中是正常行为，不是扫描器特征）。
	if !d.isTrustedSubnet(ev.SourceIP) {
		scRes := d.window.ComputeConsistency(ev.SourceIP)
		if scRes.HasSamples && scRes.IsBenign && finalScore >= d.cfg.ScoreHigh {
			finalScore = d.cfg.ScoreMedium
		}
	}

	ev.LocalRiskScore = finalScore
	isHigh := d.scorer.IsHigh(finalScore)

	// === 先做封禁决策，再记录日志 ===
	// 这样 WARN 日志能准确表达"确认要封禁"还是"仅进入观察"
	var blocked bool
	if isHigh {
		if d.cfg.Mode == 1 {
			// report-only: 只评分上报不封禁
			blocked = false
			} else {
				highConf := computeHighConfidence(result.Details)
				blocked = d.shouldBlock(ev.SourceIP, ev.Path, highConf, ev.Timestamp)
			}
	}

	// 记录详情日志（blocked 传给 Logger 做 WARN 分级）
	if d.logger != nil {
		d.logger.LogDetail(ev, result.Details, finalScore, isHigh, blocked)
	}

	// blocked=true → 同步回调 BlockTrigger（report-only 下 blocked=false 已跳过）
	if blocked {
		d.mu.RLock()
		t := d.trigger
		d.mu.RUnlock()
		if t != nil {
			_ = t(ev)
		}
	}

	// 威胁上报：任何 score > 0 都上报（不限 isHigh）
	// 让云端拿到完整攻击轨迹，跨 Agent 交叉验证
	if finalScore > 0 {
		d.mu.RLock()
		rt := d.reportTrigger
		d.mu.RUnlock()
		if rt != nil {
			rt(ev)
		}
	}
	return ev
}

// SetBotUserAgents 热更新 BotUA 关键词列表。
// 云端特征同步完成后调用此方法注入云端列表，覆盖用户配置/程序默认。
// 这是三段式优先级的最高层（程序默认 → 用户配置 → 云端）。
func (d *LocalDetector) SetBotUserAgents(list []string) {
	d.window.SetBotUserAgents(list)
}

// RegisterBlockTrigger 注册拉黑回调。并发安全。返回旧回调。
func (d *LocalDetector) RegisterBlockTrigger(t BlockTrigger) BlockTrigger {
	d.mu.Lock()
	defer d.mu.Unlock()
	old := d.trigger
	d.trigger = t
	return old
}

// RegisterThreatReportTrigger 注册威胁上报回调。并发安全。返回旧回调。
func (d *LocalDetector) RegisterThreatReportTrigger(t ThreatReportTrigger) ThreatReportTrigger {
	d.mu.Lock()
	defer d.mu.Unlock()
	old := d.reportTrigger
	d.reportTrigger = t
	return old
}

// LineParser 单行日志解析函数类型。
// 外部（如 logparser 包）可提供此类型的实现，避免 detector 包引入内部依赖。
// 返回 (Event, nil) 表示成功解析；返回 (zero, error) 表示该行无法解析，应跳过。
type LineParser func(line string) (Event, error)

const (
	preloadDefaultMinutes           = 10     // Preload 初始时间窗口（分钟）：从这个值开始尝试
	preloadMaxLines                 = 500000 // 全量扫描上限：50 万行（约 1-2 天的中等流量）
	preloadTargetHealthyBuckets     = 10     // 自适应窗口目标：至少多少个健康桶（50min+ 的有效样本）
	preloadMaxWindowMinutes         = 240    // 自适应窗口上限：最多回溯 4 小时（48 个 5min 桶）

	// ---------- 反代不透传检测阈值 ----------
	// 三个条件满足任一即判定为"反向代理未透传真实客户端 IP"：
	//   条件 A: 不同 IP 总数 <= 3（典型单反代或双反代场景）
	//   条件 B: 不同 IP 总数 <= 10 且 Top1 占比 >= 90%（N+1 反代但某节点承担绝大多数流量）
	//   条件 C: 不同 IP 总数 <= 10 且 Top3 合计占比 >= 98%（少数几个反代节点包揽几乎全部流量）
	//
	// 不包含 loopback/private IP 的计数，内部健康检查探针不干扰判定。
	proxyMinUniqueIPsForSafe   = 11      // UniqueIPs 超过此值时跳过 B/C 条件（直接安全）
	proxySingleIPThreshold     = 3       // 条件 A: UniqueIPs <= 3
	proxyTop1RatioThreshold    = 0.90    // 条件 B: Top1Ratio >= 0.90
	proxyTop3RatioThreshold    = 0.98    // 条件 C: Top3Ratio >= 0.98
)

// PreloadStats 从历史日志预扫描建立基线的统计结果。
// 由 PreloadFromLogFile 返回，调用方（main.go）用 agent logger 输出到 agent.log。
type PreloadStats struct {
	Source         string    // source name (e.g. "nginx_access")
	Path           string    // log file path
	ScannedLines   int       // 扫描行数
	TimeStart      string    // "2006-01-02 15:04"
	TimeEnd        string    //
	DurationMin    int       // 覆盖时长（分钟）
	TotalBuckets   int       // 总 5min 桶数
	ActualWindowMin int      // 自适应窗口最终使用的回溯分钟数（初始 minutes 或扩展后的值）
	HealthyBuckets int       // 健康桶数（>= 50% 中位数）
	HealthyReqMin  float64   // 健康桶阈值（req/5min）
	MedianReq      float64   // 中位数（req/5min）
	QPSP50         float64   // 健康桶 QPS P50 (5min avg req/s)
	QPSP95         float64
	QPSP99         float64
	QPSSamples     int
	Confidence     float64   // 0~1
	Duration       string    // 完成耗时（e.g. "4.2s"）
	BaselineQPS    [3]float64 // 三档窗口的 QPS P95
	QPSOutliersRemoved int    // MAD 方法剔除的 QPS 极端桶数（扫描器/爬虫/batch sync）

	// ---------- IP 多样性 / 反代检测字段 ----------
	UniqueIPs            int     // 去重后的不同 IP 数（排除 loopback/private）
	Top1IP               string  // 请求最多的 IP
	Top1Count            int64   // Top1 IP 的请求数
	Top1Ratio            float64 // Top1 IP 占总请求比例 0~1
	Top3Ratio            float64 // Top3 IP 合计占比 0~1
	ReverseProxyDetected bool    // 是否触发反代不透传检测（满足条件 A/B/C 任一）
}

// PreloadFromLogFile 从历史日志文件中预扫描数据，建立初始基线。
// 读取文件头部、按时间戳过滤保留最近 minutes 分钟内的日志行（minutes 参数现在真正生效），
// 解析后喂给 SlidingWindow，最后触发三档 Baseline.Update() + ForceReady()，
// 让基线从一开始就处于就绪状态（IsReady=true），消除冷启动期。
//
// 参数:
//
//	path:    日志文件绝对路径
//	lp:      单行解析函数（由 main.go 传入 logparser.Parser 的 adapter）
//	minutes: 回溯分钟数（<=0 使用默认 preloadDefaultMinutes）
//
// 注意：此方法在 Detector 初始化后、启动 Event 处理循环前调用一次即可。
// 内部从文件头顺序扫描（access.log 按时间正序），扫描完后按 maxTS 倒推 minutes 做时间窗口过滤。
// 最多处理 preloadMaxLines=50 万行，避免大文件导致启动过慢。
// 解析失败的行静默跳过；文件不存在或无法打开时返回 error 让调用方降级。
// 同时完成 IP 多样性统计 + 反代不透传检测（见 PreloadStats.ReverseProxyDetected）。
func (d *LocalDetector) PreloadFromLogFile(path string, lp LineParser, minutes int) (PreloadStats, error) {
	stats := PreloadStats{Path: path}
	if lp == nil {
		return stats, fmt.Errorf("nil line parser")
	}

	start := time.Now()

	// minutes 兜底
	if minutes <= 0 {
		minutes = preloadDefaultMinutes
	}

	f, err := os.Open(path)
	if err != nil {
		return stats, fmt.Errorf("open log %s: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	type timeBucket struct {
		totalReq int
		count4xx int
		count5xx int
		count404 int
		authFail int
	}
	buckets := make(map[int64]*timeBucket)
	ipCount := make(map[string]int64) // IP 多样性统计（排除 loopback/private）
	var ipTotalNonLocal int64          // 非 loopback/private 的总请求数

	var parsed int
	minTS := int64(0)
	maxTS := int64(0)

	for scanner.Scan() {
		if parsed >= preloadMaxLines {
			break
		}
		parsed++

		line := scanner.Text()
		ev, err := lp(line)
		if err != nil {
			continue
		}
		if ev.Timestamp <= 0 {
			continue
		}

		if minTS == 0 || ev.Timestamp < minTS {
			minTS = ev.Timestamp
		}
		if ev.Timestamp > maxTS {
			maxTS = ev.Timestamp
		}

		bucketKey := ev.Timestamp / 300 * 300
		bk, ok := buckets[bucketKey]
		if !ok {
			bk = &timeBucket{}
			buckets[bucketKey] = bk
		}
		bk.totalReq++
		switch ev.Status {
		case 404:
			bk.count404++
		case 401, 403:
			bk.authFail++
			bk.count4xx++
		case 400, 405, 408, 429, 422:
			bk.count4xx++
		case 500, 501, 502, 503, 504:
			bk.count5xx++
		}

		// IP 多样性统计：跳过 loopback/private/空 IP
		// 内部健康检查探针不应干扰反代判定
		if ev.SourceIP != "" && !isLoopbackIP(ev.SourceIP) && !isPrivateOrLocal(ev.SourceIP) {
			ipCount[ev.SourceIP]++
			ipTotalNonLocal++
		}
	}

	if err := scanner.Err(); err != nil {
		stats.Duration = time.Since(start).String()
		return stats, fmt.Errorf("scan log %s: %w", path, err)
	}

	stats.ScannedLines = parsed

	if len(buckets) == 0 || maxTS == 0 {
		stats.Duration = time.Since(start).String()
		// 无有效日志时也做一次反代判定（uniqueIPs=0 返回 false，安全放行）
		d.fillIPDiversityStats(&stats, ipCount, ipTotalNonLocal)
		return stats, nil
	}

	// === 自适应时间窗口过滤 ===
	// 问题：固定 minutes=10 只会留下 2 个 5min 桶，healthy 可能只有 1 个，
	//       导致 confidence 被 ×0.5 惩罚，QPS 维度 MAD/trimExtremes 因 len<5 直接跳过。
	// 方案：从传入的 minutes 开始尝试，若健康桶 < preloadTargetHealthyBuckets(10)，
	//       每次多扩 30min，最多到 preloadMaxWindowMinutes(4h)，保证 ~50min+ 有效样本。
	//       不删除 buckets map，只在计算时用 finalCutoff 过滤。

	// 排序所有桶键一次
	sortedKeys := make([]int64, 0, len(buckets))
	for k := range buckets {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Slice(sortedKeys, func(i, j int) bool { return sortedKeys[i] < sortedKeys[j] })

	// 自适应寻找最小 cutoff：让窗口内健康桶 ≥ preloadTargetHealthyBuckets
	finalCutoff := maxTS - int64(minutes)*60
	actualWindowMin := minutes
	for tryMin := minutes; tryMin <= preloadMaxWindowMinutes; tryMin += 30 {
		cutoffCandidate := maxTS - int64(tryMin)*60

		// 计算此候选窗口内的 median 和 healthy 数
		var winReqCounts []float64
		for _, k := range sortedKeys {
			if k >= cutoffCandidate {
				winReqCounts = append(winReqCounts, float64(buckets[k].totalReq))
			}
		}
		if len(winReqCounts) == 0 {
			continue
		}
		sort.Float64s(winReqCounts)
		tryMedian := winReqCounts[len(winReqCounts)/2]
		if tryMedian <= 0 {
			tryMedian = 1
		}
		tryThresh := tryMedian * 0.5
		tryHealthy := 0
		for _, c := range winReqCounts {
			if c >= tryThresh {
				tryHealthy++
			}
		}

		finalCutoff = cutoffCandidate
		actualWindowMin = tryMin
		if tryHealthy >= preloadTargetHealthyBuckets {
			break
		}
		// 已包含日志中全部桶，无法再扩
		if minTS >= cutoffCandidate {
			break
		}
	}

	// 用最终 cutoff 过滤，得到正式的 median / healthyThreshold / totalBuckets
	var reqCounts []float64
	for _, k := range sortedKeys {
		if k >= finalCutoff {
			reqCounts = append(reqCounts, float64(buckets[k].totalReq))
		}
	}
	sort.Float64s(reqCounts)
	medianReq := reqCounts[len(reqCounts)/2]
	if medianReq <= 0 {
		medianReq = 1
	}
	healthyThreshold := medianReq * 0.5
	totalBuckets := len(reqCounts)

	var (
		healthyCount int
		qpsVals      []float64
		rate4xxVals  []float64
		rate5xxVals  []float64
		rate404Vals  []float64
		rateAuthVals []float64
	)

	for _, k := range sortedKeys {
		if k < finalCutoff {
			continue
		}
		b := buckets[k]
		if float64(b.totalReq) < healthyThreshold {
			continue
		}
		healthyCount++
		bWinSec := 300
		qpsVals = append(qpsVals, float64(b.totalReq)/float64(bWinSec))
		if b.totalReq > 0 {
			t := float64(b.totalReq)
			rate4xxVals = append(rate4xxVals, float64(b.count4xx)/t)
			rate5xxVals = append(rate5xxVals, float64(b.count5xx)/t)
			rate404Vals = append(rate404Vals, float64(b.count404)/t)
			rateAuthVals = append(rateAuthVals, float64(b.authFail)/t)
		}
	}

	confidence := float64(healthyCount) / float64(totalBuckets)
	if confidence > 1 {
		confidence = 1
	}
	if healthyCount < 10 {
		confidence *= 0.5
	}

	qpsVals = trimExtremes(qpsVals, 10)
	rate4xxVals = trimExtremes(rate4xxVals, 10)
	rate5xxVals = trimExtremes(rate5xxVals, 10)
	rate404Vals = trimExtremes(rate404Vals, 10)
	rateAuthVals = trimExtremes(rateAuthVals, 10)

	// === QPS 极端桶剔除（MAD 方法）===
	// trimExtremes 只能砍比 P99 还极端 10 倍的值，砍不掉 P99 本身。
	// 扫描器/爬虫/batch sync 桶往往就是 P95/P99 那些点，所以用 MAD 直接删掉。
	// MAD = median(|x - median|)；x > median + 5*MAD 视为极端值。
	// 5×MAD 对应正态分布 ~3σ 原则，但 MAD 本身对极端值鲁棒。
	//
	// 你的场景：median=1.4, MAD≈0.5 → 阈值=1.4+5*0.5=3.9 req/s
	// 扫描器桶=70.96 > 3.9 → 被删掉 ✅
	// 正常桶=3 req/s < 3.9 → 保留 ✅
	qpsValsBefore := len(qpsVals)
	qpsVals = removeOutliersMAD(qpsVals, 5.0)
	qpsRemoved := qpsValsBefore - len(qpsVals)

	qpsDist := computePercentiles(qpsVals)

	// 动态 MIN：用 preload 计算出的 qpsDist 自身来推导
	// preload 还没有 Baseline 对象，构造临时 BaselineDimensions 喂给 computeMinQPS
	preloadMIN := computeMinQPS(BaselineDimensions{QPS: qpsDist})

	// 如果 MAD 删干净了（全是极端值，不太可能），保底给 preloadMIN
	if qpsDist.P95 < preloadMIN {
		qpsDist.P95 = preloadMIN
		qpsDist.P99 = preloadMIN * 2
		qpsDist.P50 = preloadMIN * 0.3
	}

	firstTime := time.Unix(minTS, 0).Format("2006-01-02 15:04")
	lastTime := time.Unix(maxTS, 0).Format("2006-01-02 15:04")
	durationMin := int(float64(maxTS-minTS) / 60)

	stats.TimeStart = firstTime
	stats.TimeEnd = lastTime
	stats.DurationMin = durationMin
	stats.TotalBuckets = totalBuckets
	stats.ActualWindowMin = actualWindowMin
	stats.HealthyBuckets = healthyCount
	stats.HealthyReqMin = healthyThreshold
	stats.MedianReq = medianReq
	stats.QPSP50 = qpsDist.P50
	stats.QPSP95 = qpsDist.P95
	stats.QPSP99 = qpsDist.P99
	stats.QPSSamples = len(qpsVals)
	stats.Confidence = confidence

	for i := 0; i < 3; i++ {
		bl := d.scorer.baselines[i]

		scaleFactor := 1.0 // 所有窗口用同一 QPS P95，不主动放大。运行时 Update 自然调整。

		curr := BaselineDimensions{
			QPS:          Percentile{N: len(qpsVals)},
			Rate4xx:      computePercentiles(rate4xxVals),
			Rate5xx:      computePercentiles(rate5xxVals),
			Rate404:      computePercentiles(rate404Vals),
			RateAuthFail: computePercentiles(rateAuthVals),
			RateSensPath: Percentile{N: 0, P95: 1.0, P99: 1.0},
			RateBotUA:    Percentile{N: 0, P95: 1.0, P99: 1.0},
			RateEmptyRef: Percentile{N: 0, P95: 1.0, P99: 1.0},
		}

		if len(qpsVals) > 0 {
			curr.QPS.P50 = qpsDist.P50 * scaleFactor
			curr.QPS.P95 = qpsDist.P95 * scaleFactor
			curr.QPS.P99 = qpsDist.P99 * scaleFactor
		} else {
			curr.QPS.P50 = preloadMIN * 0.3
			curr.QPS.P95 = preloadMIN
			curr.QPS.P99 = preloadMIN * 2
		}

		// 动态 MIN 再次检查（scaleFactor 放大后也不能低于 MIN）
		winMIN := computeMinQPS(BaselineDimensions{QPS: curr.QPS})
		if curr.QPS.P95 < winMIN {
			curr.QPS.P95 = winMIN
			if curr.QPS.P99 < winMIN*2 {
				curr.QPS.P99 = winMIN * 2
			}
		}

		bl.mu.Lock()
		bl.dims = curr
		bl.sampleCount = healthyCount * 10
		bl.mu.Unlock()
		bl.ForceReady()
		bl.SetConfidence(confidence)

		stats.BaselineQPS[i] = curr.QPS.P95
	}

	stats.QPSOutliersRemoved = qpsRemoved

	// === IP 多样性统计 + 反代判定 ===
	d.fillIPDiversityStats(&stats, ipCount, ipTotalNonLocal)

	stats.Duration = time.Since(start).String()
	return stats, nil
}

// fillIPDiversityStats 从 ipCount map 计算 IP 多样性指标并写入 stats。
// 包括 UniqueIPs、Top1IP/Count/Ratio、Top3Ratio，以及反代判定标记。
// ipTotal 是排除 loopback/private 后的总请求数（作为 Ratio 分母）。
func (d *LocalDetector) fillIPDiversityStats(stats *PreloadStats, ipCount map[string]int64, ipTotal int64) {
	if stats == nil {
		return
	}

	uniqueIPs := len(ipCount)
	stats.UniqueIPs = uniqueIPs

	if uniqueIPs == 0 || ipTotal == 0 {
		// 没有有效公网 IP 数据：保守放行，不触发反代检测
		stats.ReverseProxyDetected = false
		return
	}

	// 按 count 排序取 Top 3
	type kv struct {
		ip    string
		count int64
	}
	var top [3]kv
	for ip, cnt := range ipCount {
		if cnt > top[0].count {
			top[2] = top[1]
			top[1] = top[0]
			top[0] = kv{ip: ip, count: cnt}
		} else if cnt > top[1].count {
			top[2] = top[1]
			top[1] = kv{ip: ip, count: cnt}
		} else if cnt > top[2].count {
			top[2] = kv{ip: ip, count: cnt}
		}
	}

	stats.Top1IP = top[0].ip
	stats.Top1Count = top[0].count
	stats.Top1Ratio = float64(top[0].count) / float64(ipTotal)

	var top3Sum int64
	for i := 0; i < 3; i++ {
		top3Sum += top[i].count
	}
	stats.Top3Ratio = float64(top3Sum) / float64(ipTotal)

	// 反代判定
	stats.ReverseProxyDetected = isReverseProxySuspicious(uniqueIPs, stats.Top1Ratio, stats.Top3Ratio)
}

// isReverseProxySuspicious 判定 IP 多样性是否暗示"反向代理未透传真实客户端 IP"。
//
// 三个条件满足任一即返回 true：
//   条件 A: uniqueIPs <= proxySingleIPThreshold (3) — 单反代/双反代
//   条件 B: uniqueIPs <= proxyMinUniqueIPsForSafe (11) 且 top1Ratio >= 0.90 — N+1 反代集中
//   条件 C: uniqueIPs <= proxyMinUniqueIPsForSafe (11) 且 top3Ratio >= 0.98 — 少数反代包揽
//
// 设计：
//   - uniqueIPs > 10 时直接安全（正常站点不太可能 11+ 个反代节点）
//   - top1Ratio/top3Ratio 是 0~1 的比例值，不是百分比
//   - uniqueIPs == 0 时也返回 false（没有有效数据，不能武断判定）
func isReverseProxySuspicious(uniqueIPs int, top1Ratio, top3Ratio float64) bool {
	if uniqueIPs == 0 {
		return false // 无有效 IP 数据，保守放行让基线冷启动兜底
	}
	if uniqueIPs <= proxySingleIPThreshold {
		return true // 条件 A
	}
	if uniqueIPs < proxyMinUniqueIPsForSafe {
		// uniqueIPs 在 [4, 10] 区间：检查条件 B 和 C
		if top1Ratio >= proxyTop1RatioThreshold {
			return true // 条件 B
		}
		if top3Ratio >= proxyTop3RatioThreshold {
			return true // 条件 C
		}
	}
	return false
}

// Close 停止后台 evict goroutine 和基线更新 goroutine。重复调用安全。
func (d *LocalDetector) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return
	}
	d.closed = true
	if d.baselineStop != nil {
		d.baselineOnce.Do(func() { close(d.baselineStop) })
	}
	if d.observStop != nil {
		d.observOnce.Do(func() { close(d.observStop) })
	}
	d.observMu.Lock()
	d.observations = nil
	d.observMu.Unlock()
	if d.window != nil {
		d.window.Close()
	}
	if d.resourceBaseline != nil {
		d.resourceBaseline.Close()
	}
}

// isLoopbackIP 判断 IP 字符串是否为本地回环地址。
// 同时支持 IPv4 (127.0.0.0/8) 和 IPv6 (::1)。
// 解析失败（空字符串 / 非法 IP）返回 false，不影响正常流量。
func isLoopbackIP(ip string) bool {
	if ip == "" {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.IsLoopback()
}

// isPrivateOrLocal 判断 IP 是否属于内网/本地/链路本地。
// 这些 IP 是内部服务流量（健康检查探针、运维脚本、内网 RPA），
// 永远不是外部扫描威胁，不进 Window 计数、不记基线、不打分。
//
// 覆盖范围: 127.0.0.0/8（回环）、10.0.0.0/8、172.16.0.0/12、192.168.0.0/16
//         169.254.0.0/16（链路本地）、IPv6 链路本地/私有/回环/未指定
func isPrivateOrLocal(ip string) bool {
	if ip == "" {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() ||
		parsed.IsLinkLocalMulticast() || parsed.IsInterfaceLocalMulticast() ||
		ip == "0.0.0.0" || ip == "::"
}

// HasSeenRecently 查询该 IP 在 Detector 的 SlidingWindow 中是否有最近 window 内的访问记录。
// 用于 SyncEngine 的 localScoreFn 回调——云端下发一个评分但 Agent 从未见过这个 IP → 返回 0 分数。
// 纯内存查询（map 查找 + last 时间戳比较），不做任何 IO。
func (d *LocalDetector) HasSeenRecently(ip string, window time.Duration) bool {
	if d == nil || d.window == nil || ip == "" {
		return false
	}
	d.window.mu.RLock()
	defer d.window.mu.RUnlock()
	e, ok := d.window.ips[ip]
	if !ok {
		return false
	}
	now := time.Now().Unix()
	cutoff := now - int64(window.Seconds())
	e.mu.Lock()
	last := e.last
	e.mu.Unlock()
	return last >= cutoff
}

// GetRecentScore 返回该 IP 当前 SlidingWindow 下的 Detector 评分（0-100）。
// 用于 SyncEngine 的 localScoreFn 回调——把本地检测的真实分数传给综合决策引擎。
// 纯内存查询，不做任何 IO。
// 没有记录时返回 0（不是 50 的中性占位值），调用方用 0 表示"本地没见过"。
func (d *LocalDetector) GetRecentScore(ip string) float64 {
	if d == nil || d.window == nil || d.scorer == nil || ip == "" {
		return 0
	}
	d.window.mu.RLock()
	e, ok := d.window.ips[ip]
	d.window.mu.RUnlock()
	if !ok {
		return 0
	}
	// 用 ipEntry.mu 保护 ipWindow 的并发读写（与 Record 共享锁）
	e.mu.Lock()
	nowSec := time.Now().Unix()
	var counters [3]WindowCounters
	for i := 0; i < 3; i++ {
		if e.window[i] != nil {
			counters[i] = e.window[i].sum(nowSec)
		}
	}
	qpsEMA := e.qpsEMA
	seenCount := e.seenCount
	e.mu.Unlock()

	result := d.scorer.ScoreWithDetail(counters, qpsEMA, seenCount)
	return float64(result.FinalScore)
}

// GetLocalScores 返回该 IP 的两个独立本地信号分：
//   - freq:    相对特征基线偏离分（QPS/4xx/404/5xx/AuthFail/SensPath/BotUA/EmptyRef/HeadMethod，封顶 ScoreHigh）
//   - detect:  Detector 综合检测分（同 GetRecentScore，绝对 + 相对特征，封顶 ScoreHigh*2）
// 纯内存查询，不做任何 IO。本地未见过时返回 (0, 0)。
// 这两个分数供 cloudsync.Decide 决策引擎使用——freq 代表"频率/流量异常"，
// detect 代表"攻击行为综合判定"，是 DecisionEngine 的两个独立信号源。
func (d *LocalDetector) GetLocalScores(ip string) (freq, detect float64) {
	if d == nil || d.window == nil || d.scorer == nil || ip == "" {
		return 0, 0
	}
	d.window.mu.RLock()
	e, ok := d.window.ips[ip]
	d.window.mu.RUnlock()
	if !ok {
		return 0, 0
	}
	e.mu.Lock()
	nowSec := time.Now().Unix()
	var counters [3]WindowCounters
	for i := 0; i < 3; i++ {
		if e.window[i] != nil {
			counters[i] = e.window[i].sum(nowSec)
		}
	}
	qpsEMA := e.qpsEMA
	seenCount := e.seenCount
	e.mu.Unlock()

	result := d.scorer.ScoreWithDetail(counters, qpsEMA, seenCount)
	high := d.cfg.ScoreHigh

	// detect: 综合分（FinalScore，已在 scorer 内部封顶 ScoreHigh*2）
	detect = float64(result.FinalScore)

	// freq: 只取相对特征维度，三档窗口取最高档，封顶 ScoreHigh
	bestFreq := 0
	for i := 0; i < 3; i++ {
		dist := result.Details[i]
		sum := dist.QPSScore + dist.Status4xxScore + dist.Status5xxScore +
			dist.AuthFailScore + dist.Status404Score + dist.SensitivePathScore +
			dist.BotUAScore + dist.EmptyRefererScore + dist.HeadMethodScore
		if sum > bestFreq {
			bestFreq = sum
		}
	}
	if bestFreq > high {
		bestFreq = high
	}
	freq = float64(bestFreq)
	return freq, detect
}

// SetWeights 热更 Detector 的特征库权重（ScoreWeights）。
// 云端 FetchFeatures 通道同步 weights 后调用。
// 非零字段才覆盖（0 表示"保留本地默认值"）。
// 线程安全：LocalDetector.cfg 改为 *DetectorCfg，Scorer 共享同一份指针——
// 直接改 cfg.Weights，Scorer 下次打分自动使用新值。
func (d *LocalDetector) SetWeights(w ScoreWeights) {
	if d == nil || d.cfg == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if w.DangerousPattern > 0 {
		d.cfg.Weights.DangerousPattern = w.DangerousPattern
	}
	if w.DangerousMethod > 0 {
		d.cfg.Weights.DangerousMethod = w.DangerousMethod
	}
	if w.HeadMethod > 0 {
		d.cfg.Weights.HeadMethod = w.HeadMethod
	}
	if w.FileUpload > 0 {
		d.cfg.Weights.FileUpload = w.FileUpload
	}
}

// isTrustedSubnet 判断该 IP 是否命中 TrustedSubnets CIDR 列表。
// 空列表或无效 IP 返回 false。纯内存遍历（k 通常 < 10）。
func (d *LocalDetector) isTrustedSubnet(ip string) bool {
	if d == nil || len(d.trustedSubnets) == 0 || ip == "" {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range d.trustedSubnets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}
