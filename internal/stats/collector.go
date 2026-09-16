// Package stats 提供 Agent 运行时统计数据收集与分析功能。
// 用于帮助运维人员观察检测引擎效果、分析真实数据、持续调优。
package stats

import (
	"sync"
	"time"
)

// DetectorReport 检测引擎运行报告。
type DetectorReport struct {
	// 时间窗口
	StartTime   int64 `json:"start_time"`
	WindowSec   int   `json:"window_sec"`   // 报告覆盖的时间窗口（秒）
	ReportTime  int64 `json:"report_time"`  // 报告生成时间

	// 流量统计
	ProcessedEvents int64 `json:"processed_events"` // detector 实际处理的所有事件数（不受 score_low 过滤）
	TotalEvents     int64 `json:"total_events"`     // 总事件数（score >= score_low 才计入）
	TotalIPs        int64 `json:"total_ips"`        // 独立 IP 数
	HighScoreCount  int64 `json:"high_score_count"` // 高风险（触发拉黑）数
	MediumCount     int64 `json:"medium_count"`     // 中风险（score > 阈值但未拉黑）
	LowScoreCount   int64 `json:"low_score_count"`  // 低风险（正常流量）

	// 检测维度分布（命中次数）
	SensitivePathHits int64 `json:"sensitive_path_hits"`
	BotUAHits         int64 `json:"bot_ua_hits"`
	EmptyRefererHits  int64 `json:"empty_referer_hits"`
	DangerousMethodHits int64 `json:"dangerous_method_hits"`
	AuthFailHits      int64 `json:"auth_fail_hits"`

	// 状态码分布
	Status2xx int64 `json:"status_2xx"`
	Status3xx int64 `json:"status_3xx"`
	Status4xx int64 `json:"status_4xx"`
	Status5xx int64 `json:"status_5xx"`

	// 来源分布
	SourceNginx   int64 `json:"source_nginx"`
	SourceApache  int64 `json:"source_apache"`
	SourceTomcat  int64 `json:"source_tomcat"`
	SourceLinux   int64 `json:"source_linux"`

	// Top 10 高风险 IP
	TopBlocked []BlockedIP `json:"top_blocked"`
}

// BlockedIP 被拉黑 IP 详情。
type BlockedIP struct {
	IP          string `json:"ip"`
	Score       int    `json:"score"`
	BlockCount  int64  `json:"block_count"`
	LastBlockAt int64  `json:"last_block_at"`
	Sources     []string `json:"sources,omitempty"`
}

// EventRecord 记录每个事件的检测详情（用于调试/分析）。
type EventRecord struct {
	Timestamp int64  `json:"timestamp"`
	SourceIP  string `json:"source_ip"`
	Score     int    `json:"score"`
	IsHigh    bool   `json:"is_high"`
	Blocked   bool   `json:"blocked"` // 多事件确认后的最终封禁决策（shouldBlock 返回值）
	Source    string `json:"source"`
	Path      string `json:"path,omitempty"`
	Method    string `json:"method,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	Status    int    `json:"status"`

	// 各维度命中详情
	Dimensions map[string]interface{} `json:"dimensions,omitempty"`
}

// Collector 统计数据收集器。
// 线程安全，支持定期生成报告。
type Collector struct {
	mu sync.RWMutex

	startTime time.Time

	// 事件计数
	processedEvents int64
	totalEvents     int64
	totalIPs        map[string]struct{}
	highScoreCount  int64
	mediumCount     int64
	lowScoreCount   int64

	// 维度命中
	sensitivePathHits   int64
	botUAHits           int64
	emptyRefererHits    int64
	dangerousMethodHits int64
	authFailHits        int64

	// 状态码
	status2xx int64
	status3xx int64
	status4xx int64
	status5xx int64

	// 来源
	sourceNginx  int64
	sourceApache int64
	sourceTomcat int64
	sourceLinux  int64

	// Top blocked
	blockedIPs map[string]*BlockedIP

	// 最近事件采样（环形缓冲区，最多保留 1000 条）
	recentEvents []EventRecord
	recentCap    int
	recentIdx    int

	// 采样率控制（debug 模式下全记录，否则采样 1/100）
	sampleRate int // 0 = 全记录, N > 0 = 每 N 条记录 1 条
	counter    int
}

// NewCollector 创建统计收集器。
// sampleRate: 事件采样率，0=全记录，100=1/100 采样。
func NewCollector(sampleRate int) *Collector {
	if sampleRate < 0 {
		sampleRate = 0
	}
	return &Collector{
		startTime:   time.Now(),
		totalIPs:    make(map[string]struct{}),
		blockedIPs:  make(map[string]*BlockedIP),
		recentCap:   1000,
		recentEvents: make([]EventRecord, 0, 1000),
		sampleRate:  sampleRate,
	}
}

// IncrementProcessed 记录一个被 detector 处理的事件（不受 score_low 过滤，每次 Process 都 +1）。
// 用于和 Record 里的 totalEvents 对比：processedEvents 是全量，totalEvents 是 score >= score_low 的子集。
func (c *Collector) IncrementProcessed() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.processedEvents++
}

// Record 记录一个事件的检测结果。
func (c *Collector) Record(ev EventRecord) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.totalEvents++
	c.totalIPs[ev.SourceIP] = struct{}{}

	// 风险分级（三档互斥）
	//   highScoreCount: score >= ScoreHigh 的事件数（进入观察名单等待多事件确认）
	//   mediumCount:    score 在 ScoreMedium ~ ScoreHigh 之间
	//   lowScoreCount:  score < ScoreMedium
	// recordBlocked 只在真正触发封禁时登记（ev.Blocked=true，来自 shouldBlock 决策）
	if ev.IsHigh {
		c.highScoreCount++
		if ev.Blocked {
			c.recordBlocked(ev)
		}
	} else if ev.Score > 0 {
		c.mediumCount++
	} else {
		c.lowScoreCount++
	}

	// 状态码分布
	if ev.Status >= 200 && ev.Status < 300 {
		c.status2xx++
	} else if ev.Status >= 300 && ev.Status < 400 {
		c.status3xx++
	} else if ev.Status >= 400 && ev.Status < 500 {
		c.status4xx++
	} else if ev.Status >= 500 {
		c.status5xx++
	}

	// 来源分布
	switch ev.Source {
	case "nginx_access":
		c.sourceNginx++
	case "apache_access":
		c.sourceApache++
	case "tomcat_access":
		c.sourceTomcat++
	case "linux_auth":
		c.sourceLinux++
	}

	// 维度命中统计
	if dims := ev.Dimensions; dims != nil {
		if v, ok := dims["sensitive_path"].(bool); ok && v {
			c.sensitivePathHits++
		}
		if v, ok := dims["bot_ua"].(bool); ok && v {
			c.botUAHits++
		}
		if v, ok := dims["empty_referer"].(bool); ok && v {
			c.emptyRefererHits++
		}
		if v, ok := dims["dangerous_method"].(bool); ok && v {
			c.dangerousMethodHits++
		}
		if v, ok := dims["auth_fail"].(bool); ok && v {
			c.authFailHits++
		}
	}

	// 事件采样
	if c.sampleRate == 0 || (c.counter%c.sampleRate == 0) {
		c.addRecent(ev)
	}
	c.counter++
}

func (c *Collector) recordBlocked(ev EventRecord) {
	ip, ok := c.blockedIPs[ev.SourceIP]
	if !ok {
		ip = &BlockedIP{
			IP:          ev.SourceIP,
			Score:       ev.Score,
			BlockCount:  0,
			LastBlockAt: ev.Timestamp,
			Sources:     []string{ev.Source},
		}
		c.blockedIPs[ev.SourceIP] = ip
	}
	ip.BlockCount++
	if ev.Score > ip.Score {
		ip.Score = ev.Score
	}
	ip.LastBlockAt = ev.Timestamp

	// 去重来源
	found := false
	for _, s := range ip.Sources {
		if s == ev.Source {
			found = true
			break
		}
	}
	if !found {
		ip.Sources = append(ip.Sources, ev.Source)
	}
}

func (c *Collector) addRecent(ev EventRecord) {
	if len(c.recentEvents) < c.recentCap {
		c.recentEvents = append(c.recentEvents, ev)
	} else {
		c.recentEvents[c.recentIdx] = ev
		c.recentIdx = (c.recentIdx + 1) % c.recentCap
	}
}

// GenerateReport 生成当前时间窗口的检测报告。
func (c *Collector) GenerateReport() DetectorReport {
	c.mu.RLock()
	defer c.mu.RUnlock()

	now := time.Now()
	windowSec := int(now.Sub(c.startTime).Seconds())
	if windowSec < 1 {
		windowSec = 1
	}

	report := DetectorReport{
		StartTime:           c.startTime.Unix(),
		WindowSec:           windowSec,
		ReportTime:          now.Unix(),
		ProcessedEvents:     c.processedEvents,
		TotalEvents:         c.totalEvents,
		TotalIPs:            int64(len(c.totalIPs)),
		HighScoreCount:      c.highScoreCount,
		MediumCount:         c.mediumCount,
		LowScoreCount:       c.lowScoreCount,
		SensitivePathHits:   c.sensitivePathHits,
		BotUAHits:           c.botUAHits,
		EmptyRefererHits:    c.emptyRefererHits,
		DangerousMethodHits: c.dangerousMethodHits,
		AuthFailHits:        c.authFailHits,
		Status2xx:           c.status2xx,
		Status3xx:           c.status3xx,
		Status4xx:           c.status4xx,
		Status5xx:           c.status5xx,
		SourceNginx:         c.sourceNginx,
		SourceApache:        c.sourceApache,
		SourceTomcat:        c.sourceTomcat,
		SourceLinux:         c.sourceLinux,
		TopBlocked:          c.topBlocked(10),
	}

	return report
}

// RecentEvents 返回最近的采样事件（拷贝）。
func (c *Collector) RecentEvents(n int) []EventRecord {
	c.mu.RLock()
	defer c.mu.RUnlock()

	total := len(c.recentEvents)
	if n <= 0 || n > total {
		n = total
	}
	result := make([]EventRecord, n)
	// 从最新的开始
	for i := 0; i < n; i++ {
		idx := (c.recentIdx - 1 - i + c.recentCap) % c.recentCap
		if idx < total {
			result[i] = c.recentEvents[idx]
		}
	}
	return result
}

// topBlocked 返回 Top N 高风险 IP。
func (c *Collector) topBlocked(n int) []BlockedIP {
	if n <= 0 || len(c.blockedIPs) == 0 {
		return nil
	}
	type kv struct {
		ip    string
		count int64
	}
	var pairs []kv
	for ip, b := range c.blockedIPs {
		pairs = append(pairs, kv{ip, b.BlockCount})
	}
	// 简单排序（BlockCount 降序）
	for i := 0; i < len(pairs); i++ {
		for j := i + 1; j < len(pairs); j++ {
			if pairs[j].count > pairs[i].count {
				pairs[i], pairs[j] = pairs[j], pairs[i]
			}
		}
	}
	if n > len(pairs) {
		n = len(pairs)
	}
	result := make([]BlockedIP, n)
	for i := 0; i < n; i++ {
		result[i] = *c.blockedIPs[pairs[i].ip]
	}
	return result
}

// Reset 重置计数器（用于定期生成快照）。
func (c *Collector) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.startTime = time.Now()
	c.processedEvents = 0
	c.totalEvents = 0
	c.totalIPs = make(map[string]struct{})
	c.highScoreCount = 0
	c.mediumCount = 0
	c.lowScoreCount = 0
	c.sensitivePathHits = 0
	c.botUAHits = 0
	c.emptyRefererHits = 0
	c.dangerousMethodHits = 0
	c.authFailHits = 0
	c.status2xx = 0
	c.status3xx = 0
	c.status4xx = 0
	c.status5xx = 0
	c.sourceNginx = 0
	c.sourceApache = 0
	c.sourceTomcat = 0
	c.sourceLinux = 0
	c.blockedIPs = make(map[string]*BlockedIP)
}
