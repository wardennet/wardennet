// Package threatreporter 负责将 detector 检测到的威胁事件
// 聚合后批量上报给云端（通过 plugin.Report）。
//
//  架构变更（V2 法律合规加固 + 闭源插件承担防投毒逻辑）：
//
//  threatreporter（开源端）将完整 detector.Event 传递给闭源插件。
//  闭源插件内部负责：
//    1. 防投毒校验（信誉评分 / 批量刷票检测 / IP 交叉验证）
//    2. 本地威胁评分调整（商业模型，闭源）
//    3. 聚合去重（同一 IP 多条合并）
//    4. 合规裁剪（最终只上传最小威胁情报载荷）
//
//  云端只接收闭源插件加工后的最终结果，不再做业务判断。
//
//  设计原则：
//   1. 零云端凭证持有 — 仅依赖 plugin.Plugin.Report 接口，API 调用由插件内部实现
//   2. 批量聚合 — buffer 满或定时器触发时才上报，避免高频单条调用
//   3. 降级安全 — plugin 为 NoopPlugin（离线）时静默丢弃，绝不阻塞 detector
//   4. 并发安全 — 支持多 goroutine 并发 Add（detector.BlockTrigger 在检测 goroutine 触发）
package threatreporter

import (
	"sync"
	"time"

	"github.com/wardennet/agent/internal/detector"
	"github.com/wardennet/agent/internal/plugin"
)

// Reporter threatreporter 的完整载荷（V2）。
//
// 这是开源端 buffer 里暂存的完整威胁事件，包含 detector.Event 的所有字段。
// 完整数据在本地：
//   1. 驱动 detector 评分 + 本地 ipset 拉黑 ✅ 本地合法
//   2. 传给闭源插件做防投毒校验和商业加工 ✅ 闭源插件是商业交付物，合规边界在闭源端内部
//
// 闭源插件收到后内部会：
//   - 做自己的防投毒逻辑（信誉评分 / 批量刷票检测 / 行为画像）
//   - 调整评分 / 聚合 / 去重
//   - 合规裁剪成 FinalThreatPayload（只含 attacker_ip + score 等 7 字段）
//   - 最终上传裁剪后的 FinalThreatPayload 到云端
//
// 开源端**不感知**闭源插件内部做了什么加工，也不参与裁剪——这些全在闭源端完成。
type Reporter struct {
	plugin  plugin.Plugin
	agentID string
	cfg     Config

	mu     sync.Mutex
	buffer []detector.Event // 暂存完整 detector.Event

	stopCh chan struct{}
	wg     sync.WaitGroup
	closed bool

	// 统计
	flushCount int64
	sentCount  int64
	dropCount  int64
}

// Config Reporter 配置。所有字段都有合理默认值。
type Config struct {
	// BufferSize 批量上报的最大事件数，攒满立即 flush。默认 50。
	BufferSize int
	// FlushInterval 定时 flush 间隔，即使 buffer 未满也发送。默认 10s。
	FlushInterval time.Duration
}

// DefaultConfig 返回默认配置。
func DefaultConfig() Config {
	return Config{
		BufferSize:    50,
		FlushInterval: 10 * time.Second,
	}
}

// New 创建 Reporter。p 为 nil 时内部使用 NoopPlugin（离线降级）。
func New(p plugin.Plugin, agentID string, cfg Config) *Reporter {
	if p == nil {
		p = &plugin.NoopPlugin{}
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = DefaultConfig().BufferSize
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = DefaultConfig().FlushInterval
	}
	return &Reporter{
		plugin:  p,
		agentID: agentID,
		cfg:     cfg,
		buffer:  make([]detector.Event, 0, cfg.BufferSize),
		stopCh:  make(chan struct{}),
	}
}

// Start 启动后台 flush goroutine。非阻塞，可重复调用（仅首次启动）。
func (r *Reporter) Start() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.wg.Add(1)
	r.mu.Unlock()

	go r.flushLoop()
}

// Stop 停止后台 goroutine 并 flush 剩余事件。可重复调用。
func (r *Reporter) Stop() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	close(r.stopCh)
	r.mu.Unlock()

	r.wg.Wait()
	r.flush() // 最后一次 flush，不要丢数据
}

// flushLoop 定时 flush。buffer 满也会在 Add 里立即 flush。
func (r *Reporter) flushLoop() {
	defer r.wg.Done()
	ticker := time.NewTicker(r.cfg.FlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.flush()
		}
	}
}

// Add 添加一条威胁事件（完整 detector.Event）。并发安全。
//
// detector.Event 包含完整访问上下文（Path / Method / UA / Status 等）——
// 这些在本地用于驱动 detector 评分和 ipset 拉黑是合法的（本地数据不出界）。
// 传给闭源插件后，闭源插件内部自行完成防投毒校验 + 商业加工 + 合规裁剪。
//
// 开源端不参与裁剪逻辑，裁剪责任在闭源插件内部完成。
func (r *Reporter) Add(ev detector.Event) {
	if ev.SourceIP == "" {
		return // 没有攻击者 IP，丢弃（联防无价值）
	}

	r.mu.Lock()
	r.buffer = append(r.buffer, ev)
	shouldFlush := len(r.buffer) >= r.cfg.BufferSize
	r.mu.Unlock()

	if shouldFlush {
		go r.flush()
	}
}

// flush 将 buffer 里的完整 detector.Event 批量传给闭源插件。
//
// 开源端到此为止——之后闭源插件内部负责：
//   1. 接收完整事件列表
//   2. 闭源防投毒校验（信誉评分 / 批量刷票 / IP 画像）
//   3. 商业评分调整
//   4. 合规裁剪 → FinalThreatPayload（只含 attacker_ip + score + source + timestamp）
//   5. 聚合去重后上报云端
//
// 任何错误都只记 dropCount，不向上抛——detector 不应该因为云端不可用而阻塞。
func (r *Reporter) flush() {
	r.mu.Lock()
	if len(r.buffer) == 0 {
		r.mu.Unlock()
		return
	}
	batch := r.buffer
	r.buffer = make([]detector.Event, 0, r.cfg.BufferSize)
	r.mu.Unlock()

	// 直接将完整 detector.Event 列表传给闭源插件
	// 闭源插件内部自行完成：防投毒 + 商业评分 + 聚合去重 + 合规裁剪 + 加密上传
	// 开源端到此为止——不做任何裁剪或加工
	if err := r.plugin.ReportFull(batch); err != nil {
		// 上报失败：静默丢弃，detector 不阻塞
		r.mu.Lock()
		r.dropCount += int64(len(batch))
		r.flushCount++
		r.mu.Unlock()
		return
	}

	r.mu.Lock()
	r.flushCount++
	r.sentCount += int64(len(batch))
	r.mu.Unlock()
}

// Stats 返回当前统计快照。
type Stats struct {
	BufferLen  int   `json:"buffer_len"`
	FlushCount int64 `json:"flush_count"`
	SentCount  int64 `json:"sent_count"`
	DropCount  int64 `json:"drop_count"`
}

// Stats 线程安全地获取统计。
func (r *Reporter) Stats() Stats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return Stats{
		BufferLen:  len(r.buffer),
		FlushCount: r.flushCount,
		SentCount:  r.sentCount,
		DropCount:  r.dropCount,
	}
}