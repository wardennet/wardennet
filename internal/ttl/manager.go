// Package ttl 实现本地黑名单 TTL（生存时间）自动解封机制。
//  - 支持本地 block 与云端下发 block 的 TTL 独立管理
//  - 云端 TTL 超过本地上限自动截断（Phase 2 再接入云端真实校验）
//  - 后台定期清理过期条目并调用回调删除 ipset
//  - 支持 JSON 快照导出/导入，供重启后恢复
package ttl

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Source 黑名单来源。
type Source int

const (
	SourceLocal Source = iota // 本地 detector/CLI 触发
	SourceCloud               // 云端下发
)

// Entry 单条 TTL 记录。
type Entry struct {
	IP        string `json:"ip"`
	Source    Source `json:"source"`
	ExpiresAt int64  `json:"expires_at"` // Unix 秒
	CreatedAt int64  `json:"created_at"`
	TTL       int    `json:"ttl"` // 原始 TTL（秒），仅用于审计
}

// Config TTL 管理器配置（镜像 agent/internal/config 中相关字段）。
// 本地 TTL 默认 1h，云端 TTL 上限 1 天。
type Config struct {
	LocalBlockTTL int // 秒，本地 block 默认 TTL（spec 要求 3600）
	CloudBlockTTL int // 秒，允许的云端 block TTL 上限
	CloudMaxTTL   int // 秒，云端下发等级最大 TTL（phase 2 预留）
	SweepInterval int // 秒，后台清理周期；0 表示不启用后台清理
}

// DefaultConfig 返回默认配置。
func DefaultConfig() Config {
	return Config{
		LocalBlockTTL: 3600,
		CloudBlockTTL: 7200,
		CloudMaxTTL:   86400,
		SweepInterval: 30,
	}
}

// ExpireCallback 过期回调。通常由上层调用 ipset del。
type ExpireCallback func(entries []Entry)

// Manager 管理所有带 TTL 的黑名单条目。
// 线程安全。
type Manager struct {
	cfg Config

	mu      sync.RWMutex
	entries map[string]*Entry
	stop    chan struct{}
	once    sync.Once

	onExpire ExpireCallback
}

// NewManager 创建 TTL 管理器。onExpire 可为 nil。
func NewManager(cfg Config, onExpire ExpireCallback) *Manager {
	if cfg.LocalBlockTTL <= 0 {
		cfg.LocalBlockTTL = 3600
	}
	if cfg.CloudBlockTTL <= 0 {
		cfg.CloudBlockTTL = 7200
	}
	if cfg.SweepInterval < 0 {
		cfg.SweepInterval = 30
	}
	m := &Manager{
		cfg:      cfg,
		entries:  make(map[string]*Entry),
		onExpire: onExpire,
		stop:     make(chan struct{}),
	}
	if cfg.SweepInterval > 0 {
		go m.sweepLoop(time.Duration(cfg.SweepInterval) * time.Second)
	}
	return m
}

// Close 停止后台清理 goroutine。重复调用安全。
func (m *Manager) Close() {
	m.once.Do(func() { close(m.stop) })
}

// sweepLoop 周期清理过期条目。
func (m *Manager) sweepLoop(interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-t.C:
			m.Sweep()
		}
	}
}

// Sweep 立即扫描一次，清理过期条目并触发回调。
func (m *Manager) Sweep() {
	now := time.Now().Unix()
	var expired []Entry
	m.mu.Lock()
	for ip, e := range m.entries {
		if e.ExpiresAt <= now {
			expired = append(expired, *e)
			delete(m.entries, ip)
		}
	}
	m.mu.Unlock()
	if len(expired) > 0 && m.onExpire != nil {
		m.onExpire(expired)
	}
}

// Add 添加或刷新一个黑名单 TTL 条目。
// - source 为 Local 时，ttl<=0 会按 LocalBlockTTL 填充
// - source 为 Cloud 时，ttl 会被截断到 CloudBlockTTL
// 返回实际生效的 TTL（秒）。
func (m *Manager) Add(ip string, ttl int, source Source) (int, error) {
	if ip == "" {
		return 0, fmt.Errorf("empty ip")
	}
	effective := m.adjustTTL(ttl, source)
	now := time.Now()
	e := &Entry{
		IP:        ip,
		Source:    source,
		ExpiresAt: now.Unix() + int64(effective),
		CreatedAt: now.Unix(),
		TTL:       effective,
	}
	m.mu.Lock()
	m.entries[ip] = e
	m.mu.Unlock()
	return effective, nil
}

// CloudTTLSeconds 返回云端封锁的 TTL 配置（秒）。
// 供 SyncEngine.applyDecisions 给 ipset add 设置 --timeout，
// 实现云端封锁的 kernel timeout 与 TTL Sweep 双通道冗余
// （进程崩溃导致 TTL 快照丢失时，内核 timeout 仍能自动解封）。
func (m *Manager) CloudTTLSeconds() int {
	return m.cfg.CloudBlockTTL
}

// Remove 主动解除某个 IP 的 TTL（CLI 解封等场景）。
// 返回被删除的条目（供上层联动 ipset del）；不存在返回 nil。
func (m *Manager) Remove(ip string) *Entry {
	if ip == "" {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.entries[ip]; ok {
		delete(m.entries, ip)
		cp := *e
		return &cp
	}
	return nil
}

// Get 查询 IP 的 TTL 条目；不存在返回 nil。
func (m *Manager) Get(ip string) *Entry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if e, ok := m.entries[ip]; ok {
		cp := *e
		return &cp
	}
	return nil
}

// Count 返回当前条目数。
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.entries)
}

// Snapshot 导出当前全部条目（用于持久化到本地快照）。
func (m *Manager) Snapshot() ([]Entry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Entry, 0, len(m.entries))
	for _, e := range m.entries {
		out = append(out, *e)
	}
	return out, nil
}

// MarshalSnapshot 将快照序列化为 JSON。
func (m *Manager) MarshalSnapshot() ([]byte, error) {
	snap, err := m.Snapshot()
	if err != nil {
		return nil, err
	}
	return json.Marshal(snap)
}

// Restore 从快照恢复条目。已存在的条目会被覆盖（按快照时间）。
// 过期的条目直接丢弃，不进入恢复。
// 返回成功恢复的条数。
func (m *Manager) Restore(snap []Entry) (int, error) {
	now := time.Now().Unix()
	var restored int
	m.mu.Lock()
	for _, e := range snap {
		if e.IP == "" {
			continue
		}
		if e.ExpiresAt <= now {
			continue
		}
		e2 := e
		m.entries[e.IP] = &e2
		restored++
	}
	m.mu.Unlock()
	return restored, nil
}

// UnmarshalSnapshot 反序列化并恢复。
func (m *Manager) UnmarshalSnapshot(data []byte) (int, error) {
	var snap []Entry
	if err := json.Unmarshal(data, &snap); err != nil {
		return 0, err
	}
	return m.Restore(snap)
}

// adjustTTL 根据来源与配置调整 TTL。
//   - Local: ttl<=0 回退到 cfg.LocalBlockTTL
//   - Cloud: ttl 截断到 cfg.CloudBlockTTL；CloudMaxTTL 预留（Phase 2 启用）
func (m *Manager) adjustTTL(ttl int, source Source) int {
	switch source {
	case SourceCloud:
		if ttl <= 0 {
			ttl = m.cfg.CloudBlockTTL
		}
		if m.cfg.CloudBlockTTL > 0 && ttl > m.cfg.CloudBlockTTL {
			ttl = m.cfg.CloudBlockTTL
		}
		return ttl
	default: // Local
		if ttl <= 0 {
			ttl = m.cfg.LocalBlockTTL
		}
		return ttl
	}
}
