// Package snapshot 实现 Agent 本地状态的持久化快照与恢复。
//  - 定期将 ipset/TTL 状态落盘到 JSON 文件
//  - 启动时从快照恢复
//  - 心跳失败状态机接口预留（Phase 2 任务16 启用联网恢复）
package snapshot

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// IPSetSnapshot ipset 状态快照结构（镜像 ipsetutil 内部结构）。
type IPSetSnapshot struct {
	Blacklist []string `json:"blacklist"`
	Whitelist []string `json:"whitelist"`
}

// TTLSnapshot TTL 状态快照结构（镜像 ttl 内部结构）。
type TTLSnapshot struct {
	Entries []TTLEntry `json:"entries"`
}

// TTLEntry 镜像 ttl.Entry。
type TTLEntry struct {
	IP        string `json:"ip"`
	Source    int    `json:"source"`
	ExpiresAt int64  `json:"expires_at"`
	CreatedAt int64  `json:"created_at"`
	TTL       int    `json:"ttl"`
}

// FullSnapshot 完整快照。
type FullSnapshot struct {
	Version     string       `json:"version"`
	Timestamp   int64        `json:"timestamp"`
	IPSet       IPSetSnapshot `json:"ipset"`
	TTL         TTLSnapshot  `json:"ttl"`
}

// IPSetProvider 由 ipsetutil.Manager 实现。
type IPSetProvider interface {
	Snapshot() (IPSetSnapshot, error)
	RestoreIPSet(snap IPSetSnapshot) error
}

// TTLProvider 由 ttl.Manager 实现。
type TTLProvider interface {
	SnapshotTTL() (TTLSnapshot, error)
	RestoreTTL(snap TTLSnapshot) (int, error)
}

// HeartbeatState 心跳状态机（Phase 2 任务16 之前仅占位）。
type HeartbeatState int

const (
	HeartbeatUnknown    HeartbeatState = iota
	HeartbeatOK
	HeartbeatOffline
	HeartbeatRecovering
)

// StateProvider 心跳状态查询接口。
type StateProvider interface {
	HeartbeatState() HeartbeatState
}

// Config 快照管理器配置。
type Config struct {
	FilePath      string        // 快照文件路径
	Interval      time.Duration // 落盘周期；0 表示不自动落盘
	WriteAtomic   bool          // 是否原子写入（推荐 true，写临时文件后 rename）
	OnRestoreFail func(error)   // 恢复失败的回调（日志/告警）
}

// DefaultConfig 返回默认配置（/var/lib/wardennet/state.json，60s 落盘）。
func DefaultConfig() Config {
	return Config{
		FilePath:    "/var/lib/wardennet/state.json",
		Interval:    60 * time.Second,
		WriteAtomic: true,
	}
}

// Manager 快照管理器。协调 IPSetProvider + TTLProvider 的定期保存与恢复。
type Manager struct {
	cfg Config
	ip  IPSetProvider
	ttl TTLProvider
	st  StateProvider

	mu    sync.Mutex
	stop  chan struct{}
	once  sync.Once
}

// NewManager 创建快照管理器。
// ip/ttl 可为 nil（单机模式下按需启用）。st 为 nil 时默认返回 HeartbeatOK。
func NewManager(cfg Config, ip IPSetProvider, ttl TTLProvider, st StateProvider) *Manager {
	if cfg.FilePath == "" {
		cfg.FilePath = "/var/lib/wardennet/state.json"
	}
	if cfg.Interval < 0 {
		cfg.Interval = 60 * time.Second
	}
	if st == nil {
		st = dummyState{}
	}
	return &Manager{
		cfg: cfg,
		ip:  ip,
		ttl: ttl,
		st:  st,
		stop: make(chan struct{}),
	}
}

// Start 启动后台自动落盘。
func (m *Manager) Start() {
	if m.cfg.Interval > 0 {
		go m.autoSaveLoop()
	}
}

// Stop 停止后台落盘，同时执行一次最终保存（尽力而为）。
func (m *Manager) Stop() {
	m.once.Do(func() {
		close(m.stop)
		_ = m.Save() // 关闭前再保存一次
	})
}

// Save 主动保存一次快照（同步）。
func (m *Manager) Save() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	snap := FullSnapshot{
		Version:   "1",
		Timestamp: time.Now().Unix(),
	}
	if m.ip != nil {
		s, err := m.ip.Snapshot()
		if err != nil {
			return fmt.Errorf("ipset snapshot: %w", err)
		}
		snap.IPSet = s
	}
	if m.ttl != nil {
		s, err := m.ttl.SnapshotTTL()
		if err != nil {
			return fmt.Errorf("ttl snapshot: %w", err)
		}
		snap.TTL = s
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}
	return m.writeFile(data)
}

// LoadAndRestore 从文件读取快照并恢复到 ipset/ttl。
// 文件不存在返回 nil（首次启动）；损坏返回 error 并触发 OnRestoreFail。
func (m *Manager) LoadAndRestore() (*FullSnapshot, error) {
	data, err := os.ReadFile(m.cfg.FilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // 首次启动，无快照
		}
		return nil, fmt.Errorf("read snapshot: %w", err)
	}
	var snap FullSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		if m.cfg.OnRestoreFail != nil {
			m.cfg.OnRestoreFail(err)
		}
		return nil, fmt.Errorf("unmarshal snapshot: %w", err)
	}
	// 心跳状态决定恢复策略（Phase 2 再细化）
	_ = m.st.HeartbeatState()

	if m.ip != nil {
		if err := m.ip.RestoreIPSet(snap.IPSet); err != nil {
			if m.cfg.OnRestoreFail != nil {
				m.cfg.OnRestoreFail(err)
			}
			return nil, fmt.Errorf("restore ipset: %w", err)
		}
	}
	if m.ttl != nil {
		if _, err := m.ttl.RestoreTTL(snap.TTL); err != nil {
			if m.cfg.OnRestoreFail != nil {
				m.cfg.OnRestoreFail(err)
			}
			return nil, fmt.Errorf("restore ttl: %w", err)
		}
	}
	return &snap, nil
}

// writeFile 写入文件。原子模式先写临时文件再 rename。
func (m *Manager) writeFile(data []byte) error {
	dir := filepath.Dir(m.cfg.FilePath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir snapshot dir: %w", err)
	}
	if !m.cfg.WriteAtomic {
		return os.WriteFile(m.cfg.FilePath, data, 0o600)
	}
	tmp := m.cfg.FilePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, m.cfg.FilePath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// autoSaveLoop 周期落盘。
func (m *Manager) autoSaveLoop() {
	t := time.NewTicker(m.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-t.C:
			_ = m.Save() // 忽略错误，交给监控日志
		}
	}
}

// dummyState 默认心跳状态实现。
type dummyState struct{}

func (dummyState) HeartbeatState() HeartbeatState { return HeartbeatOK }
