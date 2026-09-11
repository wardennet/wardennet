// Package ttl - manager_test.go 表驱动测试：过期清理、TTL 截断、快照恢复。
package ttl

import (
	"sync"
	"testing"
	"time"
)

// TestManager_AddAndGet 验证基础 Add/Get 功能。
func TestManager_AddAndGet(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SweepInterval = 0 // 禁用后台，手动 Sweep
	m := NewManager(cfg, nil)
	defer m.Close()

	ttl, err := m.Add("1.1.1.1", 0, SourceLocal)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if ttl != cfg.LocalBlockTTL {
		t.Errorf("default local ttl=%d, want %d", ttl, cfg.LocalBlockTTL)
	}
	e := m.Get("1.1.1.1")
	if e == nil {
		t.Fatalf("entry not found")
	}
	if e.Source != SourceLocal {
		t.Errorf("source=%v, want Local", e.Source)
	}
	if m.Count() != 1 {
		t.Errorf("count=%d, want 1", m.Count())
	}
}

// TestManager_CloudTTLTruncation 云端 TTL 超过上限被截断。
func TestManager_CloudTTLTruncation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SweepInterval = 0
	m := NewManager(cfg, nil)
	defer m.Close()

	// 超上限
	ttl, err := m.Add("8.8.8.8", 10000, SourceCloud)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if ttl != cfg.CloudBlockTTL {
		t.Errorf("cloud ttl=%d, want truncated %d", ttl, cfg.CloudBlockTTL)
	}

	// 低于上限不截断
	ttl2, err := m.Add("8.8.4.4", 100, SourceCloud)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if ttl2 != 100 {
		t.Errorf("cloud ttl=%d, want 100", ttl2)
	}
}

// TestManager_SweepExpire 过期删除：添加已过期的条目，Sweep 应触发回调。
func TestManager_SweepExpire(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SweepInterval = 0

	var mu sync.Mutex
	var expired []Entry
	cb := func(es []Entry) {
		mu.Lock()
		defer mu.Unlock()
		expired = append(expired, es...)
	}
	m := NewManager(cfg, cb)
	defer m.Close()

	// 直接构造一个已过期的 Entry 写入
	m.mu.Lock()
	m.entries["10.0.0.1"] = &Entry{
		IP:        "10.0.0.1",
		Source:    SourceLocal,
		ExpiresAt: time.Now().Unix() - 10,
		CreatedAt: time.Now().Unix() - 3600,
		TTL:       3600,
	}
	m.entries["10.0.0.2"] = &Entry{
		IP:        "10.0.0.2",
		Source:    SourceCloud,
		ExpiresAt: time.Now().Unix() - 1,
		CreatedAt: time.Now().Unix() - 7200,
		TTL:       7200,
	}
	// 一个未过期的条目
	m.entries["10.0.0.3"] = &Entry{
		IP:        "10.0.0.3",
		Source:    SourceLocal,
		ExpiresAt: time.Now().Unix() + 3600,
		CreatedAt: time.Now().Unix(),
		TTL:       3600,
	}
	m.mu.Unlock()

	m.Sweep()

	mu.Lock()
	got := expired
	mu.Unlock()

	if len(got) != 2 {
		t.Fatalf("expired count=%d, want 2", len(got))
	}
	ips := make(map[string]bool)
	for _, e := range got {
		ips[e.IP] = true
	}
	if !ips["10.0.0.1"] || !ips["10.0.0.2"] {
		t.Errorf("expired ips=%v, want 10.0.0.1 & 10.0.0.2", ips)
	}
	if m.Count() != 1 {
		t.Errorf("count after sweep=%d, want 1 (only 10.0.0.3)", m.Count())
	}
	if m.Get("10.0.0.3") == nil {
		t.Errorf("10.0.0.3 should still be present")
	}
}

// TestManager_SnapshotRestore 验证 JSON 快照恢复。
func TestManager_SnapshotRestore(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SweepInterval = 0
	m1 := NewManager(cfg, nil)
	defer m1.Close()

	m1.Add("1.1.1.1", 3600, SourceLocal)
	m1.Add("2.2.2.2", 7200, SourceCloud)
	// 第三个条目已过期，不应该被恢复
	m1.mu.Lock()
	m1.entries["3.3.3.3"] = &Entry{
		IP:        "3.3.3.3",
		Source:    SourceLocal,
		ExpiresAt: time.Now().Unix() - 100,
		CreatedAt: time.Now().Unix() - 999,
		TTL:       100,
	}
	m1.mu.Unlock()

	data, err := m1.MarshalSnapshot()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	// 新 Manager 从快照恢复
	m2 := NewManager(cfg, nil)
	defer m2.Close()
	n, err := m2.UnmarshalSnapshot(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if n != 2 {
		t.Errorf("restored=%d, want 2 (3.3.3.3 已过期)", n)
	}
	if m2.Count() != 2 {
		t.Errorf("count after restore=%d, want 2", m2.Count())
	}
	if m2.Get("1.1.1.1") == nil || m2.Get("2.2.2.2") == nil {
		t.Errorf("missing restored entries")
	}
	if m2.Get("3.3.3.3") != nil {
		t.Errorf("expired entry should not be restored")
	}
}

// TestManager_Remove 主动移除条目。
func TestManager_Remove(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SweepInterval = 0
	m := NewManager(cfg, nil)
	defer m.Close()

	m.Add("5.5.5.5", 3600, SourceLocal)
	if e := m.Remove("5.5.5.5"); e == nil {
		t.Errorf("Remove returned nil, want entry")
	}
	if m.Count() != 0 {
		t.Errorf("count=%d, want 0", m.Count())
	}
	if e := m.Remove("6.6.6.6"); e != nil {
		t.Errorf("Remove nonexistent: %v", e)
	}
}

// TestManager_BackgroundSweep 验证后台清理线程按周期工作。
func TestManager_BackgroundSweep(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SweepInterval = 1 // 1 秒，加速测试

	var mu sync.Mutex
	var expired []Entry
	cb := func(es []Entry) {
		mu.Lock()
		defer mu.Unlock()
		expired = append(expired, es...)
	}
	m := NewManager(cfg, cb)

	// 添加一个已过期条目
	m.mu.Lock()
	m.entries["expired"] = &Entry{
		IP:        "expired",
		Source:    SourceLocal,
		ExpiresAt: time.Now().Unix() - 5,
		CreatedAt: time.Now().Unix() - 100,
		TTL:       100,
	}
	m.mu.Unlock()

	// 等待后台清理
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(expired)
		mu.Unlock()
		if n >= 1 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	mu.Lock()
	got := expired
	mu.Unlock()

	if len(got) < 1 {
		t.Fatalf("background sweep did not run; expired len=%d", len(got))
	}
	if got[0].IP != "expired" {
		t.Errorf("expired ip=%q, want 'expired'", got[0].IP)
	}

	m.Close()
}
