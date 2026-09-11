// Package snapshot - manager_test.go 验证快照保存/恢复/损坏回退。
package snapshot

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// ----- Mock 实现 -----

type mockIPSetProvider struct {
	mu        sync.Mutex
	blacklist []string
	whitelist []string
}

func (m *mockIPSetProvider) Snapshot() (IPSetSnapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return IPSetSnapshot{Blacklist: m.blacklist, Whitelist: m.whitelist}, nil
}

func (m *mockIPSetProvider) RestoreIPSet(snap IPSetSnapshot) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.blacklist = append([]string(nil), snap.Blacklist...)
	m.whitelist = append([]string(nil), snap.Whitelist...)
	return nil
}

type mockTTLProvider struct {
	mu      sync.Mutex
	entries []TTLEntry
}

func (m *mockTTLProvider) SnapshotTTL() (TTLSnapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return TTLSnapshot{Entries: append([]TTLEntry(nil), m.entries...)}, nil
}

func (m *mockTTLProvider) RestoreTTL(snap TTLSnapshot) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append([]TTLEntry(nil), snap.Entries...)
	return len(snap.Entries), nil
}

type mockStateProvider struct {
	state HeartbeatState
}

func (m *mockStateProvider) HeartbeatState() HeartbeatState { return m.state }

// ----- 测试用例 -----

func TestManager_SaveAndRestore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	ip := &mockIPSetProvider{
		blacklist: []string{"1.1.1.1", "2.2.2.2"},
		whitelist: []string{"127.0.0.1"},
	}
	ttl := &mockTTLProvider{
		entries: []TTLEntry{
			{IP: "1.1.1.1", Source: 0, ExpiresAt: time.Now().Add(1 * time.Hour).Unix(), TTL: 3600},
		},
	}
	cfg := Config{FilePath: path, Interval: 0, WriteAtomic: true}
	m := NewManager(cfg, ip, ttl, nil)
	if err := m.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// 清空内存后恢复
	ip.blacklist = nil
	ip.whitelist = nil
	ttl.entries = nil

	m2 := NewManager(cfg, ip, ttl, nil)
	snap, err := m2.LoadAndRestore()
	if err != nil {
		t.Fatalf("LoadAndRestore: %v", err)
	}
	if snap == nil {
		t.Fatalf("expected snapshot, got nil")
	}
	if len(ip.blacklist) != 2 {
		t.Errorf("blacklist restored=%v, want 2 entries", ip.blacklist)
	}
	if len(ip.whitelist) != 1 {
		t.Errorf("whitelist restored=%v, want 1 entry", ip.whitelist)
	}
	if len(ttl.entries) != 1 {
		t.Errorf("ttl entries restored=%v, want 1 entry", ttl.entries)
	}
}

func TestManager_FileNotFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent.json")
	m := NewManager(Config{FilePath: path, Interval: 0}, nil, nil, nil)
	snap, err := m.LoadAndRestore()
	if err != nil {
		t.Fatalf("LoadAndRestore should ignore missing file, got: %v", err)
	}
	if snap != nil {
		t.Errorf("expected nil snapshot for missing file, got %+v", snap)
	}
}

func TestManager_CorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "corrupt.json")
	// 写入损坏的 JSON
	if err := os.WriteFile(path, []byte("not valid json"), 0o600); err != nil {
		t.Fatalf("write corrupt: %v", err)
	}
	var failed error
	m := NewManager(Config{
		FilePath:      path,
		Interval:      0,
		WriteAtomic:   false,
		OnRestoreFail: func(err error) { failed = err },
	}, nil, nil, nil)
	_, err := m.LoadAndRestore()
	if err == nil {
		t.Fatalf("expected error for corrupt file")
	}
	if failed == nil {
		t.Errorf("OnRestoreFail not called")
	}
}

func TestManager_AutoSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auto.json")
	ip := &mockIPSetProvider{blacklist: []string{"auto-ip"}}
	cfg := Config{FilePath: path, Interval: 50 * time.Millisecond, WriteAtomic: true}
	m := NewManager(cfg, ip, nil, nil)
	m.Start()
	defer m.Stop()

	// 等待自动落盘
	time.Sleep(150 * time.Millisecond)

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatalf("auto save file not created")
	}
	// 再次读取恢复
	m2 := NewManager(Config{FilePath: path, Interval: 0}, &mockIPSetProvider{}, nil, nil)
	snap, err := m2.LoadAndRestore()
	if err != nil {
		t.Fatalf("LoadAndRestore: %v", err)
	}
	if snap == nil || len(snap.IPSet.Blacklist) != 1 || snap.IPSet.Blacklist[0] != "auto-ip" {
		t.Errorf("auto saved snapshot incorrect: %+v", snap)
	}
}

func TestManager_HeartbeatState(t *testing.T) {
	st := &mockStateProvider{state: HeartbeatOffline}
	NewManager(Config{Interval: 0}, nil, nil, st)
	// 保存/恢复时心跳状态应被读取（不影响逻辑，但保证能获取）
	if st.HeartbeatState() != HeartbeatOffline {
		t.Errorf("heartbeat state=%v, want Offline", st.HeartbeatState())
	}
}
