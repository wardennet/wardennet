// Package cli - handler_test.go 表驱动测试：blocklist/status/reload 命令行为。
package cli

import (
	"errors"
	"testing"
)

// ----- Mock 实现 -----

type mockIPSetManager struct {
	blocked    map[string]bool
	whitelist  map[string]bool
	blockErr   error
	unblockErr error
}

func (m *mockIPSetManager) Block(ip string) (bool, error) {
	if m.blockErr != nil {
		return false, m.blockErr
	}
	if m.blocked[ip] {
		return false, errors.New("already blocked")
	}
	m.blocked[ip] = true
	return true, nil
}
func (m *mockIPSetManager) ForceBlock(ip string) (bool, error) {
	if m.blockErr != nil {
		return false, m.blockErr
	}
	if m.blocked[ip] {
		return false, errors.New("already blocked")
	}
	m.blocked[ip] = true
	return true, nil
}
func (m *mockIPSetManager) Unblock(ip string) error {
	if m.unblockErr != nil {
		return m.unblockErr
	}
	if !m.blocked[ip] {
		return errors.New("ip not blocked")
	}
	delete(m.blocked, ip)
	return nil
}
func (m *mockIPSetManager) IsLocalWhitelisted(ip string) bool { return m.whitelist[ip] }
func (m *mockIPSetManager) LocalBlockedCount() int            { return len(m.blocked) }
func (m *mockIPSetManager) LocalWhitelistCount() int          { return len(m.whitelist) }
func (m *mockIPSetManager) ApplyCloud(entries []CloudEntry) ([]CloudEntry, error) {
	return nil, nil
}
func (m *mockIPSetManager) SyncLocalWhitelist(items []string) error { return nil }

type mockTTLManager struct {
	removed []string
	ttl     map[string]int
}

func (m *mockTTLManager) Add(ip string, ttl int, source int) (int, error) {
	if m.ttl == nil {
		m.ttl = make(map[string]int)
	}
	if ttl <= 0 {
		ttl = 3600
	}
	m.ttl[ip] = ttl
	return ttl, nil
}
func (m *mockTTLManager) Remove(ip string) *TTLEntry {
	m.removed = append(m.removed, ip)
	return &TTLEntry{IP: ip}
}
func (m *mockTTLManager) Count() int { return len(m.ttl) }

type mockStatusInfo struct {
	data map[string]interface{}
}

func (m *mockStatusInfo) GetStatus() map[string]interface{} { return m.data }

type mockReloader struct {
	err error
}

func (m *mockReloader) Reload() error { return m.err }

// ----- 测试用例 -----

func TestBlocklistHandler_Add(t *testing.T) {
	ipm := &mockIPSetManager{blocked: make(map[string]bool), whitelist: make(map[string]bool)}
	ttm := &mockTTLManager{}
	h := NewBlocklistHandler(ipm, ttm, nil)

	req := Request{Command: CmdBlockListAdd, Args: map[string]interface{}{"ip": "8.8.8.8"}}
	resp := h.blocklistAdd(req)
	if !resp.Ok {
		t.Fatalf("resp not ok: %v", resp)
	}
	data := resp.Data.(map[string]interface{})
	if got, _ := data["accepted"].(bool); !got {
		t.Errorf("accepted=%v, want true", data["accepted"])
	}
	if !ipm.blocked["8.8.8.8"] {
		t.Errorf("ip not actually blocked")
	}
}

func TestBlocklistHandler_WhitelistSkip(t *testing.T) {
	ipm := &mockIPSetManager{blocked: make(map[string]bool), whitelist: map[string]bool{"127.0.0.1": true}}
	ttm := &mockTTLManager{}
	h := NewBlocklistHandler(ipm, ttm, nil)

	req := Request{Command: CmdBlockListAdd, Args: map[string]interface{}{"ip": "127.0.0.1"}}
	resp := h.blocklistAdd(req)
	if resp.Ok {
		t.Errorf("expected not ok for whitelist skip, got %+v", resp)
	}
	data := resp.Data.(map[string]interface{})
	if reason, _ := data["reason"].(string); reason != "local_whitelist_skip" {
		t.Errorf("reason=%q, want local_whitelist_skip", reason)
	}
	if ipm.blocked["127.0.0.1"] {
		t.Errorf("whitelist ip should not be blocked")
	}
	if len(ttm.ttl) != 0 {
		t.Errorf("ttl should not be added for whitelisted ip")
	}
}

func TestBlocklistHandler_AddWithTTL(t *testing.T) {
	ipm := &mockIPSetManager{blocked: make(map[string]bool), whitelist: make(map[string]bool)}
	ttm := &mockTTLManager{}
	h := NewBlocklistHandler(ipm, ttm, nil)

	req := Request{Command: CmdBlockListAdd, Args: map[string]interface{}{"ip": "10.0.0.1", "ttl": 120}}
	resp := h.blocklistAdd(req)
	if !resp.Ok {
		t.Fatalf("not ok: %v", resp)
	}
	if ttm.ttl["10.0.0.1"] != 120 {
		t.Errorf("ttl stored=%d, want 120", ttm.ttl["10.0.0.1"])
	}
}

func TestBlocklistHandler_AddInvalidIP(t *testing.T) {
	ipm := &mockIPSetManager{blocked: make(map[string]bool)}
	h := NewBlocklistHandler(ipm, nil, nil)
	req := Request{Command: CmdBlockListAdd, Args: map[string]interface{}{"ip": "bad-ip"}}
	resp := h.blocklistAdd(req)
	if resp.Ok {
		t.Errorf("expected error for invalid ip")
	}
}

func TestBlocklistHandler_Del(t *testing.T) {
	ipm := &mockIPSetManager{blocked: map[string]bool{"10.0.0.1": true}}
	ttm := &mockTTLManager{}
	h := NewBlocklistHandler(ipm, ttm, nil)

	req := Request{Command: CmdBlockListDel, Args: map[string]interface{}{"ip": "10.0.0.1"}}
	resp := h.blocklistDel(req)
	if !resp.Ok {
		t.Fatalf("not ok: %v", resp)
	}
	if len(ipm.blocked) != 0 {
		t.Errorf("blocked count=%d, want 0", len(ipm.blocked))
	}
	if len(ttm.removed) != 1 || ttm.removed[0] != "10.0.0.1" {
		t.Errorf("ttl removed=%v, want [10.0.0.1]", ttm.removed)
	}
}

func TestBlocklistHandler_DelNotBlocked(t *testing.T) {
	ipm := &mockIPSetManager{blocked: make(map[string]bool)}
	h := NewBlocklistHandler(ipm, nil, nil)
	req := Request{Command: CmdBlockListDel, Args: map[string]interface{}{"ip": "9.9.9.9"}}
	resp := h.blocklistDel(req)
	if resp.Ok {
		t.Errorf("expected error for del non-blocked ip")
	}
}

func TestBlocklistHandler_Status(t *testing.T) {
	ipm := &mockIPSetManager{blocked: map[string]bool{"1": true, "2": true}}
	ttm := &mockTTLManager{ttl: map[string]int{"1": 3600}}
	si := &mockStatusInfo{data: map[string]interface{}{"mode": "agent"}}
	h := NewBlocklistHandler(ipm, ttm, si)

	req := Request{Command: CmdBlockListStatus}
	resp := h.blocklistStatus(req)
	if !resp.Ok {
		t.Fatalf("not ok: %v", resp)
	}
	data := resp.Data.(map[string]interface{})
	if data["blocked_count"] != 2 {
		t.Errorf("blocked_count=%v, want 2", data["blocked_count"])
	}
	if data["mode"] != "agent" {
		t.Errorf("status info not merged: %v", data)
	}
}

func TestStatusHandler(t *testing.T) {
	si := &mockStatusInfo{data: map[string]interface{}{"mem": "128MB"}}
	h := NewStatusHandler(si, "v0.1.0")
	reg := NewRegistry()
	h.Register(reg)

	resp := reg.Dispatch(Request{Command: CmdStatus})
	if !resp.Ok {
		t.Fatalf("not ok: %v", resp)
	}
	data := resp.Data.(map[string]interface{})
	if data["version"] != "v0.1.0" {
		t.Errorf("version=%v, want v0.1.0", data["version"])
	}
	if data["mem"] != "128MB" {
		t.Errorf("status data not present: %v", data)
	}
}

func TestReloadHandler(t *testing.T) {
	// 成功
	r := NewReloadHandler(&mockReloader{})
	reg := NewRegistry()
	r.Register(reg)
	resp := reg.Dispatch(Request{Command: CmdReload})
	if !resp.Ok {
		t.Errorf("expected ok, got %v", resp)
	}

	// 失败
	r2 := NewReloadHandler(&mockReloader{err: errors.New("config syntax error")})
	reg2 := NewRegistry()
	r2.Register(reg2)
	resp2 := reg2.Dispatch(Request{Command: CmdReload})
	if resp2.Ok {
		t.Errorf("expected error, got %v", resp2)
	}
}

func TestRegistry_UnknownCommand(t *testing.T) {
	reg := NewRegistry()
	resp := reg.Dispatch(Request{Command: "no-such-cmd"})
	if resp.Ok || resp.Error == "" {
		t.Errorf("expected error for unknown command")
	}
}
