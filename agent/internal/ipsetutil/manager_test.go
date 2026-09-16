// Package ipsetutil - manager_test.go 单元测试：本地白名单豁免、增量操作、降级重试。
package ipsetutil

import (
	"errors"
	"testing"
	"time"
)

// newTestManager 创建带内存 Mock 的 Manager 实例，便于测试。
func newTestManager() (*Manager, *MemClient) {
	mem := NewMemClient()
	m := NewManager(mem, 2, 10*time.Millisecond)
	return m, mem
}

// TestManager_WhitelistSkip 本地白名单绝对优先：命中白名单时 Block 返回 ErrWhitelisted。
func TestManager_WhitelistSkip(t *testing.T) {
	m, _ := newTestManager()
	defer m.Close()

	err := m.SyncLocalWhitelist([]string{"127.0.0.1", "10.0.0.0/8"})
	if err != nil {
		t.Fatalf("SyncLocalWhitelist: %v", err)
	}

	// 精确 IP
	accepted, err := m.Block("127.0.0.1")
	if accepted || !errors.Is(err, ErrWhitelisted) {
		t.Errorf("block 127.0.0.1: accepted=%v err=%v, want ErrWhitelisted", accepted, err)
	}

	// CIDR 命中
	accepted, err = m.Block("10.1.2.3")
	if accepted || !errors.Is(err, ErrWhitelisted) {
		t.Errorf("block 10.1.2.3: accepted=%v err=%v, want ErrWhitelisted", accepted, err)
	}

	// 白名单不应进入本地黑名单跟踪
	if m.LocalBlockedCount() != 0 {
		t.Errorf("LocalBlockedCount=%d, want 0", m.LocalBlockedCount())
	}
}

// TestManager_BlockAndUnblock 验证增量 add/del 正确工作。
func TestManager_BlockAndUnblock(t *testing.T) {
	m, _ := newTestManager()
	defer m.Close()

	accepted, err := m.Block("203.0.113.5")
	if err != nil {
		t.Fatalf("block first: %v", err)
	}
	if !accepted {
		t.Errorf("accepted=%v, want true", accepted)
	}

	// 幂等：重复 block 不报错
	accepted, err = m.Block("203.0.113.5")
	if !errors.Is(err, ErrAlreadyBlocked) {
		t.Errorf("second block err=%v, want ErrAlreadyBlocked", err)
	}
	if accepted {
		t.Errorf("accepted=%v, want false for already blocked", accepted)
	}

	// unblock
	if err := m.Unblock("203.0.113.5"); err != nil {
		t.Errorf("unblock: %v", err)
	}
	if err := m.Unblock("203.0.113.5"); !errors.Is(err, ErrNotBlocked) {
		t.Errorf("second unblock err=%v, want ErrNotBlocked", err)
	}
}

// TestManager_InvalidIP 非法 IP 格式被拒绝。
func TestManager_InvalidIP(t *testing.T) {
	m, _ := newTestManager()
	defer m.Close()

	if _, err := m.Block("not-an-ip"); !errors.Is(err, ErrInvalidIP) {
		t.Errorf("block invalid: %v, want ErrInvalidIP", err)
	}
	if err := m.Unblock("bad"); !errors.Is(err, ErrInvalidIP) {
		t.Errorf("unblock invalid: %v, want ErrInvalidIP", err)
	}
}

// TestManager_RetryOnFailure 底层失败时 Manager 重试，重试耗尽后返回 error。
func TestManager_RetryOnFailure(t *testing.T) {
	m, mem := newTestManager()
	defer m.Close()

	// 初始成功
	if _, err := m.Block("1.1.1.1"); err != nil {
		t.Fatalf("first block: %v", err)
	}

	// 开启故障模式
	mem.SetFlaky(true)
	_, err := m.Block("2.2.2.2")
	if err == nil {
		t.Fatalf("expected error after retry exhausted")
	}
	t.Logf("got expected error: %v", err)

	// 恢复
	mem.SetFlaky(false)
	if _, err := m.Block("2.2.2.2"); err != nil {
		t.Errorf("block after recovery: %v", err)
	}
}

// TestManager_ApplyCloud 云端下发：本地白名单豁免逻辑生效。
func TestManager_ApplyCloud(t *testing.T) {
	m, _ := newTestManager()
	defer m.Close()

	if err := m.SyncLocalWhitelist([]string{"192.168.0.0/16"}); err != nil {
		t.Fatalf("SyncLocalWhitelist: %v", err)
	}

	entries := []Entry{
		{Set: SetBlacklist, IP: "192.168.1.10", Op: OpAdd}, // 被本地豁免
		{Set: SetBlacklist, IP: "8.8.8.8", Op: OpAdd},      // 正常加入
		{Set: SetWhitelist, IP: "9.9.9.9", Op: OpAdd},      // 白名单（不受本地豁免）
	}
	filtered, err := m.ApplyCloud(entries)
	if err != nil {
		t.Fatalf("ApplyCloud: %v", err)
	}
	if len(filtered) != 1 || filtered[0].IP != "192.168.1.10" {
		t.Errorf("filtered=%v, want [192.168.1.10]", filtered)
	}
	if ok, _ := m.client.Exists(SetBlacklist, "192.168.1.10"); ok {
		t.Errorf("192.168.1.10 should NOT be in blacklist (local whitelist)")
	}
	if ok, _ := m.client.Exists(SetBlacklist, "8.8.8.8"); !ok {
		t.Errorf("8.8.8.8 should be in blacklist")
	}
	if ok, _ := m.client.Exists(SetWhitelist, "9.9.9.9"); !ok {
		t.Errorf("9.9.9.9 should be in whitelist")
	}
}

// TestManager_SyncWhitelist 验证白名单全量重建。
// 白名单使用 hash:net 类型，裸 IP 会被规范化为 CIDR 形式（IPv4→/32、IPv6→/128），
// CIDR 保持原样。内存白名单不受影响（仍记录裸 IP，保证 IsLocalWhitelisted 精确匹配正常）。
func TestManager_SyncWhitelist(t *testing.T) {
	m, mem := newTestManager()
	defer m.Close()

	if err := m.SyncLocalWhitelist([]string{"1.1.1.1", "2.2.2.2", "10.0.0.0/24"}); err != nil {
		t.Fatalf("first sync: %v", err)
	}
	if c := m.LocalWhitelistCount(); c != 3 {
		t.Errorf("count after first sync=%d, want 3", c)
	}
	// 裸 IP 已规范化为 CIDR 写入 ipset
	members, err := mem.List(SetWhitelist)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(members) != 3 {
		t.Fatalf("whitelist members=%v, want 3 entries", members)
	}
	want := map[string]bool{
		"1.1.1.1/32":   true,
		"2.2.2.2/32":   true,
		"10.0.0.0/24": true,
	}
	for _, m := range members {
		if !want[m] {
			t.Errorf("unexpected whitelist member: %s", m)
		}
	}

	// 重新同步：应覆盖旧条目
	if err := m.SyncLocalWhitelist([]string{"3.3.3.3"}); err != nil {
		t.Fatalf("second sync: %v", err)
	}
	if c := m.LocalWhitelistCount(); c != 1 {
		t.Errorf("count after second sync=%d, want 1", c)
	}
	members, err = mem.List(SetWhitelist)
	if err != nil {
		t.Fatalf("list after second sync: %v", err)
	}
	if len(members) != 1 || members[0] != "3.3.3.3/32" {
		t.Errorf("whitelist members=%v, want [3.3.3.3/32]", members)
	}
}

// TestManager_SyncWhitelistIPv6 裸 IPv6（如 ::1）必须能被规范化并写入 hash:net 白名单。
// 这是真实环境报错的复现场景：裸 IPv6 在 hash:net 上会被拒，
// 规范化为 /128 后既能写入 ipset，也能通过 IsLocalWhitelisted 正确识别。
// IPv4-mapped IPv6（::ffff:x.x.x.x）在 Go net.ParseIP 中会被折叠成 IPv4 形式，
// 因此 ipset 中存储为 IPv4/32，但内存白名单同时保留原字符串和规范化字符串，
// 保证两种查询形态都能命中。
func TestManager_SyncWhitelistIPv6(t *testing.T) {
	m, mem := newTestManager()
	defer m.Close()

	if err := m.SyncLocalWhitelist([]string{"127.0.0.1", "::1", "::ffff:192.0.2.1"}); err != nil {
		t.Fatalf("ipv6 sync: %v", err)
	}

	// ipset 侧均以 CIDR 形式存储
	// 注意：IPv4-mapped IPv6 会被 net.ParseIP 折叠为 IPv4 形式，因此存为 192.0.2.1/32
	members, err := mem.List(SetWhitelist)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	want := map[string]bool{
		"127.0.0.1/32":  true,
		"::1/128":       true,
		"192.0.2.1/32":  true, // ::ffff:192.0.2.1 被规范化为 IPv4
	}
	for _, member := range members {
		if !want[member] {
			t.Errorf("unexpected member: %s", member)
		}
	}

	// 豁免逻辑：所有形态的查询都必须命中
	testIPs := []string{
		"127.0.0.1",
		"::1",
		"::ffff:192.0.2.1", // 原字符串形态
		"192.0.2.1",        // 规范化后的 IPv4 形态
	}
	for _, ip := range testIPs {
		if !m.IsLocalWhitelisted(ip) {
			t.Errorf("IsLocalWhitelisted(%q) should be true", ip)
		}
		accepted, err := m.Block(ip)
		if accepted || err == nil {
			t.Errorf("Block(%q) should be rejected by whitelist: accepted=%v err=%v", ip, accepted, err)
		}
	}

	// 内存白名单条目数（精确+CIDR 总和）
	if c := m.LocalWhitelistCount(); c < 3 {
		t.Errorf("LocalWhitelistCount=%d, want >=3 (IPv4-mapped IPv6 stores 2 keys)", c)
	}
}

// TestManager_SyncWhitelistMemoryFallback 即使 ipset 写入失败，内存白名单依然生效。
// 这是为了保障"ipset 是内核加速，不是唯一数据源"这一原则。
func TestManager_SyncWhitelistMemoryFallback(t *testing.T) {
	m, mem := newTestManager()
	defer m.Close()

	// 先写入一次，确保初始状态正常
	if err := m.SyncLocalWhitelist([]string{"10.0.0.1"}); err != nil {
		t.Fatalf("init sync: %v", err)
	}

	// 开启 flaky 让 ipset 写入失败
	mem.SetFlaky(true)
	defer mem.SetFlaky(false)

	err := m.SyncLocalWhitelist([]string{"10.0.0.1", "::1"})
	if err == nil {
		t.Fatalf("expected ipset error due to flaky client")
	}
	t.Logf("got expected ipset error: %v", err)

	// 关键：即使 ipset 写入失败，内存白名单也必须生效
	if !m.IsLocalWhitelisted("::1") {
		t.Errorf("::1 should be whitelisted in memory even when ipset write fails")
	}
	if !m.IsLocalWhitelisted("10.0.0.1") {
		t.Errorf("10.0.0.1 should still be whitelisted in memory")
	}
	accepted, err := m.Block("::1")
	if accepted || err == nil {
		t.Errorf("Block(::1) should be rejected by in-memory whitelist: accepted=%v err=%v", accepted, err)
	}
}

// TestManager_SyncWhitelistPartialFailure 逐条写入：某一条 IP 写入失败时跳过该条，其余条目正常写入。
// 这是用户要求的核心行为——保证"部分可用"。
func TestManager_SyncWhitelistPartialFailure(t *testing.T) {
	m, mem := newTestManager()
	defer m.Close()

	// 设置 ::1/128 为指定失败 IP
	mem.SetFailOnIPs("::1/128")

	err := m.SyncLocalWhitelist([]string{"127.0.0.1", "::1", "192.168.1.0/24"})
	if err == nil {
		t.Fatalf("expected partial failure error for ::1/128")
	}
	t.Logf("got expected partial failure: %v", err)

	// 1. 内存白名单应包含所有条目（包括失败的 ::1）
	if !m.IsLocalWhitelisted("::1") {
		t.Errorf("::1 should be whitelisted in memory even when ipset write fails")
	}
	if !m.IsLocalWhitelisted("127.0.0.1") {
		t.Errorf("127.0.0.1 should be whitelisted in memory")
	}
	if !m.IsLocalWhitelisted("192.168.1.100") {
		t.Errorf("192.168.1.100 should be whitelisted via CIDR 192.168.1.0/24")
	}

	// 2. 成功写入的条目应在 ipset 中
	members, _ := mem.List(SetWhitelist)
	want := map[string]bool{
		"127.0.0.1/32":   true,
		"192.168.1.0/24": true,
	}
	for _, member := range members {
		if !want[member] && member == "::1/128" {
			t.Errorf("::1/128 should NOT be in ipset (write failed)")
		}
		if want[member] {
			delete(want, member)
		}
	}
	if len(want) > 0 {
		t.Errorf("missing successful ipset entries: %v", want)
	}

	// 3. 失败的 ::1/128 不应在 whitelisted 跟踪中
	m.mu.RLock()
	_, tracked := m.whitelisted["::1/128"]
	m.mu.RUnlock()
	if tracked {
		t.Errorf("::1/128 should NOT be in whitelisted tracker (ipset write failed)")
	}

	// 4. Block 应被内存白名单豁免
	accepted, err := m.Block("::1")
	if accepted || err == nil {
		t.Errorf("Block(::1) should be rejected by in-memory whitelist: accepted=%v err=%v", accepted, err)
	}

	// 5. 清除失败设置后，重新同步应成功
	mem.SetFailOnIPs() // 清空失败列表
	err = m.SyncLocalWhitelist([]string{"127.0.0.1", "::1", "192.168.1.0/24"})
	if err != nil {
		t.Fatalf("second sync should succeed: %v", err)
	}
	// 这次 ::1/128 应该在 ipset 中
	members, _ = mem.List(SetWhitelist)
	found := false
	for _, member := range members {
		if member == "::1/128" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("::1/128 should be in ipset after retry without failure")
	}
}

// TestManager_SyncWhitelistBatchFirst 验证两级写入策略：
//   1. 所有条目有效 → 批量写入成功（不降级逐条）
//   2. 部分条目无效 → 批量失败后降级逐条，跳过失败条目
func TestManager_SyncWhitelistBatchFirst(t *testing.T) {
	m, mem := newTestManager()
	defer m.Close()

	// 场景 1：所有条目有效，批量写入直接成功
	err := m.SyncLocalWhitelist([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"})
	if err != nil {
		t.Fatalf("all-valid sync should succeed via batch: %v", err)
	}
	members, _ := mem.List(SetWhitelist)
	if len(members) != 3 {
		t.Errorf("batch success: want 3 members, got %v", members)
	}

	// 先清空白名单，确保后续测试不受历史影响
	if err := m.SyncLocalWhitelist([]string{}); err != nil {
		t.Fatalf("clear whitelist: %v", err)
	}
	members, _ = mem.List(SetWhitelist)
	if len(members) != 0 {
		t.Fatalf("whitelist should be empty after clear, got %v", members)
	}

	// 场景 2：指定 10.0.0.2/32 为失败项，批量写入整体失败后降级逐条
	mem.SetFailOnIPs("10.0.0.2/32")
	err = m.SyncLocalWhitelist([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"})
	if err == nil {
		t.Fatalf("expected partial failure because 10.0.0.2/32 is marked as fail")
	}
	t.Logf("batch failed, per-entry fallback kicked in: %v", err)

	// 只有 10.0.0.1 和 10.0.0.3 成功写入，10.0.0.2 被跳过
	members, _ = mem.List(SetWhitelist)
	want := map[string]bool{
		"10.0.0.1/32": true,
		"10.0.0.3/32": true,
	}
	for _, member := range members {
		if member == "10.0.0.2/32" {
			t.Errorf("10.0.0.2/32 should NOT be in ipset (marked as fail)")
		}
		if want[member] {
			delete(want, member)
		}
	}
	if len(want) > 0 {
		t.Errorf("missing successful entries after fallback: %v", want)
	}

	// 场景 3：清除失败项，重新同步批量恢复
		mem.SetFailOnIPs()
		err = m.SyncLocalWhitelist([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"})
		if err != nil {
			t.Fatalf("recovery sync should succeed via batch: %v", err)
		}
		members, _ = mem.List(SetWhitelist)
		if len(members) != 3 {
			t.Errorf("recovery: want 3 members, got %v", members)
		}
}

// TestManager_Block_TimeoutFallback 验证 timeout 降级：
// 当内核/ipset 不支持 --timeout 参数时，Manager 应自动降级为不带 timeout 的 add，
// 仍能成功将 IP 加入黑名单。
//
// 场景来源：deepin 生产环境 ipset v6.29 + 旧内核：
//   ipset add wardennet_blacklist IP -exist --timeout 3600 → Kernel error -1
//   ipset add wardennet_blacklist IP -exist                → 成功
func TestManager_Block_TimeoutFallback(t *testing.T) {
	mem := NewMemClient()
	mem.SetNoTimeout(true) // 模拟旧内核：带 timeout 失败，不带 timeout 成功
	m := NewManager(mem, 1, 10*time.Millisecond)
	m.SetBlockTimeout(3600) // 配置了 timeout
	defer m.Close()

	// 第一次 Block：带 timeout 会在 applyWithRetry 里失败，
	// Manager.blockInternal 里检测到 err 后，去掉 timeout 降级重试 → 成功
	accepted, err := m.Block("106.75.139.66")
	if err != nil {
		t.Fatalf("Block should succeed after timeout fallback, got err=%v", err)
	}
	if !accepted {
		t.Errorf("accepted should be true after timeout fallback")
	}

	// 验证 IP 已在 ipset 中
	ok, _ := mem.Exists(SetBlacklist, "106.75.139.66")
	if !ok {
		t.Errorf("IP should be in blacklist after timeout fallback")
	}

	// 第二次 Block：已在黑名单中 → ErrAlreadyBlocked（幂等）
	accepted, err = m.Block("106.75.139.66")
	if !errors.Is(err, ErrAlreadyBlocked) {
		t.Errorf("second block: want ErrAlreadyBlocked, got err=%v accepted=%v", err, accepted)
	}

	// 第三次 Block 不同 IP：同样 timeout 降级
	accepted, err = m.Block("8.8.8.8")
	if err != nil {
		t.Fatalf("second IP should also succeed via timeout fallback, got err=%v", err)
	}
	if !accepted {
		t.Errorf("second IP: accepted should be true")
	}
	ok, _ = mem.Exists(SetBlacklist, "8.8.8.8")
	if !ok {
		t.Errorf("second IP should be in blacklist")
	}

	// 关掉 noTimeout，再 Block → 直接成功（带 timeout 正常）
	mem.SetNoTimeout(false)
	accepted, err = m.Block("1.1.1.1")
	if err != nil {
		t.Fatalf("with noTimeout off, Block should succeed: %v", err)
	}
	if !accepted {
		t.Errorf("with noTimeout off: accepted should be true")
	}
}

// TestManager_Block_TimeoutZeroNoFallback 验证 timeout=0 时不触发降级：
// 不带 timeout 的 add 失败就是真失败，不应该重试。
func TestManager_Block_TimeoutZeroNoFallback(t *testing.T) {
	mem := NewMemClient()
	mem.SetNoTimeout(true)
	m := NewManager(mem, 1, 10*time.Millisecond)
	m.SetBlockTimeout(0) // timeout = 0，不配置
	defer m.Close()

	// timeout=0 时，blockInternal 第一次就是不带 timeout 的 add，
	// MemClient noTimeout 只拒绝 Timeout>0 的，所以应该成功
	accepted, err := m.Block("10.0.0.1")
	if err != nil {
		t.Fatalf("timeout=0 with noTimeout client: Block should succeed: %v", err)
	}
	if !accepted {
		t.Errorf("accepted should be true")
	}
}
