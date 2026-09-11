// Package ipsetutil - priority_test.go 白名单优先级与永久豁免专项验收测试。
// 覆盖：本地白名单绝对优先、ForceBlock 强制覆盖、云端下发黑名单被豁免、白名单移出后恢复等场景。
package ipsetutil

import (
	"errors"
	"testing"
	"time"
)

// newPriorityTestManager 创建用于优先级测试的 Manager。
func newPriorityTestManager() (*Manager, *MemClient) {
	mem := NewMemClient()
	m := NewManager(mem, 2, 10*time.Millisecond)
	return m, mem
}

// TestPriority_LocalWhitelistHighest 验证本地白名单优先级最高：
// 1. 本地白名单 IP 被 Block() 豁免
// 2. 本地白名单 IP 即使云端下发黑名单也被过滤
func TestPriority_LocalWhitelistHighest(t *testing.T) {
	m, _ := newPriorityTestManager()
	defer m.Close()

	// 同步本地白名单
	err := m.SyncLocalWhitelist([]string{"10.0.0.1", "192.168.1.0/24"})
	if err != nil {
		t.Fatalf("SyncLocalWhitelist: %v", err)
	}

	t.Run("Block_whitelisted_IP_exempt", func(t *testing.T) {
		accepted, err := m.Block("10.0.0.1")
		if accepted || !errors.Is(err, ErrWhitelisted) {
			t.Errorf("Block whitelisted: accepted=%v err=%v, want ErrWhitelisted", accepted, err)
		}
	})

	t.Run("Block_CIDR_whitelisted_exempt", func(t *testing.T) {
		// 192.168.1.100 在 192.168.1.0/24 内
		accepted, err := m.Block("192.168.1.100")
		if accepted || !errors.Is(err, ErrWhitelisted) {
			t.Errorf("Block CIDR whitelisted: accepted=%v err=%v, want ErrWhitelisted", accepted, err)
		}
	})

	t.Run("Cloud_blacklist_add_filtered_for_whitelisted", func(t *testing.T) {
		entries := []Entry{
			{Set: SetBlacklist, IP: "10.0.0.1", Op: OpAdd},
			{Set: SetBlacklist, IP: "192.168.1.50", Op: OpAdd}, // CIDR 内
			{Set: SetBlacklist, IP: "8.8.8.8", Op: OpAdd},      // 不在白名单
		}
		filtered, err := m.ApplyCloud(entries)
		if err != nil {
			t.Fatalf("ApplyCloud: %v", err)
		}
		// 两个白名单 IP 都应被过滤
		if len(filtered) != 2 {
			t.Errorf("filtered count=%d, want 2", len(filtered))
		}
		// 10.0.0.1 不在黑名单
		if ok, _ := m.client.Exists(SetBlacklist, "10.0.0.1"); ok {
			t.Errorf("10.0.0.1 should NOT be in blacklist (local whitelist)")
		}
		// 192.168.1.50 不在黑名单
		if ok, _ := m.client.Exists(SetBlacklist, "192.168.1.50"); ok {
			t.Errorf("192.168.1.50 should NOT be in blacklist (CIDR whitelist)")
		}
		// 8.8.8.8 应在黑名单
		if ok, _ := m.client.Exists(SetBlacklist, "8.8.8.8"); !ok {
			t.Errorf("8.8.8.8 should be in blacklist")
		}
	})

	t.Run("Whitelisted_IP_not_in_blocked_tracker", func(t *testing.T) {
		// 白名单 IP 不应出现在 blocked map 中
		if m.LocalBlockedCount() != 1 { // 只有 8.8.8.8
			t.Errorf("LocalBlockedCount=%d, want 1", m.LocalBlockedCount())
		}
	})
}

// TestPriority_ForceBlock 验证 --force 覆盖白名单：
// 1. ForceBlock 忽略白名单豁免
// 2. ForceBlock 正常加入黑名单
// 3. 幂等行为正确
func TestPriority_ForceBlock(t *testing.T) {
	m, _ := newPriorityTestManager()
	defer m.Close()

	err := m.SyncLocalWhitelist([]string{"127.0.0.1", "10.0.0.0/8"})
	if err != nil {
		t.Fatalf("SyncLocalWhitelist: %v", err)
	}

	t.Run("ForceBlock_bypasses_whitelist", func(t *testing.T) {
		// 127.0.0.1 在白名单中
		accepted, err := m.ForceBlock("127.0.0.1")
		if err != nil {
			t.Fatalf("ForceBlock error: %v", err)
		}
		if !accepted {
			t.Errorf("ForceBlock whitelisted IP: accepted=%v, want true", accepted)
		}
		if ok, _ := m.client.Exists(SetBlacklist, "127.0.0.1"); !ok {
			t.Errorf("127.0.0.1 should be in blacklist after ForceBlock")
		}
	})

	t.Run("ForceBlock_CIDR_bypasses_whitelist", func(t *testing.T) {
		// 10.1.2.3 在 10.0.0.0/8 白名单 CIDR 内
		accepted, err := m.ForceBlock("10.1.2.3")
		if err != nil {
			t.Fatalf("ForceBlock CIDR error: %v", err)
		}
		if !accepted {
			t.Errorf("ForceBlock CIDR: accepted=%v, want true", accepted)
		}
	})

	t.Run("ForceBlock_idempotent", func(t *testing.T) {
		// 重复 ForceBlock 同一 IP 应幂等
		accepted, err := m.ForceBlock("127.0.0.1")
		if !errors.Is(err, ErrAlreadyBlocked) {
			t.Errorf("second ForceBlock err=%v, want ErrAlreadyBlocked", err)
		}
		if accepted {
			t.Errorf("second ForceBlock accepted=%v, want false", accepted)
		}
	})

	t.Run("Normal_Block_still_respects_whitelist_after_force", func(t *testing.T) {
		// ForceBlock 之后，普通 Block 对白名单 IP 仍然豁免
		accepted, err := m.Block("10.0.0.5")
		if accepted || !errors.Is(err, ErrWhitelisted) {
			t.Errorf("Block after ForceBlock: accepted=%v err=%v, want ErrWhitelisted", accepted, err)
		}
	})
}

// TestPriority_WhitelistRemoval 验证白名单移出后恢复：
// 1. 移出白名单前 Block 被豁免
// 2. 移出白名单后 Block 正常生效
func TestPriority_WhitelistRemoval(t *testing.T) {
	m, _ := newPriorityTestManager()
	defer m.Close()

	// 初始白名单
	err := m.SyncLocalWhitelist([]string{"172.16.0.1"})
	if err != nil {
		t.Fatalf("SyncLocalWhitelist: %v", err)
	}

	// 确认豁免
	accepted, err := m.Block("172.16.0.1")
	if accepted || !errors.Is(err, ErrWhitelisted) {
		t.Fatalf("Block before removal: accepted=%v err=%v, want ErrWhitelisted", accepted, err)
	}

	// 移出白名单
	err = m.SyncLocalWhitelist([]string{}) // 清空白名单
	if err != nil {
		t.Fatalf("SyncLocalWhitelist remove: %v", err)
	}

	// 确认不再豁免
	accepted, err = m.Block("172.16.0.1")
	if err != nil {
		t.Fatalf("Block after removal error: %v", err)
	}
	if !accepted {
		t.Errorf("Block after removal: accepted=%v, want true", accepted)
	}
	if ok, _ := m.client.Exists(SetBlacklist, "172.16.0.1"); !ok {
		t.Errorf("172.16.0.1 should be in blacklist after whitelist removal")
	}
}

// TestPriority_WhitelistClearsBlacklistHistory 验证加白联动清黑：
// 1. ForceBlock 加入黑名单
// 2. 加入白名单后，ForceBlock 拉黑的记录应从 blacklist ipset 和 blocked map 中删除
//    （白名单不仅运行时豁免，还联动清理黑名单，防止 iptables ACCEPT 规则被意外移除后流量又被 DROP）
func TestPriority_WhitelistClearsBlacklistHistory(t *testing.T) {
	m, _ := newPriorityTestManager()
	defer m.Close()

	// 先 ForceBlock 拉黑
	_, err := m.ForceBlock("5.5.5.5")
	if err != nil {
		t.Fatalf("ForceBlock: %v", err)
	}

	// 确认已在 blocked map 和 blacklist ipset 中
	if m.LocalBlockedCount() != 1 {
		t.Fatalf("blocked count should be 1 before whitelist, got %d", m.LocalBlockedCount())
	}
	if ok, _ := m.client.Exists(SetBlacklist, "5.5.5.5"); !ok {
		t.Fatalf("5.5.5.5 should be in blacklist ipset before whitelist")
	}

	// 现在加入白名单（触发加白联动清黑）
	err = m.SyncLocalWhitelist([]string{"5.5.5.5"})
	if err != nil {
		t.Fatalf("SyncLocalWhitelist: %v", err)
	}

	// 白名单命中
	if !m.IsLocalWhitelisted("5.5.5.5") {
		t.Errorf("5.5.5.5 should be whitelisted")
	}

	// 加白联动清黑：黑名单 ipset 中的记录应被删除
	if ok, _ := m.client.Exists(SetBlacklist, "5.5.5.5"); ok {
		t.Errorf("5.5.5.5 should be removed from blacklist ipset after whitelist (联动清黑)")
	}

	// blocked map 也应被清理
	if m.LocalBlockedCount() != 0 {
		t.Errorf("blocked count should be 0 after whitelist, got %d", m.LocalBlockedCount())
	}

	// 普通 Block 被豁免（白名单优先）
	accepted, err := m.Block("5.5.5.5")
	if accepted || !errors.Is(err, ErrWhitelisted) {
		t.Errorf("Block whitelisted: accepted=%v err=%v, want ErrWhitelisted", accepted, err)
	}
}

// TestPriority_CloudWhitelistAppliedNormally 验证云端白名单正常写入：
// 1. 云端白名单 add 直接写入（不受本地白名单豁免判定）
// 2. 云端白名单 del 正常删除
func TestPriority_CloudWhitelistAppliedNormally(t *testing.T) {
	m, _ := newPriorityTestManager()
	defer m.Close()

	// 本地白名单
	err := m.SyncLocalWhitelist([]string{"10.0.0.1"})
	if err != nil {
		t.Fatalf("SyncLocalWhitelist: %v", err)
	}

	// 云端下发白名单（IP 恰好与本地白名单相同）
	entries := []Entry{
		{Set: SetWhitelist, IP: "10.0.0.1", Op: OpAdd},
		{Set: SetWhitelist, IP: "8.8.4.4", Op: OpAdd},
	}
	filtered, err := m.ApplyCloud(entries)
	if err != nil {
		t.Fatalf("ApplyCloud whitelist: %v", err)
	}
	// 白名单条目不应被过滤（只有黑名单受本地白名单豁免）
	if len(filtered) != 0 {
		t.Errorf("filtered=%v, want empty (whitelist entries not filtered)", filtered)
	}
	if ok, _ := m.client.Exists(SetWhitelist, "10.0.0.1"); !ok {
		t.Errorf("10.0.0.1 should be in whitelist set from cloud")
	}
	if ok, _ := m.client.Exists(SetWhitelist, "8.8.4.4"); !ok {
		t.Errorf("8.8.4.4 should be in whitelist set from cloud")
	}
}

// TestPriority_MixedCloudEntries 验证混合云端条目（黑名单 + 白名单）正确处理。
func TestPriority_MixedCloudEntries(t *testing.T) {
	m, _ := newPriorityTestManager()
	defer m.Close()

	err := m.SyncLocalWhitelist([]string{"192.168.0.0/16", "10.0.0.1"})
	if err != nil {
		t.Fatalf("SyncLocalWhitelist: %v", err)
	}

	entries := []Entry{
		{Set: SetBlacklist, IP: "10.0.0.1", Op: OpAdd},     // 被本地豁免
		{Set: SetBlacklist, IP: "192.168.5.1", Op: OpAdd},  // 被本地豁免 (CIDR)
		{Set: SetBlacklist, IP: "1.2.3.4", Op: OpAdd},      // 正常加入
		{Set: SetWhitelist, IP: "5.6.7.8", Op: OpAdd},      // 白名单正常写入
	}
	filtered, err := m.ApplyCloud(entries)
	if err != nil {
		t.Fatalf("ApplyCloud mixed: %v", err)
	}
	if len(filtered) != 2 {
		t.Errorf("filtered count=%d, want 2", len(filtered))
	}
	if ok, _ := m.client.Exists(SetBlacklist, "1.2.3.4"); !ok {
		t.Errorf("1.2.3.4 should be in blacklist")
	}
	if ok, _ := m.client.Exists(SetWhitelist, "5.6.7.8"); !ok {
		t.Errorf("5.6.7.8 should be in whitelist")
	}
	// 被豁免的 IP 不应在黑名单
	if ok, _ := m.client.Exists(SetBlacklist, "10.0.0.1"); ok {
		t.Errorf("10.0.0.1 should NOT be in blacklist (whitelisted)")
	}
	if ok, _ := m.client.Exists(SetBlacklist, "192.168.5.1"); ok {
		t.Errorf("192.168.5.1 should NOT be in blacklist (CIDR whitelisted)")
	}
}

// TestPriority_ConcurrentAccess 并发安全：多个 goroutine 同时 Block/ForceBlock。
func TestPriority_ConcurrentAccess(t *testing.T) {
	m, _ := newPriorityTestManager()
	defer m.Close()

	err := m.SyncLocalWhitelist([]string{"10.0.0.1"})
	if err != nil {
		t.Fatalf("SyncLocalWhitelist: %v", err)
	}

	done := make(chan bool, 50)
	for i := 0; i < 10; i++ {
		go func() {
			// 白名单 IP 的 Block 应返回 ErrWhitelisted
			accepted, err := m.Block("10.0.0.1")
			if accepted || !errors.Is(err, ErrWhitelisted) {
				t.Errorf("concurrent Block: accepted=%v err=%v", accepted, err)
			}
			done <- true
		}()
	}
	for i := 0; i < 10; i++ {
		<-done
	}

	// 并发 ForceBlock（白名单 IP）
	for i := 0; i < 10; i++ {
		go func() {
			_, err := m.ForceBlock("10.0.0.1")
			if err != nil && !errors.Is(err, ErrAlreadyBlocked) {
				t.Errorf("concurrent ForceBlock: err=%v", err)
			}
			done <- true
		}()
	}
	for i := 0; i < 10; i++ {
		<-done
	}

	// 最终黑名单中应有 10.0.0.1（被 ForceBlock 加入）
	if ok, _ := m.client.Exists(SetBlacklist, "10.0.0.1"); !ok {
		t.Errorf("10.0.0.1 should be in blacklist after ForceBlock")
	}
}

// TestPriority_ImmutableWhitelistEntries 验证 SyncLocalWhitelist 的替换行为：
// 1. 新白名单覆盖旧白名单
// 2. 旧条目被正确从 ipset 中删除
func TestPriority_ImmutableWhitelistEntries(t *testing.T) {
	m, mem := newPriorityTestManager()
	defer m.Close()

	// 初始白名单
	err := m.SyncLocalWhitelist([]string{"1.1.1.1", "2.2.2.2"})
	if err != nil {
		t.Fatalf("first sync: %v", err)
	}

	members, _ := mem.List(SetWhitelist)
	if len(members) != 2 {
		t.Errorf("whitelist members=%v, want 2", members)
	}

	// 替换
	err = m.SyncLocalWhitelist([]string{"3.3.3.3"})
	if err != nil {
		t.Fatalf("second sync: %v", err)
	}

	members, _ = mem.List(SetWhitelist)
	if len(members) != 1 || members[0] != "3.3.3.3/32" {
		t.Errorf("whitelist members after replace=%v, want [3.3.3.3/32]", members)
	}

	// 旧白名单 IP 现在可以被 Block 了
	accepted, err := m.Block("1.1.1.1")
	if err != nil {
		t.Fatalf("Block after whitelist removal: %v", err)
	}
	if !accepted {
		t.Errorf("Block after removal: accepted=%v, want true", accepted)
	}
}

// TestPriority_InvalidIP 验证非法 IP 格式在 Block/ForceBlock 中被拒绝。
func TestPriority_InvalidIP(t *testing.T) {
	m, _ := newPriorityTestManager()
	defer m.Close()

	if _, err := m.ForceBlock("bad-ip"); !errors.Is(err, ErrInvalidIP) {
		t.Errorf("ForceBlock invalid: %v, want ErrInvalidIP", err)
	}
	if _, err := m.ForceBlock(""); !errors.Is(err, ErrInvalidIP) {
		t.Errorf("ForceBlock empty: %v, want ErrInvalidIP", err)
	}
}

// TestPriority_EmptyWhitelist 空白名单时所有 Block 正常工作。
func TestPriority_EmptyWhitelist(t *testing.T) {
	m, _ := newPriorityTestManager()
	defer m.Close()

	// 不设置白名单
	if m.IsLocalWhitelisted("8.8.8.8") {
		t.Errorf("empty whitelist: 8.8.8.8 should not be whitelisted")
	}

	accepted, err := m.Block("8.8.8.8")
	if err != nil {
		t.Fatalf("Block no whitelist: %v", err)
	}
	if !accepted {
		t.Errorf("Block no whitelist: accepted=%v, want true", accepted)
	}
}

// TestPriority_CloudApplyPartialFailure 云端下发：单条失败不影响其他条目。
// 某一条黑名单写入失败时跳过该条，其余条目正常写入。
func TestPriority_CloudApplyPartialFailure(t *testing.T) {
	m, mem := newPriorityTestManager()
	defer m.Close()

	// 设置 8.8.8.8 为指定失败 IP
	mem.SetFailOnIPs("8.8.8.8")

	entries := []Entry{
		{Set: SetBlacklist, IP: "8.8.8.8", Op: OpAdd},     // 指定失败
		{Set: SetBlacklist, IP: "1.2.3.4", Op: OpAdd},     // 正常
		{Set: SetWhitelist, IP: "5.6.7.8", Op: OpAdd},     // 正常
	}
	filtered, err := m.ApplyCloud(entries)
	if err == nil {
		t.Fatalf("expected partial failure error")
	}
	t.Logf("got expected partial failure: %v", err)

	// 1. 被豁免的条目应为空（本地无白名单）
	if len(filtered) != 0 {
		t.Errorf("filtered count=%d, want 0", len(filtered))
	}

	// 2. 正常条目应在 ipset 中
	if ok, _ := m.client.Exists(SetBlacklist, "1.2.3.4"); !ok {
		t.Errorf("1.2.3.4 should be in blacklist (successful write)")
	}
	if ok, _ := m.client.Exists(SetWhitelist, "5.6.7.8"); !ok {
		t.Errorf("5.6.7.8 should be in whitelist (successful write)")
	}

	// 3. 失败的条目不应在 ipset 中
	if ok, _ := m.client.Exists(SetBlacklist, "8.8.8.8"); ok {
		t.Errorf("8.8.8.8 should NOT be in blacklist (write failed)")
	}

	// 4. 内存状态：成功条目已更新，失败条目未更新
	m.mu.RLock()
	_, blocked1234 := m.blocked["1.2.3.4"]
	_, blocked8888 := m.blocked["8.8.8.8"]
	_, whitelisted5678 := m.whitelisted["5.6.7.8"]
	m.mu.RUnlock()
	if !blocked1234 {
		t.Errorf("1.2.3.4 should be in blocked tracker (successful write)")
	}
	if blocked8888 {
		t.Errorf("8.8.8.8 should NOT be in blocked tracker (write failed)")
	}
	if !whitelisted5678 {
		t.Errorf("5.6.7.8 should be in whitelisted tracker (successful write)")
	}
}