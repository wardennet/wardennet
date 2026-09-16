// Package ipsetutil - manager.go 封装 Manager：
//  - 维护本地白名单（优先级绝对最高）
//  - 增量 add/del，避免频繁全量 reload
//  - ipset 调用失败自动降级重试，不影响业务
package ipsetutil

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// 业务错误类型，供上层判断决策。
var (
	// ErrWhitelisted 命中本地白名单，请求被豁免。
	ErrWhitelisted = errors.New("ip is in local whitelist, skipped")
	// ErrAlreadyBlocked IP 已在黑名单中，幂等跳过。
	ErrAlreadyBlocked = errors.New("ip is already blocked")
	// ErrNotBlocked IP 不在黑名单中，解除封禁跳过。
	ErrNotBlocked = errors.New("ip is not blocked")
	// ErrInvalidIP 非法 IP 格式。
	ErrInvalidIP = errors.New("invalid ip or cidr")
)

// Manager 维护黑白名单业务状态并驱动底层 Client。
type Manager struct {
	client Client
	retry  int           // 重试次数（每次间隔 200ms）
	delay  time.Duration // 重试间隔

	blockTimeout int // 本地 blacklist add 默认 --timeout 秒数（由上层 TTL 配置注入），0 表示不加

	mu           sync.RWMutex
	localWL      map[string]struct{} // 本地白名单精确匹配
	localWLCIDR  []*net.IPNet        // 本地白名单 CIDR
	blocked      map[string]struct{} // 已在黑名单中的 IP（供增量判断）
	whitelisted  map[string]struct{} // 已在白名单中的 IP（供增量判断）
	closed       bool
}

// NewManager 创建 Manager。client 为 nil 时自动使用 MemClient（单元测试友好）。
// retry<=0 时默认为 3 次；delay<=0 时默认为 200ms。
func NewManager(client Client, retry int, delay time.Duration) *Manager {
	if client == nil {
		client = NewMemClient()
	}
	if retry <= 0 {
		retry = 3
	}
	if delay <= 0 {
		delay = 200 * time.Millisecond
	}
	m := &Manager{
		client:     client,
		retry:      retry,
		delay:      delay,
		localWL:    make(map[string]struct{}),
		blocked:    make(map[string]struct{}),
		whitelisted: make(map[string]struct{}),
	}
	// 确保集合存在
	_ = client.EnsureSet(SetBlacklist)
	_ = client.EnsureSet(SetWhitelist)
	return m
}

// SetBlockTimeout 设置本地 blacklist add 时的默认 ipset --timeout 秒数。
// 设为 0 表示不加 timeout（内核默认值，永不自动过期）。
// 仅影响后续 Block/ForceBlock 调用；ApplyCloud 不受影响（云端条目自带 Timeout）。
func (m *Manager) SetBlockTimeout(seconds int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if seconds < 0 {
		seconds = 0
	}
	m.blockTimeout = seconds
}

// Close 预留资源释放接口。目前无后台 goroutine，留空。
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
}

// ipToCIDR 将裸 IP 转成 hash:net 可接受的 CIDR 形式。
// IPv4 → /32，IPv6 → /128。hash:net 仅接受 IP/prefix 形式，裸 IPv6（如 ::1）
// 在部分内核版本会被拒绝，因此统一规范化。
// IPv4-mapped IPv6（如 ::ffff:192.0.2.1）必须保持 IPv6 语义，不能误判为 IPv4。
func ipToCIDR(ip net.IP) string {
	s := ip.String()
	// IPv6 地址（含 IPv4-mapped IPv6）统一走 /128
	if strings.Contains(s, ":") {
		return s + "/128"
	}
	return s + "/32"
}

// SyncLocalWhitelist 同步本地白名单（来自配置文件/用户指令）。
// 两级写入策略：
//   1. 先批量写入 ipset（高效，减少 syscall 次数）
//   2. 批量失败时降级为逐条写入，跳过失败条目，其余照常写入
//
// 内存白名单（localWL + localWLCIDR）始终完整更新，豁免逻辑不依赖 ipset。
// whitelisted 仅记录成功写入 ipset 的条目，保证后续增量 diff 计算正确。
func (m *Manager) SyncLocalWhitelist(items []string) error {
	newWL := make(map[string]struct{})
	var newCIDR []*net.IPNet

	desiredMembers := make(map[string]struct{})

	for _, s := range items {
		if s == "" {
			continue
		}
		if ip := net.ParseIP(s); ip != nil {
			newWL[s] = struct{}{}
			newWL[ip.String()] = struct{}{}
			desiredMembers[ipToCIDR(ip)] = struct{}{}
			continue
		}
		if _, n, err := net.ParseCIDR(s); err == nil {
			newCIDR = append(newCIDR, n)
			desiredMembers[n.String()] = struct{}{}
			continue
		}
		return fmt.Errorf("%w: %q", ErrInvalidIP, s)
	}

	// 1. 保存旧 whitelisted（计算需要删除的旧条目）
	m.mu.RLock()
	oldWhitelisted := make(map[string]struct{}, len(m.whitelisted))
	for k := range m.whitelisted {
		oldWhitelisted[k] = struct{}{}
	}
	m.mu.RUnlock()

	// 2. 更新内存白名单 —— 始终成功，豁免逻辑的真相来源
	m.mu.Lock()
	m.localWL = newWL
	m.localWLCIDR = newCIDR
	m.mu.Unlock()

	// 3. 构建 add/del 条目列表（含加白联动清黑）
	var addEntries []Entry
	var blacklistDelEntries []Entry // 白名单新增 → 联动从黑名单删除
	for member := range desiredMembers {
		addEntries = append(addEntries, Entry{Set: SetWhitelist, IP: member, Op: OpAdd})
		// 加白联动清黑：白名单新增时，从黑名单删除对应的裸 IP
		if bareIP, ok := cidrToBareIP(member); ok {
			blacklistDelEntries = append(blacklistDelEntries, Entry{Set: SetBlacklist, IP: bareIP, Op: OpDel})
		} else if _, ipnet, err := net.ParseCIDR(member); err == nil {
			// 子网 CIDR：找出 blocked map 中属于该子网的 IP
			m.mu.RLock()
			for blockedIP := range m.blocked {
				if parsed := net.ParseIP(blockedIP); parsed != nil && ipnet.Contains(parsed) {
					blacklistDelEntries = append(blacklistDelEntries, Entry{Set: SetBlacklist, IP: blockedIP, Op: OpDel})
				}
			}
			m.mu.RUnlock()
		}
	}
	var delEntries []Entry
	for ip := range oldWhitelisted {
		if _, exists := desiredMembers[ip]; !exists {
			delEntries = append(delEntries, Entry{Set: SetWhitelist, IP: ip, Op: OpDel})
		}
	}

	// 4. 两级写入：先删黑（联动），再加白，最后清理过期白名单
	var blacklistFailed map[string]struct{}
	if len(blacklistDelEntries) > 0 {
		blacklistFailed, _ = m.applyBatchOrFallback(blacklistDelEntries) // 删黑失败不阻塞加白（幂等）
	}
	failedAdds, errAdd := m.applyBatchOrFallback(addEntries)
	_, errDel := m.applyBatchOrFallback(delEntries)

	// 5. 更新 whitelisted + blocked（加白联动清黑）
	m.mu.Lock()
	// 先更新 blocked：只删除 ipset 实际删除成功的条目（failedMap 中的保留 blocked 状态）
	for _, e := range blacklistDelEntries {
		if _, fail := blacklistFailed[e.IP]; !fail {
			delete(m.blocked, e.IP)
		}
	}
	// 再更新 whitelisted —— 仅包含成功写入 ipset 的 add 条目
	m.whitelisted = make(map[string]struct{})
	for _, e := range addEntries {
		if _, fail := failedAdds[e.IP]; !fail {
			m.whitelisted[e.IP] = struct{}{}
		}
	}
	m.mu.Unlock()

	// 6. 汇总错误
	if errAdd != nil || errDel != nil {
		return fmt.Errorf("ipset sync partial failure: add_err=%v del_err=%v", errAdd, errDel)
	}
	return nil
}

// IsLocalWhitelisted 判断 IP 是否命中本地白名单。线程安全。
func (m *Manager) IsLocalWhitelisted(ip string) bool {
	if ip == "" {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, ok := m.localWL[ip]; ok {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range m.localWLCIDR {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// Contains 实现 detector.WhitelistChecker 接口（Go duck typing，无需 import detector）。
// 与 IsLocalWhitelisted 等价，专门为 Detector 统一白名单数据源设计。
func (m *Manager) Contains(ip string) bool {
	return m.IsLocalWhitelisted(ip)
}

// Block 将 IP 加入黑名单。返回 accepted=true 表示已受理；accepted=false 表示被白名单豁免或已存在。
// 业务规则：本地白名单绝对优先，命中则直接返回 ErrWhitelisted（accepted=false）。
// IP 已在黑名单中则返回 ErrAlreadyBlocked（accepted=false，幂等跳过）。
func (m *Manager) Block(ip string) (accepted bool, err error) {
	if !isValidIP(ip) {
		return false, ErrInvalidIP
	}
	if m.IsLocalWhitelisted(ip) {
		return false, ErrWhitelisted
	}
	return m.blockInternal(ip)
}

// ForceBlock 强制将 IP 加入黑名单，忽略本地白名单豁免。
// 仅用于 CLI blocklist add --force 场景，优先级高于一切白名单。
func (m *Manager) ForceBlock(ip string) (accepted bool, err error) {
	if !isValidIP(ip) {
		return false, ErrInvalidIP
	}
	return m.blockInternal(ip)
}

// blockInternal 内部黑名单添加逻辑（Block 与 ForceBlock 共用）。
func (m *Manager) blockInternal(ip string) (accepted bool, err error) {
	// 幂等：已在黑名单中直接返回（不视为错误）
	m.mu.RLock()
	_, blocked := m.blocked[ip]
	timeout := m.blockTimeout
	m.mu.RUnlock()
	if blocked {
		return false, ErrAlreadyBlocked
	}

	if err := m.applyWithRetry([]Entry{{Set: SetBlacklist, IP: ip, Op: OpAdd, Timeout: timeout}}); err != nil {
		// 如果 ipset 报 "already exists"，视为幂等成功
		if isAlreadyExistsError(err) {
			m.mu.Lock()
			m.blocked[ip] = struct{}{}
			m.mu.Unlock()
			return false, nil // 不视为错误，不触发 warn
		}
		return false, err
	}
	m.mu.Lock()
	m.blocked[ip] = struct{}{}
	m.mu.Unlock()
	return true, nil
}

// isAlreadyExistsError 判断是否为 ipset "已存在" 类错误。
func isAlreadyExistsError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return contains(msg, "already exists") ||
		contains(msg, "element is already") ||
		contains(msg, "exists")
}

// contains 字符串包含检查（避免引入 strings 包在文件头部）。
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Unblock 将 IP 从黑名单删除。
// 幂等设计：
//   - 内存 blocked map 中不存在 → 返回 ErrNotBlocked
//   - ipset 中已不存在（可能被 kernel timeout 提前删除）→ 视为成功，清理内存 map
//     （这是与内核 timeout 竞态的兜底，防止 blocked 内存残留导致再封锁失败）
func (m *Manager) Unblock(ip string) error {
	if !isValidIP(ip) {
		return ErrInvalidIP
	}
	m.mu.RLock()
	_, blocked := m.blocked[ip]
	m.mu.RUnlock()
	if !blocked {
		return ErrNotBlocked
	}
	err := m.applyWithRetry([]Entry{{Set: SetBlacklist, IP: ip, Op: OpDel}})
	// 无论 ipset del 成功还是条目已被内核 timeout 提前清理，
	// 都必须清掉 blocked 内存记录——否则该 IP 再触发 Block 会
	// 被 ErrAlreadyBlocked 跳过，导致内核无条目 = 防护失效
	// （这是 kernel timeout 与 TTL Sweep 竞态的关键修复）
	m.mu.Lock()
	delete(m.blocked, ip)
	m.mu.Unlock()
	if err != nil && !isNotInSetError(err) {
		return err
	}
	return nil
}

// isNotInSetError 判断错误是否为"IP 不在 ipset 中"（被 kernel timeout 提前清理的情况）。
// client_linux.go 已追加 -exist，这个检查作为跨平台/降级路径兜底。
func isNotInSetError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return contains(msg, "does not exist") || // set 不存在
		contains(msg, "cannot find element") ||
		contains(msg, "element not found") ||
		contains(msg, "cannot be deleted") // ipset v7: "Element cannot be deleted from the set: it's not added"
}

// ApplyCloud 应用云端下发的黑白名单变更。
// 两级写入策略：先批量写入，批量失败时降级为逐条写入。
// 云端黑名单受本地白名单豁免；云端白名单直接写入（不参与本地豁免判定）。
// 返回 filtered 为被本地白名单豁免的条目；error 仅在部分/全部失败时返回。
func (m *Manager) ApplyCloud(entries []Entry) ([]Entry, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	var filtered []Entry // 命中本地白名单的云端黑名单，需要反馈给云端
	var toApply []Entry  // 实际需要写入 ipset 的条目
	for _, e := range entries {
		if !isValidIP(e.IP) {
			continue
		}
		if e.Set == SetBlacklist && m.IsLocalWhitelisted(e.IP) {
			filtered = append(filtered, e)
			continue
		}
		// 加白联动清黑：WhiteAdd 时先从黑名单删除，操作顺序先删黑再加白
		if e.Set == SetWhitelist && e.Op == OpAdd {
			toApply = append(toApply, Entry{Set: SetBlacklist, IP: e.IP, Op: OpDel})
		}
		toApply = append(toApply, e)
	}
	if len(toApply) == 0 {
		return filtered, nil
	}

	// 两级写入：先批量，失败降级逐条
	failedMap, err := m.applyBatchOrFallback(toApply)

	// 更新成功条目的内存状态
	if len(failedMap) < len(toApply) {
		m.mu.Lock()
		for _, e := range toApply {
			if _, fail := failedMap[e.IP]; fail {
				continue
			}
			switch e.Set {
			case SetBlacklist:
				if e.Op == OpAdd {
					m.blocked[e.IP] = struct{}{}
				} else {
					delete(m.blocked, e.IP)
				}
			case SetWhitelist:
				if e.Op == OpAdd {
					m.whitelisted[e.IP] = struct{}{}
				} else {
					delete(m.whitelisted, e.IP)
				}
			}
		}
		m.mu.Unlock()
	}

	return filtered, err
}

// LocalBlockedCount 返回本地内存中已记录的黑名单 IP 数（用于统计）。
func (m *Manager) LocalBlockedCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.blocked)
}

// RebuildFromKernel 从内核 ipset 重建 blocked 内存 map。
// 启动时调用，确保内存状态与内核一致。
// 内核查询失败时不阻塞启动（返回 nil），由调用方记录 warn 日志。
func (m *Manager) RebuildFromKernel() (int, error) {
	members, err := m.client.List(SetBlacklist)
	if err != nil {
		// 内核 ipset 可能还不存在或权限不够——降级返回空列表
		return 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	rebuilt := make(map[string]struct{}, len(members))
	for _, ip := range members {
		rebuilt[ip] = struct{}{}
	}
	m.blocked = rebuilt
	return len(members), nil
}

// LocalWhitelistCount 返回本地白名单条目数（精确+CIDR 总条目）。
func (m *Manager) LocalWhitelistCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.localWL) + len(m.localWLCIDR)
}

// applyBatchOrFallback 两级写入策略：
//   1. 先批量写入（一次性提交所有条目，高效）
//   2. 批量失败时降级为逐条写入，跳过失败条目
//
// 返回值：
//   - failed: 失败的 IP 集合（批量成功时为空 map，逐条降级时包含具体失败 IP）
//   - error: 非 nil 表示存在部分或全部失败
func (m *Manager) applyBatchOrFallback(entries []Entry) (map[string]struct{}, error) {
	failed := make(map[string]struct{})
	if len(entries) == 0 {
		return failed, nil
	}

	// 第一级：批量写入
	if err := m.applyWithRetry(entries); err == nil {
		// 批量成功，无失败
		return failed, nil
	}

	// 第二级：降级为逐条写入
	for _, e := range entries {
		err := m.applyWithRetry([]Entry{e})
		if err != nil {
			failed[e.IP] = struct{}{}
		}
	}

	if len(failed) > 0 {
		return failed, fmt.Errorf("partial failure: %d/%d entries failed", len(failed), len(entries))
	}
	return failed, nil
}

// applyWithRetry 带重试的底层应用。重试期间阻塞调用方，保证业务及时感知失败。
func (m *Manager) applyWithRetry(entries []Entry) error {
	if len(entries) == 0 {
		return nil
	}
	var lastErr error
	for i := 0; i <= m.retry; i++ {
		if err := m.client.Apply(entries); err != nil {
			lastErr = err
			if i < m.retry {
				time.Sleep(m.delay)
			}
			continue
		}
		return nil
	}
	return fmt.Errorf("ipset apply failed after %d retries: %w", m.retry+1, lastErr)
}

// isValidIP 校验 IP 或 CIDR 合法性。
func isValidIP(s string) bool {
	if s == "" {
		return false
	}
	if ip := net.ParseIP(s); ip != nil {
		return true
	}
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	return false
}

// cidrToBareIP 如果 cidr 是单 IP CIDR（IPv4 /32 或 IPv6 /128），返回裸 IP 字符串和 true。
// 子网 CIDR 或解析失败返回 "", false。用于从白名单 CIDR 成员提取裸 IP 以联动清黑。
func cidrToBareIP(cidr string) (string, bool) {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", false
	}
	if ip.To4() != nil {
		// IPv4 单 IP
		if strings.HasSuffix(cidr, "/32") {
			return ip.String(), true
		}
	} else {
		// IPv6 单 IP（含 IPv4-mapped IPv6）
		if strings.HasSuffix(cidr, "/128") {
			return ip.String(), true
		}
	}
	return "", false
}
