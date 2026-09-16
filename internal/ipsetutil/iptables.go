// Package ipsetutil - iptables.go 管理 iptables 规则，确保 ipset 黑名单真正生效。
// 在 Linux 生产环境下，需要通过 iptables 将 ipset 中的 IP 流量 DROP 掉。
package ipsetutil

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

const (
	// IptablesBin iptables 命令路径
	IptablesBin = "iptables"
	// DefaultBanPorts 默认封禁端口（80=HTTP, 443=HTTPS）
	DefaultBanPorts = "80,443"
)

// IptablesManager 管理 iptables 规则。
// 在非 Linux 平台上所有操作都是空实现，保证编译通过。
type IptablesManager struct {
	iptablesBin string
	banSetName  string
	banPorts    string
}

// NewIptablesManager 创建 iptables 管理器。
func NewIptablesManager(iptablesBin, banSetName, banPorts string) *IptablesManager {
	if iptablesBin == "" {
		iptablesBin = IptablesBin
	}
	if banPorts == "" {
		banPorts = DefaultBanPorts
	}
	return &IptablesManager{
		iptablesBin: iptablesBin,
		banSetName:  banSetName,
		banPorts:    banPorts,
	}
}

// EnsureWhitelistAcceptRule 确保白名单 ACCEPT 规则存在且排在 DROP 规则之前。
// firewalld reload 或管理员手动重排可能导致 ACCEPT 排到 DROP 之后，
// 本函数在已存在时额外校验规则顺序，不对则删后重插修正位置。
// 规则: iptables -I INPUT -m set --match-set wardennet_whitelist src -j ACCEPT
func (m *IptablesManager) EnsureWhitelistAcceptRule() error {
	rule := fmt.Sprintf("-m set --match-set %s src -j ACCEPT", SetWhitelist)
	if m.ruleExists(rule) {
		// 顺序校验：ACCEPT 序号必须 < DROP 序号（排在前面先匹配）
		wlNum, wlOK := m.ruleNumber(rule)
		dropRule := fmt.Sprintf("-p tcp -m set --match-set %s src -m multiport --dports %s -j DROP", m.banSetName, m.banPorts)
		dropNum, dropOK := m.ruleNumber(dropRule)
		if wlOK && dropOK && wlNum >= dropNum {
			// 顺序反了：删了重插（-D 参数必须与创建时的 -I 参数完全一致，
			// 多余的 -p tcp 会导致规则匹配失败删不掉）
			_ = m.run(m.iptablesBin, "-D", "INPUT",
				"-m", "set", "--match-set", SetWhitelist, "src", "-j", "ACCEPT")
			return m.run(m.iptablesBin, "-I", "INPUT",
				"-m", "set", "--match-set", SetWhitelist, "src",
				"-j", "ACCEPT",
			)
		}
		return nil
	}
	return m.run(m.iptablesBin,
		"-I", "INPUT",
		"-m", "set", "--match-set", SetWhitelist, "src",
		"-j", "ACCEPT",
	)
}

// EnsureBanRule 确保 iptables 封禁规则存在。
// 规则：iptables -I INPUT -p tcp -m set --match-set <set> src -m multiport --dports <ports> -j DROP
func (m *IptablesManager) EnsureBanRule() error {
	rule := fmt.Sprintf(
		"-p tcp -m set --match-set %s src -m multiport --dports %s -j DROP",
		m.banSetName, m.banPorts,
	)

	// 检查规则是否已存在
	if m.ruleExists(rule) {
		return nil
	}

	// 插入规则到 INPUT 链
	return m.run(m.iptablesBin,
		"-I", "INPUT",
		"-p", "tcp",
		"-m", "set", "--match-set", m.banSetName, "src",
		"-m", "multiport", "--dports", m.banPorts,
		"-j", "DROP",
	)
}

// RemoveBanRule 移除 iptables 封禁规则和白名单 ACCEPT 规则（用于优雅关闭）。
// 两条规则可能只有一条存在，分别尝试删除，全部失败才返回错误。
func (m *IptablesManager) RemoveBanRule() error {
	banErr := m.run(m.iptablesBin,
		"-D", "INPUT",
		"-p", "tcp",
		"-m", "set", "--match-set", m.banSetName, "src",
		"-m", "multiport", "--dports", m.banPorts,
		"-j", "DROP",
	)
	wlErr := m.run(m.iptablesBin,
		"-D", "INPUT",
		"-m", "set", "--match-set", SetWhitelist, "src",
		"-j", "ACCEPT",
	)
	if banErr != nil && wlErr != nil {
		return fmt.Errorf("remove ban rule: %v; remove whitelist accept rule: %v", banErr, wlErr)
	}
	return nil
}

// ruleExists 检查 iptables 规则是否已存在。
func (m *IptablesManager) ruleExists(rule string) bool {
	out, err := m.runOutput(m.iptablesBin, "-S", "INPUT")
	if err != nil {
		return false
	}
	return strings.Contains(string(out), rule)
}

// ruleNumber 从 iptables INPUT 链中查找包含 substr 的规则行，返回其序号。
// iptables -S INPUT 按规则顺序输出（第 N 行即第 N 条规则），直接按行序计数。
// 注意：不能用 --line-numbers——它仅 -L 模式支持，-S 模式会报 unrecognized option。
// iptables 报错或找不到时返回 0, false。
func (m *IptablesManager) ruleNumber(substr string) (int, bool) {
	out, err := m.runOutput(m.iptablesBin, "-S", "INPUT")
	if err != nil {
		return 0, false
	}
	num := 0
	for _, line := range strings.Split(string(out), "\n") {
		if line == "" {
			continue
		}
		num++ // 非空行即一条规则，行序 = 规则序号
		if strings.Contains(line, substr) {
			return num, true
		}
	}
	return 0, false
}

// run 执行命令。
func (m *IptablesManager) run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	return cmd.Run()
}

// runOutput 执行命令并返回 stdout。
func (m *IptablesManager) runOutput(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return stdout.Bytes(), nil
}
