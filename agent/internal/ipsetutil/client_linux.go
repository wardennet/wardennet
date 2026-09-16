//go:build linux
// +build linux

package ipsetutil

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// LinuxClient 通过系统 ipset 命令调用内核 ipset。
// 在 Linux 生产环境下使用，真实执行 ipset create/add/del/test/list 命令。
type LinuxClient struct {
	Bin string // ipset 命令路径，默认 "ipset"
}

// NewLinuxClient 创建 Linux ipset 客户端。
func NewLinuxClient(bin string) *LinuxClient {
	if bin == "" {
		bin = "ipset"
	}
	return &LinuxClient{Bin: bin}
}

// EnsureSet 确保 ipset 集合存在，不存在则创建。
// whitelist 使用 hash:net（支持 IP/CIDR/IPv6，静态列表无需 timeout）；
// blacklist 使用 hash:ip（支持 timeout，动态拉黑需要 TTL 过期）。
// 如果已存在的集合类型与期望不符（如旧版 whitelist 为 hash:ip），
// 会自动销毁重建（一次性迁移，白名单成员在 SyncLocalWhitelist 中会重新添加）。
func (c *LinuxClient) EnsureSet(name string) error {
	desiredType := "hash:ip"
	if name == SetWhitelist {
		desiredType = "hash:net"
	}

	// 检查集合是否存在
	err := c.run(c.Bin, "list", "set", name)
	if err == nil {
		// 已存在，检查类型是否正确
		actualType := c.getType(name)
		if actualType == desiredType {
			return nil // 类型正确，无需处理
		}
		// 类型不匹配：销毁重建（迁移场景）
		if err := c.run(c.Bin, "destroy", name); err != nil {
			return fmt.Errorf("destroy %s for type migration: %w", name, err)
		}
	}

	return c.run(c.Bin, "create", name, desiredType)
}

// getType 查询 ipset 集合的类型（如 "hash:ip"、"hash:net"）。
func (c *LinuxClient) getType(name string) string {
	out, err := c.runOutput(c.Bin, "list", "set", name)
	if err != nil {
		return ""
	}
	// 解析 "Type: hash:ip" 或 "Type: hash:net"
	for _, line := range bytes.Split(out, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("Type:")) {
			return strings.TrimSpace(string(line[len("Type:"):]))
		}
	}
	return ""
}

// Apply 原子应用一批变更。
func (c *LinuxClient) Apply(entries []Entry) error {
	for i, e := range entries {
		if err := c.applyOne(e); err != nil {
			return fmt.Errorf("entry %d failed [%s %s]: %w", i, e.Set, e.IP, err)
		}
	}
	return nil
}

func (c *LinuxClient) applyOne(e Entry) error {
	if e.Set == "" || e.IP == "" {
		return fmt.Errorf("invalid entry: set=%q ip=%q", e.Set, e.IP)
	}
	switch e.Op {
	case OpAdd:
		// -exist 避免重复添加报错
		args := []string{"add", e.Set, e.IP, "-exist"}
		// blacklist 条目可带 timeout，内核到期自动清除
		if e.Set == SetBlacklist && e.Timeout > 0 {
			args = append(args, "--timeout", fmt.Sprintf("%d", e.Timeout))
		}
		return c.run(c.Bin, args...)
	case OpDel:
		// -exist: 条目不存在时静默返回 0，避免与 kernel timeout 竞态
		// （内核已删除条目但内存 blocked map 还在 → Sweep Unblock 重试失败）
		return c.run(c.Bin, "del", e.Set, e.IP, "-exist")
	default:
		return fmt.Errorf("unknown op %d", e.Op)
	}
}

// Exists 查询 IP 是否在指定集合中。
func (c *LinuxClient) Exists(set, ip string) (bool, error) {
	err := c.run(c.Bin, "test", set, ip)
	if err == nil {
		return true, nil
	}
	// exit code 1 表示不存在
	return false, nil
}

// List 返回指定集合全部成员。
func (c *LinuxClient) List(set string) ([]string, error) {
	out, err := c.runOutput(c.Bin, "list", "set", set)
	if err != nil {
		return nil, err
	}
	return parseListOutput(out), nil
}

// run 执行命令并返回错误。错误信息包含 stderr，便于定位 ipset 拒绝原因。
func (c *LinuxClient) run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// 将 stderr 附带到错误信息中，方便日志排查（如裸 IPv6 被 hash:net 拒绝）
		if stderr.Len() > 0 {
			return fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
		}
		return err
	}
	return nil
}

// runOutput 执行命令并返回 stdout。
func (c *LinuxClient) runOutput(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return stdout.Bytes(), nil
}

// parseListOutput 解析 `ipset list set_name` 输出。
func parseListOutput(out []byte) []string {
	s := string(out)
	lines := strings.Split(s, "\n")
	var members []string
	inMembers := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "Members:" {
			inMembers = true
			continue
		}
		if inMembers {
			if trimmed == "" {
				break
			}
			members = append(members, trimmed)
		}
	}
	return members
}
