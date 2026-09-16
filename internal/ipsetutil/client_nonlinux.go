//go:build !linux
// +build !linux

package ipsetutil

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// LinuxClient 在非 Linux 平台提供退化实现：
//  - EnsureSet 静默返回 nil（不报错，保证业务流程继续）
//  - Apply 尝试执行 ipset 命令，失败时静默忽略
//  - Exists/List 返回空结果
type LinuxClient struct {
	Bin string
}

// NewLinuxClient 在非 Linux 仍返回该结构以保持 API 一致。
func NewLinuxClient(bin string) *LinuxClient {
	if bin == "" {
		bin = "ipset"
	}
	return &LinuxClient{Bin: bin}
}

func (c *LinuxClient) EnsureSet(name string) error {
	return nil
}

func (c *LinuxClient) Apply(entries []Entry) error {
	for i, e := range entries {
		if err := c.applyOne(e); err != nil {
			// 非 Linux 下静默忽略错误
			_ = i
			continue
		}
	}
	return nil
}

func (c *LinuxClient) applyOne(e Entry) error {
	if e.Set == "" || e.IP == "" {
		return fmt.Errorf("invalid entry: set=%q ip=%q", e.Set, e.IP)
	}
	var args []string
	switch e.Op {
	case OpAdd:
		args = []string{"add", e.Set, e.IP, "-exist"}
		// 非 Linux 平台尝试传递 timeout 参数（若 ipset 不存在则静默忽略）
		if e.Set == SetBlacklist && e.Timeout > 0 {
			args = append(args, "--timeout", fmt.Sprintf("%d", e.Timeout))
		}
	case OpDel:
		args = []string{"del", e.Set, e.IP}
	default:
		return fmt.Errorf("unknown op %d", e.Op)
	}
	cmd := exec.Command(c.Bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	_ = cmd.Run()
	return nil
}

func (c *LinuxClient) Exists(set, ip string) (bool, error) {
	return false, nil
}

func (c *LinuxClient) List(set string) ([]string, error) {
	return nil, nil
}

// parseListOutput 保留供可能的测试使用。
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
