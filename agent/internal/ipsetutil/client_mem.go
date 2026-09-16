package ipsetutil

import (
	"fmt"
	"sort"
	"sync"
)

// MemClient 内存 Mock 实现，用于单元测试与非 Linux 环境降级。
type MemClient struct {
	mu        sync.Mutex
	sets      map[string]map[string]struct{}
	flaky     bool                    // true 时 Apply 随机失败（用于重试测试）
	failOnIPs map[string]struct{}     // 指定哪些 IP 应失败（用于逐条跳过测试）
	noTimeout bool                    // true 时拒绝任何带 Timeout>0 的 OpAdd（模拟旧内核 ipset bug）
}

// NewMemClient 创建内存 Mock 客户端。
func NewMemClient() *MemClient {
	return &MemClient{
		sets:      make(map[string]map[string]struct{}),
		failOnIPs: make(map[string]struct{}),
	}
}

// SetFlaky 开启/关闭故障模式（用于测试降级重试）。
func (c *MemClient) SetFlaky(v bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.flaky = v
}

// SetFailOnIPs 设置指定 IP 的失败列表（用于测试逐条跳过场景）。
// 只有这些 IP 的写入会失败，其他 IP 正常写入。
func (c *MemClient) SetFailOnIPs(ips ...string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failOnIPs = make(map[string]struct{})
	for _, ip := range ips {
		c.failOnIPs[ip] = struct{}{}
	}
}

// SetNoTimeout 开启/关闭 "timeout 不支持" 故障模式（模拟旧内核 ipset bug）。
// 开启后，任何 Timeout>0 的 OpAdd 都会返回 "Kernel error -1"，
// 不带 timeout 的 OpAdd 正常。用于测试 Manager/LinuxClient 的 timeout 降级逻辑。
func (c *MemClient) SetNoTimeout(v bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.noTimeout = v
}

func (c *MemClient) EnsureSet(name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.sets[name]; !ok {
		c.sets[name] = make(map[string]struct{})
	}
	return nil
}

func (c *MemClient) Apply(entries []Entry) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.flaky {
		return fmt.Errorf("mem client flaky: simulated failure")
	}
	for i, e := range entries {
		// noTimeout 故障模式：模拟旧 kernel ipset bug，带 timeout 的 add 失败
		if c.noTimeout && e.Op == OpAdd && e.Timeout > 0 {
			return fmt.Errorf("entry %d failed [%s %s]: ipset: Kernel error received: Unknown error -1 (timeout not supported)",
				i, e.Set, e.IP)
		}
		// 检查是否为指定要失败的 IP
		if _, fail := c.failOnIPs[e.IP]; fail {
			return fmt.Errorf("entry %d failed [%s %s]: simulated IP-specific failure", i, e.Set, e.IP)
		}
		if err := c.applyOneLocked(e); err != nil {
			return fmt.Errorf("entry %d failed [%s %s]: %w", i, e.Set, e.IP, err)
		}
	}
	return nil
}

func (c *MemClient) applyOneLocked(e Entry) error {
	s, ok := c.sets[e.Set]
	if !ok {
		s = make(map[string]struct{})
		c.sets[e.Set] = s
	}
	switch e.Op {
	case OpAdd:
		s[e.IP] = struct{}{}
	case OpDel:
		delete(s, e.IP)
	default:
		return fmt.Errorf("unknown op %d", e.Op)
	}
	return nil
}

func (c *MemClient) Exists(set, ip string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.sets[set]
	if !ok {
		return false, nil
	}
	_, ok2 := s[ip]
	return ok2, nil
}

func (c *MemClient) List(set string) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.sets[set]
	if !ok {
		return nil, nil
	}
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}
