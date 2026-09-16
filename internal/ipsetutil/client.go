// Package ipsetutil 管理本地防火墙黑白名单。
// 提供底层 Client 接口（Linux ipset 实现 + 内存 Mock 实现）与 Manager 业务封装。
package ipsetutil

// SetName 内置集合名。phase 1 仅本地使用，集合名固定。
const (
	SetBlacklist = "wardennet_blacklist"
	SetWhitelist = "wardennet_whitelist"
)

// Op 操作类型。
type Op int

const (
	OpAdd Op = iota // 加入集合
	OpDel           // 从集合删除
)

// Entry 待执行的单条变更。
type Entry struct {
	Set     string // SetBlacklist / SetWhitelist
	IP      string // IPv4/IPv6/CIDR
	Op      Op
	Timeout int // ipset --timeout 秒数，0 表示不设（内核默认值）。仅 blacklist add 生效。
}

// Client 底层 ipset 客户端接口。Linux 真实实现与内存 Mock 都满足此接口。
type Client interface {
	// EnsureSet 确保集合存在，不存在则创建。
	EnsureSet(name string) error
	// Apply 原子应用一批变更；失败返回 error。
	Apply(entries []Entry) error
	// Exists 查询 IP 是否在指定集合中。
	Exists(set, ip string) (bool, error)
	// List 返回指定集合全部成员（用于快照/调试）。
	List(set string) ([]string, error)
}
