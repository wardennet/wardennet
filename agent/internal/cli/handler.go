// Package cli - handler.go 实现 Agent 内置命令（blocklist/status/reload 等）的 Handler。
// 本文件仅依赖本包定义的接口（IPSetManager/StatusInfo/Reloader），由上层在 main 中注入。
package cli

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"time"
)

// ----- 依赖接口（由上层注入） -----

// IPSetManager ipset 管理器抽象。
// 与 ipsetutil.Manager 接口对齐，便于单元测试 Mock。
type IPSetManager interface {
	Block(ip string) (accepted bool, err error)
	ForceBlock(ip string) (accepted bool, err error)
	Unblock(ip string) error
	IsLocalWhitelisted(ip string) bool
	LocalBlockedCount() int
	LocalWhitelistCount() int
	ApplyCloud(entries []CloudEntry) ([]CloudEntry, error)
	SyncLocalWhitelist(items []string) error
}

// CloudEntry 云端下发变更（镜像 ipsetutil.Entry 结构）。
type CloudEntry struct {
	Set string
	IP  string
	Op  OpType
}

// OpType 操作类型（镜像 ipsetutil.Op）。
type OpType int

const (
	OpAdd OpType = iota
	OpDel
)

// TTLManager TTL 管理器抽象。
type TTLManager interface {
	Add(ip string, ttl int, source int) (int, error)
	Remove(ip string) *TTLEntry
	Count() int
}

// TTLEntry TTL 条目（镜像 ttl.Entry）。
type TTLEntry struct {
	IP        string
	Source    int
	ExpiresAt int64
	CreatedAt int64
	TTL       int
}

// Source 常量（镜像 ttl.Source）。
const (
	SourceLocal = 0
	SourceCloud = 1
)

// StatusInfo 提供 Agent 运行状态。
type StatusInfo interface {
	GetStatus() map[string]interface{}
}

// Reloader 支持热加载。
type Reloader interface {
	Reload() error
}

// ----- Handler 实现 -----

// BlocklistHandler 处理 blocklist.add / blocklist.del 命令。
type BlocklistHandler struct {
	IPSet  IPSetManager
	TTL    TTLManager
	Status StatusInfo
}

// NewBlocklistHandler 创建 blocklist Handler。
func NewBlocklistHandler(ipm IPSetManager, ttm TTLManager, si StatusInfo) *BlocklistHandler {
	return &BlocklistHandler{IPSet: ipm, TTL: ttm, Status: si}
}

// Add 注册所有命令到 Registry。
func (h *BlocklistHandler) Register(reg *Registry) {
	reg.Register(CmdBlockListAdd, h.blocklistAdd)
	reg.Register(CmdBlockListDel, h.blocklistDel)
	reg.Register(CmdBlockListStatus, h.blocklistStatus)
}

func (h *BlocklistHandler) blocklistAdd(req Request) Response {
	ip, ok := req.Args["ip"].(string)
	if !ok || ip == "" {
		return errResp("missing or invalid 'ip' arg")
	}
	if !isValidIP(ip) {
		return errResp(fmt.Sprintf("invalid ip: %s", ip))
	}

	force, _ := req.Args["force"].(bool)
	if !force && h.IPSet.IsLocalWhitelisted(ip) {
		return Response{Ok: false, Error: "SKIP: ip in local whitelist", Data: map[string]interface{}{
			"ip":       ip,
			"accepted": false,
			"reason":   "local_whitelist_skip",
		}}
	}

	// 默认 TTL 0，由 Manager 使用本地默认
	ttlSec := 0
	if raw, ok := req.Args["ttl"]; ok {
		switch v := raw.(type) {
		case float64:
			ttlSec = int(v)
		case int:
			ttlSec = v
		}
	}

	// force 时使用 ForceBlock 绕过白名单
	var accepted bool
	var err error
	if force {
		accepted, err = h.IPSet.ForceBlock(ip)
	} else {
		accepted, err = h.IPSet.Block(ip)
	}
	if err != nil {
		return errResp(err.Error())
	}

	// 已在黑名单中：直接返回幂等成功
	if !accepted {
		return Response{Ok: true, Message: "already blocked", Data: map[string]interface{}{
			"ip":       ip,
			"accepted": false,
		}}
	}

	// 成功：写入 TTL
	var ttlApplied int
	if h.TTL != nil {
		ttlApplied, _ = h.TTL.Add(ip, ttlSec, SourceLocal)
	}
	return Response{Ok: true, Data: map[string]interface{}{
		"ip":        ip,
		"accepted":  true,
		"ttl":       ttlApplied,
		"expires_at": time.Now().Unix() + int64(ttlApplied),
	}}
}

func (h *BlocklistHandler) blocklistDel(req Request) Response {
	ip, ok := req.Args["ip"].(string)
	if !ok || ip == "" {
		return errResp("missing or invalid 'ip' arg")
	}
	if !isValidIP(ip) {
		return errResp(fmt.Sprintf("invalid ip: %s", ip))
	}

	if err := h.IPSet.Unblock(ip); err != nil {
		return errResp(err.Error())
	}
	if h.TTL != nil {
		_ = h.TTL.Remove(ip)
	}
	return Response{Ok: true, Data: map[string]interface{}{
		"ip": ip,
	}}
}

func (h *BlocklistHandler) blocklistStatus(req Request) Response {
	data := map[string]interface{}{
		"timestamp": time.Now().Unix(),
	}
	if h.IPSet != nil {
		data["blocked_count"] = h.IPSet.LocalBlockedCount()
		data["whitelist_count"] = h.IPSet.LocalWhitelistCount()
	}
	if h.TTL != nil {
		data["ttl_entries"] = h.TTL.Count()
	}
	if h.Status != nil {
		for k, v := range h.Status.GetStatus() {
			data[k] = v
		}
	}
	return Response{Ok: true, Data: data}
}

// StatusHandler 返回 Agent 整体运行状态。
type StatusHandler struct {
	Status  StatusInfo
	Version string
}

// NewStatusHandler 创建 Status Handler。
func NewStatusHandler(si StatusInfo, version string) *StatusHandler {
	return &StatusHandler{Status: si, Version: version}
}

// Register 注册 status 命令。
func (s *StatusHandler) Register(reg *Registry) {
	reg.Register(CmdStatus, func(req Request) Response {
		data := map[string]interface{}{
			"version":   s.Version,
			"timestamp": time.Now().Unix(),
		}
		if s.Status != nil {
			for k, v := range s.Status.GetStatus() {
				data[k] = v
			}
		}
		return Response{Ok: true, Data: data}
	})
}

// ReloadHandler 配置热加载。
type ReloadHandler struct {
	Reloader Reloader
}

// NewReloadHandler 创建 Reload Handler。
func NewReloadHandler(r Reloader) *ReloadHandler {
	return &ReloadHandler{Reloader: r}
}

// Register 注册 reload 命令。
func (r *ReloadHandler) Register(reg *Registry) {
	reg.Register(CmdReload, func(req Request) Response {
		if r.Reloader == nil {
			return errResp("reloader not configured")
		}
		if err := r.Reloader.Reload(); err != nil {
			return errResp(err.Error())
		}
		return Response{Ok: true, Message: "reloaded successfully"}
	})
}

// ----- 辅助 -----

// errResp 构造错误响应。
func errResp(msg string) Response {
	return Response{Ok: false, Error: msg}
}

// isValidIP 校验 IP/CIDR 合法性。
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

// ArgsToMap 将 json.RawMessage / interface{} 转换为方便读取的 map[string]interface{}。
// 当 CLI 通过 --args '{"ip":"1.1.1.1"}' 传入时，Request.Args 为 map[string]interface{}；
// 本函数主要用于未来扩展。
func ArgsToMap(raw json.RawMessage) (map[string]interface{}, error) {
	out := make(map[string]interface{})
	if len(raw) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// SortedKeys 返回 map 的有序键列表（便于测试与稳定输出）。
func SortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
