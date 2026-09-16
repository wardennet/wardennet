// Package cli 定义 Agent 本地管理命令的接口与数据结构。
// 命令通过 UnixSocket 以 JSON 形式收发，Agent 进程内部分发执行。
package cli

import "sync"

// 命令名常量（对应 spec §3.4 CLI 子命令）。
const (
	CmdBlockListAdd    = "blocklist.add"
	CmdBlockListDel    = "blocklist.del"
	CmdBlockListStatus = "blocklist.status"
	CmdStatus          = "status"
	CmdReload          = "reload"
)

// Request 来自 CLI 的请求。
type Request struct {
	Command string                 `json:"command"`
	Args    map[string]interface{} `json:"args,omitempty"`
}

// Response 返回给 CLI 的响应。
type Response struct {
	Ok      bool        `json:"ok"`
	Error   string      `json:"error,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Message string      `json:"message,omitempty"`
}

// Handler 命令处理函数类型。
// 返回的 Response 会被序列化写回 UnixSocket。
type Handler func(req Request) Response

// Registry 命令注册表：命令名 -> Handler。
type Registry struct {
	mu       sync.RWMutex
	handlers map[string]Handler
}

// NewRegistry 创建空注册表。
func NewRegistry() *Registry {
	return &Registry{handlers: make(map[string]Handler)}
}

// Register 注册一个命令处理器。同名重复注册会被覆盖。
func (r *Registry) Register(cmd string, h Handler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.handlers[cmd] = h
}

// Dispatch 分发执行指定命令。未知命令返回 not_found。
func (r *Registry) Dispatch(req Request) Response {
	r.mu.RLock()
	h, ok := r.handlers[req.Command]
	r.mu.RUnlock()
	if !ok {
		return Response{Ok: false, Error: "command not found: " + req.Command}
	}
	defer func() {
		if rec := recover(); rec != nil {
			// 防止 handler panic 导致整个 Agent 崩溃
			panic("handler panic: " + stringRecover(rec))
		}
	}()
	return h(req)
}

// stringRecover 将 recover() 返回值转为字符串，兼容 error 与其他类型。
func stringRecover(v interface{}) string {
	switch e := v.(type) {
	case error:
		return e.Error()
	case string:
		return e
	default:
		return "unknown panic"
	}
}

// Registered 返回所有已注册的命令名（用于 status）。
func (r *Registry) Registered() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.handlers))
	for k := range r.handlers {
		out = append(out, k)
	}
	return out
}
