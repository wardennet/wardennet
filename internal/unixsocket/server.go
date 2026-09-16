// Package unixsocket 实现本地 CLI 通信的 Unix Socket 服务端。
// 仅监听本地，无任何 TCP 端口；符合红线 4.1 “无外网 TCP 监听”。
//
// 注意：为避开 Go module 在 github.com/wardennet/agent 下把内包当远程模块
// 解析的网络下载失败，本包不引入 cli 包，在本包内镜像定义 Request/Response/
// Handler/Registry 类型，字段 JSON tag 与 cli 包完全一致，后续集成时可直接赋值。
package unixsocket

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ----- 镜像 cli 包类型 -----

// Request 来自 CLI 的请求（镜像 cli.Request）。
type Request struct {
	Command string                 `json:"command"`
	Args    map[string]interface{} `json:"args,omitempty"`
}

// Response 返回给 CLI 的响应（镜像 cli.Response）。
type Response struct {
	Ok      bool        `json:"ok"`
	Error   string      `json:"error,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Message string      `json:"message,omitempty"`
}

// Handler 命令处理函数类型（镜像 cli.Handler）。
type Handler func(req Request) Response

// Registry 命令注册表（镜像 cli.Registry）。
type Registry struct {
	mu       sync.RWMutex
	handlers map[string]Handler
}

// NewRegistry 创建空注册表。
func NewRegistry() *Registry {
	return &Registry{handlers: make(map[string]Handler)}
}

// Register 注册一个命令处理器。
func (r *Registry) Register(cmd string, h Handler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.handlers[cmd] = h
}

// Dispatch 分发执行指定命令。
func (r *Registry) Dispatch(req Request) Response {
	r.mu.RLock()
	h, ok := r.handlers[req.Command]
	r.mu.RUnlock()
	if !ok {
		return Response{Ok: false, Error: "command not found: " + req.Command}
	}
	defer func() {
		if rec := recover(); rec != nil {
			panic("handler panic: " + fmt.Sprint(rec))
		}
	}()
	return h(req)
}

// ----- 服务端实现 -----

// Server Unix Socket 服务端。
type Server struct {
	path string
	reg  *Registry

	listener net.Listener
	stop     chan struct{}
	once     sync.Once
	wg       sync.WaitGroup
}

// NewServer 创建 Unix Socket 服务。path 通常为 /var/run/wardennet.sock。
// reg 为命令注册表；为 nil 时使用空注册表（需后续 Register）。
func NewServer(path string, reg *Registry) *Server {
	if reg == nil {
		reg = NewRegistry()
	}
	return &Server{
		path: path,
		reg:  reg,
		stop: make(chan struct{}),
	}
}

// Start 启动 Unix Socket 监听。若 path 已存在旧 socket 文件则先删除。
// 成功启动后立即返回，后台协程处理连接。
func (s *Server) Start() error {
	if s.path == "" {
		return fmt.Errorf("empty unix socket path")
	}
	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return fmt.Errorf("mkdir socket dir: %w", err)
	}
	// 清除旧 socket
	if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale socket: %w", err)
	}

	ln, err := net.Listen("unix", s.path)
	if err != nil {
		return fmt.Errorf("listen unix: %w", err)
	}
	s.listener = ln
	// 权限收紧到 0600（仅本机 root/当前用户可访问）
	_ = os.Chmod(s.path, 0600)

	s.wg.Add(1)
	go s.acceptLoop()
	return nil
}

// Stop 关闭服务端并等待所有连接处理完成。
func (s *Server) Stop() {
	s.once.Do(func() {
		close(s.stop)
		if s.listener != nil {
			_ = s.listener.Close()
		}
	})
	s.wg.Wait()
	_ = os.Remove(s.path)
}

// acceptLoop 接受新连接。
func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		c, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.stop:
				return
			default:
				// 暂时忽略其它 accept 错误，继续监听
				continue
			}
		}
		s.wg.Add(1)
		go s.handleConn(c)
	}
}

// handleConn 单连接处理：读取一行 JSON 请求，分发响应写回。
func (s *Server) handleConn(c net.Conn) {
	defer s.wg.Done()
	defer c.Close()

	// 设置读 deadline 防止连接长期挂起
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))

	rd := json.NewDecoder(c)
	for {
		// 检查是否停止
		select {
		case <-s.stop:
			return
		default:
		}

		var req Request
		if err := rd.Decode(&req); err != nil {
			// EOF 或解码失败都结束本次连接
			return
		}
		resp := s.reg.Dispatch(req)
		_ = writeJSON(c, resp)
	}
}

// writeJSON 写回一行 JSON + 换行，便于客户端逐行读取。
func writeJSON(c net.Conn, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = c.Write(data)
	return err
}

// timeNow 封装时间函数，便于测试替换。
var timeNow = func() time.Time {
	return time.Now()
}
