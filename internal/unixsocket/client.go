// Package unixsocket - client.go 实现 Unix Socket 客户端。
// 用于 Agent 二进制内置 CLI 子命令（wardennet status / blocklist add ...）。
// 不依赖 socat/python/curl，纯 Go 实现。
package unixsocket

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
)

// DefaultSocketPath Agent 默认 Unix Socket 路径。
const DefaultSocketPath = "/var/run/wardennet.sock"

// Client Unix Socket 客户端。
type Client struct {
	path    string
	timeout time.Duration
}

// NewClient 创建 Unix Socket 客户端。
// path 为空时使用 DefaultSocketPath。timeout 为 0 时使用默认 5s。
func NewClient(path string, timeout time.Duration) *Client {
	if path == "" {
		path = DefaultSocketPath
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Client{path: path, timeout: timeout}
}

// Send 发送命令到 Agent 并返回原始 JSON 响应。
func (c *Client) Send(cmd string, args map[string]interface{}) (*Response, error) {
	// 检查 socket 是否存在
	if _, err := os.Stat(c.path); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("agent socket 不存在 (%s)，请确认 Agent 正在运行", c.path)
		}
		return nil, fmt.Errorf("检查 socket 失败: %w", err)
	}

	conn, err := net.DialTimeout("unix", c.path, c.timeout)
	if err != nil {
		return nil, fmt.Errorf("连接 Agent 失败: %w", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(c.timeout))

	req := Request{Command: cmd, Args: args}
	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("序列化请求失败: %w", err)
	}
	data = append(data, '\n')

	if _, err := conn.Write(data); err != nil {
		return nil, fmt.Errorf("发送请求失败: %w", err)
	}

	// 逐行读取响应（服务端用 json.NewDecoder 逐行写回）
	dec := json.NewDecoder(conn)
	var resp Response
	if err := dec.Decode(&resp); err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}
	return &resp, nil
}
