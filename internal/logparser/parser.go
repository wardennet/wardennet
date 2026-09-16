// Package logparser 实现 4 种内置日志解析器与统一 tail 续读。
// 所有解析器输出统一的 Event 结构，供后续滑动窗口检测引擎消费。
package logparser

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// Source 名称常量，与 config.LogSource.Parser 对齐。
const (
	SourceNginxAccess  = "nginx_access"
	SourceApacheAccess = "apache_access"
	SourceTomcatAccess = "tomcat_access"
	SourceLinuxAuth    = "linux_auth"
)

// Event 是所有解析器输出的统一结构。
// LocalRiskScore 由滑动窗口检测引擎（任务3）填充，解析器置 0。
type Event struct {
	Timestamp      time.Time // 解析出的请求时间；无时间字段时用当前时间
	SourceIP       string    // 客户端 IP（IPv4/IPv6/hostname）
	Source         string    // 来源 parser 名（nginx_access 等）
	RawLine        string    // 原始日志行，用于审计与上报
	Method         string    // HTTP 方法（GET/POST 等），非 HTTP 日志为空
	Path           string    // HTTP 请求路径，非 HTTP 日志为空
	Status         int       // HTTP 状态码，非 HTTP 日志为 0
	BytesSent      int64     // 响应字节数
	UserAgent      string    // User-Agent
	Referer        string    // Referer
	AuthAction     string    // linux_auth 专用：Failed password / Accepted password / Invalid user 等
	AuthUser       string    // linux_auth 专用：登录用户名
	LocalRiskScore int       // 滑动窗口打分（任务3 填充）

	// v1.0 新增：请求体扫描 + 文件上传拦截
	Body        string // POST 请求体（Nginx $request_body 解析）
	ContentType string // Content-Type 头
	FileName    string // multipart 上传文件名
	FileExt     string // 上传文件扩展名（含点）
	FileMime    string // 上传文件 MIME 类型

	// v1.1 新增：Cloudflare / 代理场景下的双 IP 识别
	// EdgeIP 是 Agent 直接看到的来源 IP（Nginx $remote_addr），即边缘代理节点 IP。
	// 当使用 Cloudflare CDN 时，EdgeIP 就是 Cloudflare 节点 IP；直连场景下 EdgeIP == SourceIP。
	EdgeIP string
	// ClientIPFrom 标记 SourceIP（真实 IP）的提取来源，用于云端做决策时判断可信度。
	// 取值：direct / xff / cf_connecting_ip / true_client_ip
	ClientIPFrom string

	// v1.2 新增：Tail 层检测到日志截断/轮转时标记为 true。
	// 由 tail.go 在 inode 变化 / size 变小时批量设置（通常影响轮转后第一批 Event）。
	// 用于 detector / cloudplugin 判断当前批次数据是否有缺失风险。
	Truncated bool
}

// Parser 解析单行日志为 Event。
// 实现应返回 (Event, nil) 或 (zero, ErrUnparsable)。
type Parser interface {
	Name() string
	Parse(line string) (Event, error)
}

// ErrUnparsable 表示该行无法被当前解析器解析（格式不符）。
// 调用方可选择跳过或交给其他解析器尝试。
var ErrUnparsable = errors.New("log line unparsable")

// Registry 解析器注册表，按名字查找。
// 线程安全；注册后不可覆盖。
type Registry struct {
	mu      sync.RWMutex
	parsers map[string]Parser
}

// NewRegistry 返回含全部内置解析器的注册表。
func NewRegistry() *Registry {
	r := &Registry{parsers: make(map[string]Parser, 4)}
	r.Register(&nginxParser{})
	r.Register(&apacheParser{})
	r.Register(&tomcatParser{})
	r.Register(&linuxAuthParser{})
	return r
}

// Register 注册解析器。重复名返回 error，避免覆盖内置解析器。
func (r *Registry) Register(p Parser) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := p.Name()
	if _, exists := r.parsers[name]; exists {
		return fmt.Errorf("parser %q already registered", name)
	}
	r.parsers[name] = p
	return nil
}

// RegisterCustom 基于用户配置的正则和分组创建并注册自定义解析器。
// name: 解析器名称（对应 config 中的 parser 字段）
// regexStr: 正则表达式
// groups: 字段分组索引映射
func (r *Registry) RegisterCustom(name, regexStr string, groups map[string]int) error {
	p, err := NewCustomParser(name, regexStr, groups)
	if err != nil {
		return err
	}
	return r.Register(p)
}

// Get 按名字查找解析器。
func (r *Registry) Get(name string) (Parser, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.parsers[name]
	return p, ok
}

// Names 返回已注册的全部解析器名。
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.parsers))
	for n := range r.parsers {
		names = append(names, n)
	}
	return names
}
