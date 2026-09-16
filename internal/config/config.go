// Package config 定义 WardenNet Agent 的全部配置结构与默认值。
// 所有运行时可调参数（TTL、日志路径、UnixSocket 路径、日志源开关）均从此处 YAML 解析，禁止硬编码到业务代码。
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// LogLevel 日志级别，与 log/slog.Level 对齐。
type LogLevel string

const (
	LevelDebug LogLevel = "debug"
	LevelInfo  LogLevel = "info"
	LevelWarn  LogLevel = "warn"
	LevelError LogLevel = "error"
)

// LogSource 单个日志源的解析与上报开关配置。
// AllowUpload 控制证据是否上报云端；linux_auth 默认 false（合规要求）。
// 用 *bool 区分「未声明」与「显式 false」，避免 YAML 零值覆盖默认值。
// CustomRegex 允许用户指定自定义日志格式的正则表达式，用于支持非标准格式。
// RegexGroups 指定正则中各字段的分组索引（从 1 开始），用于从匹配结果中提取字段。
type LogSource struct {
	Path        string            `yaml:"path"`
	Parser      string            `yaml:"parser"`       // nginx_access / apache_access / tomcat_access / linux_auth
	AllowUpload *bool             `yaml:"allow_upload"` // 指针；nil 表示未声明，沿用默认
	CustomRegex string            `yaml:"custom_regex"` // 自定义日志格式正则（可选，覆盖内置解析器）
	RegexGroups map[string]int    `yaml:"regex_groups"` // 正则分组索引映射（可选）
}

// IsAllowUpload 返回是否允许上报。nil 时按非 linux_auth 源视为 true。
// linux_auth 的 false 由 Default() 显式设置，本方法天然返回正确值。
func (s LogSource) IsAllowUpload() bool {
	if s.AllowUpload == nil {
		return true
	}
	return *s.AllowUpload
}

// HasCustomRegex 返回是否配置了自定义正则表达式。
func (s LogSource) HasCustomRegex() bool {
	return s.CustomRegex != ""
}

// GetRegexGroup 返回指定字段的正则分组索引。
// 支持的字段名：ip, time, request, status, bytes, referer, uagent, xff
// 返回 0 表示未配置该字段。
func (s LogSource) GetRegexGroup(field string) int {
	if s.RegexGroups == nil {
		return 0
	}
	return s.RegexGroups[field]
}

// AgentSection Agent 本地 TTL 与云端 TTL 上限。
// CloudMaxTTL 用于校验云端下发等级最大 TTL，Phase 2 启用截断逻辑。
type AgentSection struct {
	LocalBlockTTL int `yaml:"local_block_ttl"` // 秒，本地拉黑默认 TTL
	CloudBlockTTL int `yaml:"cloud_block_ttl"` // 秒，云端下发拉黑 TTL 上限
	CloudMaxTTL   int `yaml:"cloud_max_ttl"`   // 秒，云端下发等级最大 TTL 上限，Phase 2 启用校验
}

// LogSection 日志输出配置。File 为空则仅输出到 stdout。
type LogSection struct {
	Level      string `yaml:"level"`       // debug/info/warn/error
	File       string `yaml:"file"`        // 日志文件路径，空则仅 stdout
	MaxSize    int    `yaml:"max_size"`    // 单文件最大 MB
	MaxBackups int    `yaml:"max_backups"` // 保留旧文件数
	MaxAge     int    `yaml:"max_age"`     // 旧文件保留天数
	Compress   bool   `yaml:"compress"`    // 旧文件 gzip 压缩
}

// StatsSection 统计报告配置。
type StatsSection struct {
	ReportInterval int `yaml:"report_interval"` // 报告间隔（秒），0 表示禁用统计报告
}

// UnixSocketSection 本地 CLI 通信 UnixSocket 路径。
type UnixSocketSection struct {
	Path string `yaml:"path"` // 默认 /var/run/wardennet.sock
}

// DetectorWindow 单个滑动窗口配置。可通过 YAML 覆盖三档默认值。
type DetectorWindow struct {
	Size int `yaml:"size"`
}

// DetectorSection 本地滑动窗口检测引擎配置。
// 关键参数（窗口、阈值、权重）全部可调，禁止硬编码到业务代码。
// 三档窗口并行统计，任一窗口超限则累计 LocalRiskScore 权重。
//
// 防误杀机制（多层防御）：
//  1. 空 Referer 佐证信号：仅当空 Referer 是唯一可疑信号时降级 80%（scorer.go 实现）
//  2. 已知 HTTP 客户端 UA 白名单：okhttp/python-requests 等不判定为 Bot（window.go 实现）
//  3. 敏感路径状态码关联：仅统计 status >= 400 的敏感路径命中（window.go 实现）
//  4. 路径段精确匹配：env 不匹配 env.js，admin 不匹配 admin.js（window.go 实现）
//  5. 真实用户奖励：静态资源 + 有效 Referer 双维度扣分（scorer.go 实现）
//  6. 本地 IP 白名单：命中白名单直接跳过检测（detector.go 实现）
//  7. 跳过路径列表：浏览器常规行为（favicon/robots.txt 等）完全不参与检测（detector.go 实现）
type DetectorSection struct {
	Enabled     bool              `yaml:"enabled"`     // 总开关；关闭后仍产出 Event 但不计分
	Mode        string            `yaml:"mode"`        // block(默认) = 正常封禁；report = 只评分上报不封禁
	ScoreHigh   int               `yaml:"score_high"`  // 高分阈值：>= 此分触发本地拉黑候选
	ScoreMedium int               `yaml:"score_medium"` // 中等风险阈值：>= 此分进入观察名单
	ScoreLow    int               `yaml:"score_low"`    // 低风险阈值：>= 此分记录评分
	Sensitivity string            `yaml:"sensitivity"` // high / medium(默认) / low；控制评分触发门槛
	Weights     ScoreWeights      `yaml:"weights"`     // 各特征权重
	Windows     [3]DetectorWindow `yaml:"windows"`     // 三档窗口，默认 [10, 30, 60] 秒

	// 可配置特征列表（三段式合并：内置默认 + 本地配置 + 云端拉取，支持排除项）
	// 格式一（简单列表，向后兼容）：known_http_clients: ["okhttp", "python-requests"]
	// 格式二（结构化，支持排除项和云端控制）：
	//   known_http_clients:
	//     local: ["okhttp", "python-requests"]
	//     excludes: ["internal-api"]
	//     disable_builtin: false
	//     disable_cloud: false
	KnownHTTPClients  FlexibleFeatureList `yaml:"known_http_clients"`
	SensitivePaths    FlexibleFeatureList `yaml:"sensitive_paths"`
	DangerousPatterns FlexibleFeatureList `yaml:"dangerous_patterns"`

	// 跳过路径列表：匹配的路径完全不参与检测（不计分、不拉黑）。
	// 支持两种匹配模式：
	//   - 精确匹配：如 "/favicon.ico"、"/robots.txt"
	//   - 前缀匹配：以 "/" 结尾，如 "/.well-known/" 匹配该前缀下所有路径
	// 大小写不敏感，自动去除 query string 后匹配。
	// 默认值：/favicon.ico, /favicon.png, /robots.txt, /.well-known/
	SkipPaths []string `yaml:"skip_paths"`

	// v1.0 新增：请求体扫描配置
	BodyScan BodyScanCfg `yaml:"body_scan"`

	// v1.0 新增：IDOR/BOLA 越权检测配置（默认关闭）
	ResourceBaseline ResourceBaselineCfg `yaml:"resource_baseline"`

	// v1.2 新增：Consistency 5 维行为评分的阈值/权重/工程参数。
	// 使用 yaml.Node 接收原始 YAML 节点，由 adapter 层 Unmarshal 到 detector.ConsistencyThresholds。
	// 留空（不声明 consistency）则全部使用程序默认值，生产行为零变化。
	// 调参场景：纯 API 站（降低 path_concentrated_threshold）、
	// SPA 富前端（放宽 novelty_early30_min）、内部 RPA 客户端（降低 score_threshold）。
	Consistency *yaml.Node `yaml:"consistency"`

	// v1.2 新增：可信内网网段配置。
	// 命中此列表的 IP 正常参与 SlidingWindow 计数（保留基线数据），
	// 但跳过 Consistency BENIGN 降权 gate（防止 API 网关/K8s Pod 等内部流量
	// 被误判为"路径极集中的扫描器"）。
	// 与白名单的区别：白名单是"零检测 + 永不封禁"，TrustedSubnet 是"轻量化检测"。
	// 默认空列表（不启用），需要用户显式配置。
	TrustedSubnets []string `yaml:"trusted_subnets"`

	// v1.3 新增：蜜罐路径列表（触之必死）。
	// 扫描器一定会扫 /admin、/.env、/phpmyadmin 等路径——命中即判定为恶意扫描。
	// 与 SensitivePaths（基线偏离评分）不同：蜜罐命中是绝对判定，
	// 直接触发封禁（绕过多事件确认、绕过 Consistency 降权 gate）。
	// 支持两种匹配模式（与 skip_paths 一致）：
	//   - 精确匹配："/admin" 只匹配 "/admin"
	//   - 前缀匹配："/traps/" 匹配该前缀下所有路径
	// 默认空列表（不启用），需要用户显式配置。
	// 严禁配置真实业务路径——蜜罐路径与 SkipPaths 重叠时启动时会 WARN 但不阻塞。
	HoneypotPaths []string `yaml:"honeypot_paths"`
}

// v1.0 新增配置结构 —— 纯 YAML 解析用，无外部依赖

// BodyScanCfg 请求体扫描配置（JSON/Form/XML/XXE/文件上传）。
type BodyScanCfg struct {
	Enabled      bool     `yaml:"enabled"`
	MaxBodySize  int64    `yaml:"max_body_size"`   // 字节，默认 1MB
	ContentTypes []string `yaml:"content_types"`
	FileUpload   FileUploadCfg `yaml:"file_upload"`
}

// FileUploadCfg 文件上传安全检测配置。
type FileUploadCfg struct {
	BlockedExtensions []string `yaml:"blocked_extensions"` // 含点：.php, .phtml
	BlockedMimeTypes  []string `yaml:"blocked_mime_types"`
}

// ResourceBaselineCfg IDOR/BOLA 越权检测配置。
// 默认关闭（Enabled=false），用户显式开启。
type ResourceBaselineCfg struct {
	Enabled  bool             `yaml:"enabled"`
	Patterns []ResourcePatternCfg `yaml:"patterns"`
}

// ResourcePatternCfg 单个资源基线模式配置。
type ResourcePatternCfg struct {
	PathRegex string `yaml:"path_regex"`
	IDRegex   string `yaml:"id_regex"`
	WindowSec int    `yaml:"window_sec"`
	MaxIDs    int    `yaml:"max_ids"`
	Weight    int    `yaml:"weight"`
}

// PortScanCfg 端口扫描检测配置（v1.0 新增顶级 section）。
type PortScanCfg struct {
	Enabled    bool           `yaml:"enabled"`
	Source     string         `yaml:"source"`      // auto | iptables | pcap | disabled
	LogPath    string         `yaml:"log_path"`
	LogPrefix  string         `yaml:"log_prefix"`
	BlockTTL   int            `yaml:"block_ttl"`
	Weight     int            `yaml:"weight"`
	PcapIface  string         `yaml:"pcap_iface"`
	PcapFilter string         `yaml:"pcap_filter"`
	Windows    [3]PortWindowCfg `yaml:"windows"`
}

// PortWindowCfg 端口扫描单档窗口配置。
type PortWindowCfg struct {
	Size     int `yaml:"size"`
	MaxPorts int `yaml:"max_ports"`
}

// ScoreWeights 绝对特征权重（基线自学习引擎使用）。
// 仅保留绝对可判定特征，相对特征由基线自动适配。
type ScoreWeights struct {
	DangerousPattern int `yaml:"dangerous_pattern"` // 危险攻击模式（解码后匹配）
	DangerousMethod  int `yaml:"dangerous_method"`  // 危险 HTTP 方法（CONNECT/TRACE/DELETE/PUT/PATCH/OPTIONS）
	FileUpload       int `yaml:"file_upload"`       // 文件上传风险权重
}

// IPSetSection 本地配置的白名单/黑名单列表。
// 优先级：本地配置白名单 > 云端全局/租户白名单 > 其他黑名单。
type IPSetSection struct {
	Whitelist []string `yaml:"whitelist"` // 本地配置白名单 IP/CIDR 列表
	Blacklist []string `yaml:"blacklist"` // 本地配置黑名单 IP/CIDR 列表（断网模式兜底）
}

// CloudSection 云端 SaaS 对接配置。
// 云端能力完全通过 plugin.Plugin 接口实现，Agent 不直接发 HTTP 请求。
// Plugin 为 NoopPlugin（无插件）时自动降级为纯本地运行（本配置可全部留空）。
type CloudSection struct {
	Enabled    bool   `yaml:"enabled"`      // 是否启用云端对接（需同时有 Plugin 才生效；false 时 cloudsync 引擎直接跳过）
	BaseURL    string `yaml:"base_url"`     // 云端 SaaS 地址（如 https://api.wardenet.io）
	TenantID   string `yaml:"tenant_id"`    // 租户标识（云端注册后获得）
	AgentSecret string `yaml:"agent_secret"` // Agent 密钥（云端注册后获取，HMAC 鉴权用）

	// 插件路径（覆盖 plugin.DefaultPluginPath /usr/lib/wardennet/libcloudplugin.so）
	PluginPath string `yaml:"plugin_path"`

	// 同步参数（V0.1 轮询模式；V1.0 将升级 wait-notify，interval 退化为 fallback 兜底）
	SyncInterval      int `yaml:"sync_interval"`       // Diff 拉取间隔（秒，默认 600 = 10min）
	HeartbeatInterval int `yaml:"heartbeat_interval"`  // 心跳间隔（秒，默认 300 = 5min）
	CommandInterval   int `yaml:"command_interval"`    // 远程指令轮询间隔（秒，默认 120 = 2min）
	FeatureInterval   int `yaml:"feature_interval"`    // 特征值云同步间隔（秒，默认 600 = 10min）
}

// AgentConfig Agent 主配置根结构。
type AgentConfig struct {
	Agent      AgentSection            `yaml:"agent"`
	Cloud      CloudSection            `yaml:"cloud"`   // 云端对接配置（v0.1 新增）
	Detector   DetectorSection         `yaml:"detector"`
	IPSet      IPSetSection            `yaml:"ipset"`
	LogSources map[string]LogSource    `yaml:"log_sources"`
	Log        LogSection              `yaml:"log"`
	Stats      StatsSection            `yaml:"stats"`
	UnixSocket UnixSocketSection       `yaml:"unix_socket"`
	PortScan   PortScanCfg             `yaml:"port_scan"` // v1.0 新增顶级 section
}

// Default 返回带默认值的配置。Linux Auth 默认 allow_upload=false 落实数据最小化合规。
func Default() AgentConfig {
	t := true
	f := false
	return AgentConfig{
		Agent: AgentSection{
			LocalBlockTTL: 3600,  // 1 小时
			CloudBlockTTL: 7200,  // 2 小时
			CloudMaxTTL:   86400, // 1 天，Phase 2 校验上限
		},
		Detector: DetectorSection{
			Enabled:     true,
			Mode:        "block",
			ScoreHigh:   50,
			ScoreMedium: 30,
			ScoreLow:    10,
			Sensitivity: "medium",
			Weights: ScoreWeights{
				DangerousPattern: 5,
				DangerousMethod:  3,
				FileUpload:       20,
			},
			Windows: [3]DetectorWindow{
				{Size: 10},
				{Size: 30},
				{Size: 60},
			},
			SkipPaths: []string{"/favicon.ico", "/favicon.png", "/robots.txt", "/.well-known/"},
		},
		IPSet: IPSetSection{
			Whitelist: []string{"127.0.0.1", "::1"}, // 本地回环默认豁免
			Blacklist: []string{},
		},
		LogSources: map[string]LogSource{
			"nginx_access":  {Parser: "nginx_access", AllowUpload: &t},
			"apache_access": {Parser: "apache_access", AllowUpload: &t},
			"tomcat_access": {Parser: "tomcat_access", AllowUpload: &t},
			"linux_auth":    {Parser: "linux_auth", AllowUpload: &f}, // 合规：默认不上报
		},
		Log: LogSection{
			Level:      string(LevelInfo),
			File:       "", // 默认仅 stdout
			MaxSize:    100,
			MaxBackups: 7,
			MaxAge:     30,
			Compress:   true,
		},
		Stats: StatsSection{
			ReportInterval: 60, // 默认 60 秒输出一次统计报告
		},
		UnixSocket: UnixSocketSection{
			Path: "/var/run/wardennet.sock",
		},
		// v0.1 新增：云端对接默认值（默认禁用，需显式开启 cloud.enabled=true + 配置 base_url / tenant_id）
		Cloud: CloudSection{
			Enabled:           false,
			BaseURL:           "",
			TenantID:          "",
			AgentSecret:       "",
			PluginPath:        "", // 空 = 使用 plugin.DefaultPluginPath
			SyncInterval:      600, // 10min
			HeartbeatInterval: 300, // 5min
			CommandInterval:   120, // 2min
			FeatureInterval:   600, // 10min
		},
		// v1.0 新增默认值
		PortScan: PortScanCfg{
			Enabled:    false, // 默认关闭，用户显式开启
			Source:     "auto",
			LogPath:    "/var/log/syslog",
			LogPrefix:  "[PORT_SCAN]: ",
			BlockTTL:   3600,
			Weight:     30,
			PcapIface:  "any",
			PcapFilter: "tcp[tcpflags] & tcp-syn != 0",
			Windows: [3]PortWindowCfg{
				{Size: 5, MaxPorts: 5},
				{Size: 30, MaxPorts: 15},
				{Size: 120, MaxPorts: 40},
			},
		},
	}
}

// Validate 校验配置合法性。CloudBlockTTL 与 CloudMaxTTL 的强校验在 Phase 2 启用，
// Phase 1 仅校验非空与基础范围，预留接口。
func (c *AgentConfig) Validate() error {
	if c.Agent.LocalBlockTTL <= 0 {
		return errors.New("agent.local_block_ttl must be positive")
	}
	if c.Agent.CloudBlockTTL <= 0 {
		return errors.New("agent.cloud_block_ttl must be positive")
	}
	if c.Agent.CloudMaxTTL <= 0 {
		return errors.New("agent.cloud_max_ttl must be positive")
	}
	// Phase 2 校验点：cloud_block_ttl 不得超过 cloud_max_ttl，预留接口（暂不强制）
	if c.Agent.CloudBlockTTL > c.Agent.CloudMaxTTL {
		// Phase 1 仅记录可接受，Phase 2 将在此处返回 error。
		// 当前保留以备 Phase 2 启用：return fmt.Errorf("cloud_block_ttl %d exceeds cloud_max_ttl %d", ...)
		_ = fmt.Errorf("cloud_block_ttl %d exceeds cloud_max_ttl %d (will be enforced in Phase 2)",
			c.Agent.CloudBlockTTL, c.Agent.CloudMaxTTL)
	}

	if c.Log.Level != "" {
		switch LogLevel(c.Log.Level) {
		case LevelDebug, LevelInfo, LevelWarn, LevelError:
		default:
			return fmt.Errorf("log.level invalid: %s", c.Log.Level)
		}
	}
	if c.Log.File != "" {
		if err := validateWritableDir(filepath.Dir(c.Log.File)); err != nil {
			return fmt.Errorf("log.file dir: %w", err)
		}
		if c.Log.MaxSize <= 0 {
			return errors.New("log.max_size must be positive")
		}
		if c.Log.MaxBackups < 0 {
			return errors.New("log.max_backups must be non-negative")
		}
		if c.Log.MaxAge < 0 {
			return errors.New("log.max_age must be non-negative")
		}
	}

	if c.UnixSocket.Path == "" {
		return errors.New("unix_socket.path must not be empty")
	}
	if err := validateWritableDir(filepath.Dir(c.UnixSocket.Path)); err != nil {
		return fmt.Errorf("unix_socket.path dir: %w", err)
	}

	for name, src := range c.LogSources {
		if src.Parser == "" {
			return fmt.Errorf("log_sources.%s.parser must not be empty", name)
		}
		// 自定义正则时跳过 parser 校验（因为使用自定义正则解析）
		if src.HasCustomRegex() {
			// 校验自定义正则是否有效
			if _, err := regexp.Compile(src.CustomRegex); err != nil {
				return fmt.Errorf("log_sources.%s.custom_regex invalid: %w", name, err)
			}
			continue
		}
		switch src.Parser {
		case "nginx_access", "apache_access", "tomcat_access", "linux_auth":
		default:
			return fmt.Errorf("log_sources.%s.parser invalid: %s", name, src.Parser)
		}
		// linux_auth 的 allow_upload 默认 false（由 Default 保证）。
		// 用户可显式开启用于审计场景，不强制 false。
	}

	// Detector 校验：已启用时窗口大小必须为正值，权重非负，Sensitivity 合法。
	if c.Detector.Enabled {
		if c.Detector.ScoreHigh <= 0 {
			return errors.New("detector.score_high must be positive")
		}
		switch c.Detector.Sensitivity {
		case "", "high", "medium", "low":
		default:
			return fmt.Errorf("detector.sensitivity invalid: %s (must be high, medium, or low)", c.Detector.Sensitivity)
		}
		if c.Detector.Mode != "" && c.Detector.Mode != "block" && c.Detector.Mode != "report" {
			return fmt.Errorf("detector.mode invalid: %s (must be block or report)", c.Detector.Mode)
		}
		if c.Detector.Weights.DangerousPattern < 0 || c.Detector.Weights.DangerousMethod < 0 ||
			c.Detector.Weights.FileUpload < 0 {
			return errors.New("detector.weights must be non-negative")
		}
		for i, w := range c.Detector.Windows {
			if w.Size <= 0 {
				return fmt.Errorf("detector.windows[%d].size must be positive", i)
			}
		}
	}

	// IPSet 校验：Whitelist/Blacklist 元素必须合法 IP/CIDR（校验不通过时拒绝启动）。
	for i, ip := range c.IPSet.Whitelist {
		if !validateIPOrCIDR(ip) {
			return fmt.Errorf("ipset.whitelist[%d] invalid: %s", i, ip)
		}
	}
	for i, ip := range c.IPSet.Blacklist {
		if !validateIPOrCIDR(ip) {
			return fmt.Errorf("ipset.blacklist[%d] invalid: %s", i, ip)
		}
	}

	// Stats 校验：report_interval 为 0 表示禁用，否则必须为正整数。
	if c.Stats.ReportInterval < 0 {
		return errors.New("stats.report_interval must be non-negative (0 disables reports)")
	}

	return nil
}

// validateIPOrCIDR 判断字符串是否为合法 IP 或 CIDR（IPv4/IPv6 均支持）。
func validateIPOrCIDR(s string) bool {
	if s == "" {
		return false
	}
	if net.ParseIP(s) != nil {
		return true
	}
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	return false
}

// validateWritableDir 检查目录存在或可创建。Linux 路径在 Windows 下无法 stat，
// 仅做形式校验，运行时由系统调用决定。
func validateWritableDir(dir string) error {
	if dir == "" {
		return nil
	}
	// UnixSocket 与日志在 Linux 部署；Windows 开发环境跳过实际 stat。
	if !strings.Contains(dir, "/") && !strings.Contains(dir, "\\") {
		return nil
	}
	if info, err := os.Stat(dir); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("not a directory: %s", dir)
		}
	}
	return nil
}

// ---- 三段式特征列表配置 ----

// FlexibleFeatureList 灵活特征列表，支持两种 YAML 格式：
//
//	格式一（简单列表，向后兼容）：
//	  known_http_clients: ["okhttp", "python-requests"]
//
//	格式二（结构化，支持排除项和云端控制）：
//	  known_http_clients:
//	    local: ["okhttp", "python-requests"]
//	    excludes: ["internal-api"]  # 排除确实存在的业务路径
//	    disable_builtin: false      # 禁用内置默认值（慎用）
//	    disable_cloud: false        # 禁用云端拉取
//
// 内部实现使用 yaml.Node 进行自定义反序列化。
type FlexibleFeatureList struct {
	// Local 用户本地配置的条目（格式一或格式二的 local 字段）
	Local []string
	// Excludes 需要排除的条目（仅格式二支持）
	Excludes []string
	// DisableBuiltin 是否禁用内置默认值
	DisableBuiltin bool
	// DisableCloud 是否禁用云端拉取
	DisableCloud bool
}

// UnmarshalYAML 自定义反序列化，同时支持简单列表和结构化两种格式。
func (f *FlexibleFeatureList) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.SequenceNode:
		// 格式一：简单字符串列表
		var items []string
		if err := value.Decode(&items); err != nil {
			return fmt.Errorf("feature list sequence: %w", err)
		}
		f.Local = items
	case yaml.MappingNode:
		// 格式二：结构化配置
		type raw struct {
			Local          []string `yaml:"local"`
			Excludes       []string `yaml:"excludes"`
			DisableBuiltin bool     `yaml:"disable_builtin"`
			DisableCloud   bool     `yaml:"disable_cloud"`
		}
		var r raw
		if err := value.Decode(&r); err != nil {
			return fmt.Errorf("feature list mapping: %w", err)
		}
		f.Local = r.Local
		f.Excludes = r.Excludes
		f.DisableBuiltin = r.DisableBuiltin
		f.DisableCloud = r.DisableCloud
	case yaml.ScalarNode:
		// 空字符串/null：视为空列表
		if value.Value == "" || value.Value == "null" || value.Tag == "!!null" {
			f.Local = nil
			return nil
		}
		// 单个字符串：视为只含一个元素的列表
		f.Local = []string{value.Value}
	default:
		return fmt.Errorf("unsupported feature list YAML node kind: %v", value.Kind)
	}
	return nil
}
