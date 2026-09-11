// Package detector 实现 Agent 本地滑动窗口检测引擎。
// 三档时间窗口（10s/30s/60s）并行统计，无外部依赖，内存基于环形桶 + TTL 淘汰。
//
// v1.1 404 路径归一化：
//   同一根因导致的批量 404（如前端 Bug 拼接错 URL）归并为一个 distinct base，
//   不同扫描方向的 404（/admin vs /.env vs /phpmyadmin）保持独立计数。
//   归一化只影响 404 维度，不影响 401/403/其他 4xx。
//
// 注意：为避开 Go module 在 github.com/wardennet/agent（私有未开源）下把内包当远程
// 模块解析的网络下载失败，本包不引入任何内部包（config/logparser/logger 等），
// 所需的配置结构与 Event 结构在本包内镜像定义，并通过 NewXXX 构造参数接收；
// 字段名/顺序与 agent/internal/config、agent/internal/logparser 中对应结构一致，
// 外部集成时可直接赋值/构造。
package detector

import (
	"fmt"
	"os"
	"path"
	"strings"
	"sync"
	"time"
)

// ---------- 404 路径归一化 ----------
// 设计目标：
//   - 前端 Bug 批量 404（同一前缀，仅尾部不同）→ 归并为 1 个 distinct base
//   - 真实扫描探测（不同前缀 /admin /.env /phpmyadmin）→ 保持独立计数
//   - UUID / 长数字 / 长十六进制串视为变量段，归一化为 {id}

// normalize404Path 将 404 路径归一化为"根因 base"。
// 规则：去 query → 变量段替换为 {id} → 取前 4 段。
func normalize404Path(path string) string {
	// 去 query string
	if qIdx := strings.Index(path, "?"); qIdx >= 0 {
		path = path[:qIdx]
	}
	// 去末尾 /
	path = strings.TrimRight(path, "/")
	if path == "" {
		return "/"
	}

	lower := strings.ToLower(path)
	segs := strings.Split(lower, "/")

	result := make([]string, 0, len(segs))
	for _, seg := range segs {
		if seg == "" {
			continue
		}
		if isVariablePathSeg(seg) {
			result = append(result, "{id}")
		} else {
			result = append(result, seg)
		}
	}

	// 取前 4 段作为 base，保留足够区分度
	if len(result) > 4 {
		result = result[:4]
	}
	if len(result) == 0 {
		return "/"
	}
	return "/" + strings.Join(result, "/")
}

// isVariablePathSeg 判断路径段是否像变量（应归一化为 {id}）。
func isVariablePathSeg(seg string) bool {
	// UUID 模式：8-4-4-4-12 小写十六进制
	if len(seg) == 36 && strings.Count(seg, "-") == 4 {
		return true
	}
	// 纯数字（长度 >= 4，避免 id=1 这种短数字误伤）
	if len(seg) >= 4 {
		for i := 0; i < len(seg); i++ {
			c := seg[i]
			if c < '0' || c > '9' {
				goto notPureNum
			}
		}
		return true
	notPureNum:
	}
	// 长十六进制串（24+ 字符：ObjectId=24, MD5=32, SHA1=40）
	if len(seg) >= 24 {
		for i := 0; i < len(seg); i++ {
			c := seg[i]
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return false
			}
		}
		return true
	}
	return false
}

// ---------- 敏感路径 / Bot UA / 静态资源 常量 ----------

// sensitivePaths 扫描器常探测的敏感路径关键词。
// 匹配规则：
//   - 不含 "/" 的关键词（如 env, admin, swagger）：按路径段精确匹配，
//     即 env 只匹配 /env 或 /api/env，不匹配 /env.js
//   - 含 "/" 的关键词（如 etc/passwd）：按子串匹配（含路径分隔符的多段路径）
//   - 以 "." 开头的关键词（如 .env, .git）：按路径段精确匹配
//   - 路径穿越模式（../../, ..\, %2e%2e）：按子串匹配
var sensitivePaths = []string{
	// === 原有 ===
	"actuator", "env", "phpmyadmin", "wp-admin",
	"backup", "admin", "console", "manager", "phpinfo",
	"swagger", "swagger-ui", "swagger-resources",
	"druid", "hystrix", "nacos", "sentinel",
	".git", ".env",
	"../../", "..\\", "%2e%2e", "etc/passwd",

	// === 新增：CMS / 编辑器 / 模板探测 ===
	"dedecms",              // 织梦 CMS 目录扫描
	"ckeditor",             // CKEditor 漏洞探测
	"templets",             // CMS 模板目录（dedecms 等）
	"thinkphp",             // ThinkPHP 漏洞探测
	"upload20",             // 旧版 dedecms upload20 接口
	"member/templets",      // CMS 会员模板目录（含 /，子串匹配）
	"include/ckeditor",     // CKEditor 插件目录（含 /，子串匹配）

	// === 新增：Nmap / 路由器探测 ===
	"hnap1",                // Linksys 路由器管理接口
	"evox/about",           // Nmap NSE 探测路径
	"nmaplowercheck",       // Nmap 低端口扫描验证路径

	// === 新增：中间件 ===
	"weblogic",             // Oracle WebLogic
	"jboss",                // Red Hat JBoss
	"struts",               // Apache Struts
}

// DefaultBotUserAgents 返回内置的自动化工具/扫描器 User-Agent 关键词。
// 大小写不敏感匹配（isBotUserAgent 里做了 strings.ToLower）。
// 用户配置（DetectorCfg.BotUserAgents）和云端特征（FeatureManager.GetBotUserAgents()）
// 会覆盖此默认值，实现"程序默认 → 用户配置 → 云端同步"的三段式优先级。
func DefaultBotUserAgents() []string {
	return []string{
		// 通用 HTTP 客户端（已在 knownHTTPClients 白名单里的会先排掉，这里是补充）
		"curl", "wget",
		// 扫描器 / 渗透工具
		"nikto", "sqlmap", "nmap", "masscan", "dirbuster",
		"gobuster", "wfuzz", "hydra", "metasploit", "burpsuite",
		"zgrab", "censys", "shodan", "zoomeye",
		// Nmap 子串（补充 "nmap scripting engine" 的精准匹配，虽然 "nmap" 已能覆盖）
		"nmap scripting",
		// 漏洞扫描器
		"nessus", "acunetix", "qualys", "openvas",
		// 其他自动化 / 爬虫工具
		"httrack", "w3af", "arachni", "skipfish",
	}
}

// knownHTTPClients 已知的合法 HTTP 客户端库（API 调用方）。
// 这些 UA 不是扫描器/Bot，不应计入 BotUAHit。
// 匹配到这些 UA 时，isBotUserAgent 返回 false。
var knownHTTPClients = []string{
	"okhttp",           // Square's OkHttp (Android/Java)
	"apache-httpclient", // Apache HttpClient (Java)
	"resttemplate",      // Spring RestTemplate (Java)
	"webclient",         // Spring WebClient (Java)
	"httpclient",        // Generic HTTP client
	"java/",             // Generic Java HTTP (java.net.URLConnection)
	"python-requests",   // Python requests library
	"httpx",             // Python httpx library
	"aiohttp",           // Python async HTTP
	"go-http-client",    // Go net/http
	"axios",             // JavaScript axios
	"fetch",             // JavaScript fetch (browsers normally omit this)
	"postman",           // Postman API testing
	"insomnia",          // Insomnia API testing
}

// staticResourceExt 静态资源扩展名（真实用户浏览器会自动加载）。
var staticResourceExt = []string{
	".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
	".ico", ".woff", ".woff2", ".ttf", ".eot",
}

// normalBrowserUA 正常桌面/移动端浏览器的 User-Agent 特征关键词（全小写）。
// 用于识别"合法用户访问坏掉的后端"场景（浏览器 SPA 自动批量请求 API 全 404），
// 在 legitimateUserContext 判定中作为核心条件之一。
var normalBrowserUA = []string{
	"chrome/",    // Chrome / Chromium（含 Brave 等 Chromium 系浏览器）
	"firefox/",   // Firefox
	"edg/",       // Edge 新版 (Edg / EdgA / EdgiOS)
	"opr/",       // Opera 新版
	"opera",      // Opera 旧版
	"msie ",      // IE 旧版
	"trident/",   // IE 11+ （配合 rv: 判断）
	"vivaldi/",   // Vivaldi
	"yabrowser",  // Yandex Browser
	"duckduckgo", // DuckDuckGo Browser
	"brave/",     // Brave
}

// dangerousHTTPMethods 扫描器使用的致命 HTTP 方法。
// DELETE/PUT/PATCH：资源修改类，扫描器尝试写操作。
// CONNECT/TRACE：代理隧道/请求跟踪，正常业务不使用。
// OPTIONS：扫描 CORS/端点能力，浏览器自动发出但非常罕见。
// 注意：HEAD 已拆分到 headHTTPMethod（非致命、低权重），因为正常业务也会用
//       HEAD（报表导出探测端点、健康检查、CDN 缓存回源、Load Balancer 探测等）。
var dangerousHTTPMethods = map[string]bool{
	"CONNECT": true,
	"TRACE":   true,
	"DELETE":  true,
	"PUT":     true,
	"PATCH":   true,
	"OPTIONS": true,
}

// headHTTPMethod HEAD 请求单独处理。
// 扫描器会用 HEAD 探测端点，但正常业务（报表导出/CDN/健康检查）也会用。
// 权重低（1）且不参与致命特征判定（noFatalAttack / computeHighConfidence）。
var headHTTPMethod = map[string]bool{
	"HEAD": true,
}

// ---------- 镜像配置结构（与 config.DetectorWindow / DetectorSection 一致） ----------

// WindowCfg 单个滑动窗口配置。可通过 YAML 覆盖三档默认值。
type WindowCfg struct {
	Size int // 窗口大小（秒）：10 / 30 / 60
}

// ScoreWeights 各检测特征的打分权重。均为正整数，越大触发拉黑越敏感。
type ScoreWeights struct {
	DangerousPattern int // 危险攻击模式（解码后匹配的注入/XSS/路径遍历等）
	DangerousMethod  int // 致命 HTTP 方法（DELETE/PUT/PATCH/CONNECT/TRACE/OPTIONS）
	HeadMethod       int // HEAD 请求（低权重，正常业务也会用，如报表导出/健康检查）
	FileUpload       int // 文件上传拦截（v1.0 新增：木马/后门上传）
}

// DetectorCfg 本地滑动窗口检测引擎配置。
// 关键参数（窗口、阈值、权重）全部可调，禁止硬编码到业务代码。
type DetectorCfg struct {
	Enabled     bool         // 总开关；关闭后仍产出 Event 但不计分
	Mode        int          // 0=block(默认), 1=report-only（只评分上报不封禁）
	ScoreHigh   int          // 高分阈值：>= 此分触发本地拉黑候选
	ScoreMedium int          // 中等风险阈值：>= 此分进入观察名单
	ScoreLow    int          // 低风险阈值：>= 此分记录评分
	Sensitivity int          // 灵敏度：1=high, 2=medium, 3=low，默认 2
	Weights     ScoreWeights // 各特征权重
	Windows     [3]WindowCfg // 三档窗口，默认 [10, 30, 60] 秒

	// 可配置特征列表（替代硬编码的包级变量）
	KnownHTTPClients  []string // 合法 HTTP 客户端 UA 白名单
	BotUserAgents     []string // BotUA 关键词列表（三段式优先级：Default → 用户配置 → 云端）
	SensitivePaths    []string // 敏感路径关键词列表
	DangerousPatterns []string // 危险攻击模式（解码后匹配：SQL 注入/XSS/路径遍历等）

	// 跳过路径列表：匹配的路径完全不参与检测（不计分、不拉黑）。
	// 支持两种匹配模式：
	//   - 精确匹配：以 "/" 开头且不以 "/" 结尾，如 "/favicon.ico"、"/robots.txt"
	//   - 前缀匹配：以 "/" 结尾，如 "/.well-known/" 匹配该前缀下的所有路径
	// 大小写不敏感。典型场景：浏览器自动请求 favicon、爬虫探测 robots.txt 等。
	SkipPaths []string

	// --- 多事件确认机制（防误封） ---
	//
	// 背景：单次高分可能是 NAT 出口 IP 后某客户端/插件一过性请求（如安全探针、老旧代理网关），
	// 而非真正攻击。真实扫描器会在几秒内持续触发高分。因此引入"观察名单 + 多次确认"：
	//
	//   首次 isHigh → IP 进入观察名单，不计封。
	//   MergeWindowSec 内连续 isHigh → 算同一次事件（只刷新时间，不增加计数）。
	//   ObserveWindowSec 内再次 isHigh（≥ MergeWindowSec 后） → 计数 +1。
	//   count >= ConfirmCount → 触发 BlockTrigger，观察记录清除。
	//   ObserveWindowSec 过期未凑够 → 观察记录自动清除（视为一过性噪声）。
	//
	// 为 0 或 1 表示关闭确认（向后兼容，直接单次高分即封）。
	ConfirmCount     int // 触发封禁需要的独立高分次数，默认 2
	ObserveWindowSec int // 观察窗口（秒），默认 30
	MergeWindowSec   int // 同一次事件合并窗口（秒），默认 5

	// v1.2 新增：Consistency 5 维行为评分的阈值/权重/工程参数。
	// nil 字段由 DefaultConsistencyThresholds() 兜底。
	// 用于 Scorer 之后的降权 gate：
	//   若 IP 行为形状是 BENIGN（score >= Consistency.ScoreThreshold）
	//   但 Scorer 给了高分 → 降权到 ScoreMedium。
	Consistency *ConsistencyThresholds

	// v1.2 新增：可信内网网段（CIDR）。
	// 命中此列表的 IP 正常参与 SlidingWindow 计数（保留基线数据），
	// 但跳过 Consistency BENIGN 降权 gate（防止 API 网关/K8s Pod 等内部流量
	// 被误判为"路径极集中的扫描器"）。
	// 与白名单的区别：白名单是"零检测 + 永不封禁"，TrustedSubnet 是"轻量化检测"。
	// 默认空列表（不启用），需要用户显式配置。
	TrustedSubnets []string

	// v1.3 新增：蜜罐路径列表（触之必死）。
	// 扫描器一定会扫 /admin、/.env、/phpmyadmin 等路径——命中即判定为恶意扫描。
	// 与 SensitivePaths（基线偏离评分）不同：蜜罐命中是绝对判定，
	// 直接触发封禁（绕过多事件确认、绕过 Consistency 降权 gate）。
	// 默认空列表（不启用），需要用户显式配置。
	HoneypotPaths []string
}

// ---------- 镜像 Event 结构（与 logparser.Event 一致，仅使用检测器所需字段） ----------

// Event 镜像：detector 侧的最小 Event 视图。
// 外部集成时，logparser.Event 可直接通过字段赋值拷贝到本结构。
//
// 新增字段（v1.0 增强）：
//   Body / ContentType — 支持 POST 请求体扫描（Nginx 需配置 $request_body）
//   FileName / FileExt / FileMime — 支持 multipart 文件上传拦截
// 旧 logparser 不填充这些字段时为空字符串，BodyScanner 自动跳过（零开销）。
type Event struct {
	SourceIP       string
	Source         string // nginx_access / apache_access / tomcat_access / linux_auth
	Method         string // GET/POST/PUT/CONNECT 等
	Path           string // HTTP 请求路径
	Status         int
	BytesSent      int64  // 响应字节数
	UserAgent      string // User-Agent 头
	Referer        string // Referer 头
	AuthAction     string // linux_auth Failed/Invalid 系列动作文本
	LocalRiskScore int    // detector 回填：本地风险分
	RawLine        string // 保留字段，不参与检测
	Timestamp      int64  // 保留字段，不参与检测

	// v1.0 增强：请求体扫描 + 文件上传
	Body        string // POST 请求体（Nginx $request_body）
	ContentType string // Content-Type 头
	FileName    string // multipart 上传的文件名
	FileExt     string // 上传文件扩展名（含点，如 ".php"）
	FileMime    string // 上传文件 MIME 类型

	// v1.1 新增：Cloudflare / 代理场景下的双 IP 识别
	// EdgeIP 是 Agent 直接看到的边缘节点 IP（Nginx $remote_addr），
	// 直连场景下 EdgeIP == SourceIP。
	EdgeIP string
	// ClientIPFrom 标记 SourceIP（真实 IP）的提取来源：
	// direct / xff / cf_connecting_ip / true_client_ip
	ClientIPFrom string

	// v1.3 新增：路径遍历意图标记
	// normalizeRequestPath 在 clean 前检测原始路径是否包含穿越特征（../, %2e%2e, ..\ 等），
	// 置位此字段后 Record 会独立计数 PathTraversalHit。
	// 这样即使攻击者穿越到非敏感目标路径（不在 sensitivePaths 里），
	// "尝试路径遍历"这个攻击意图本身仍然会被捕获。
	PathTraversal bool
}

// SourceLinuxAuth linux_auth 源名常量。
const SourceLinuxAuth = "linux_auth"

// WindowCounters 单个窗口内聚合的统计值。由 Scorer 消费打分。
type WindowCounters struct {
	WindowSec           int   // 窗口大小（秒）
	TotalReq            int64 // 总请求数
	Count4xx            int64 // 4xx 状态码次数
	Count401            int64 // 401 未授权次数（Token/Session 过期等，合法降级）
	Count5xx            int64 // 5xx 状态码次数
	Count404            int64 // 404 状态码次数
	AuthFail            int64 // 认证失败次数（linux_auth）
	SensitivePathHit    int64 // 敏感路径命中次数
	DangerousPatternHit int64 // 危险攻击模式命中次数（路径 + Body 扫描）
	BotUAHit            int64 // Bot/User-Agent 异常次数
	EmptyRefererHit     int64 // 空 Referer 次数
	StaticResHit        int64 // 静态资源请求次数（真实用户特征）
	DangerousMethod     int64 // 致命 HTTP 方法次数（DELETE/PUT/PATCH/CONNECT/TRACE/OPTIONS）
	HeadMethod          int64 // HEAD 请求次数（非致命、低权重，正常业务也会用）
	FileUploadBlocked   int64 // 文件上传拦截次数（v1.0 新增）
	NormalBrowserHit    int64 // 正常浏览器 UA 次数（legitimateUserContext 判定用）
	LatestTimestamp     int64 // 窗口内最新事件的 Unix 时间戳（用于昼夜判断）

	// v1.1 新增：4xx 路径集中度追踪
	// distinct4xxPaths = 该窗口内产生过 4xx 的归一化路径数量
	//   - 小值（≤ 2）+ 非浏览器 + 非 Bot → 大概率是合法客户端调某一个坏端点 → 应降权
	//   - 大值（≥ 5）→ 扫描器分散探测多个端点 → 正常计分
	Distinct4xxPaths int64

	// v1.3 新增：路径遍历攻击意图计数
	// 原始路径中包含 "../"、"%2e%2e"、"..\" 等穿越特征（clean 前捕获）
	// 独立于 SensitivePathHit：即使遍历目标不在 sensitivePaths 里，
	// "攻击者在尝试路径遍历"这个行为本身就是强攻击信号
	PathTraversalHit int64
}

// ipBucket 单个时间桶（1 秒粒度）的计数。
type ipBucket struct {
	second            int64 // Unix 秒
	totalReq          int64
	count4xx          int64
	count401          int64 // 401 未授权次数（独立统计，用于合法降级）
	count5xx          int64
	count404          int64
	authFail          int64
	sensitivePath     int64
	dangerousPattern  int64 // 危险攻击模式命中（解码后匹配）
	botUA             int64
	emptyReferer      int64
	staticRes         int64
	dangerousMethod   int64 // 致命 HTTP 方法次数（DELETE/PUT/PATCH/CONNECT/TRACE/OPTIONS）
	headMethod        int64 // HEAD 请求次数（非致命、低权重，正常业务也会用）
	fileUploadBlocked int64 // 文件上传拦截（v1.0 新增）
	normalBrowser     int64 // 正常浏览器 UA 次数
	pathTraversal     int64 // v1.3 新增：路径遍历攻击意图命中
}

// ipWindow 单个 IP 在单个窗口大小下的环形桶数组。
// 容量 = 窗口大小（秒），覆盖整个窗口。
type ipWindow struct {
	windowSec int
	buckets   []ipBucket // 长度 = windowSec
	head      int        // 下一个写入位置（环形写入）
}

// newIPWindow 创建一个大小为 windowSec 秒的环形桶数组。
func newIPWindow(windowSec int) *ipWindow {
	if windowSec <= 0 {
		windowSec = 1
	}
	return &ipWindow{
		windowSec: windowSec,
		buckets:   make([]ipBucket, windowSec),
	}
}

// record 记录一次事件，自动处理跨秒时的桶覆盖。
func (w *ipWindow) record(nowSec int64, b *ipBucket) {
	pos := int(nowSec % int64(w.windowSec))
	if w.buckets[pos].second != nowSec {
		w.buckets[pos] = ipBucket{second: nowSec}
	}
	dst := &w.buckets[pos]
	dst.totalReq += b.totalReq
	dst.count4xx += b.count4xx
	dst.count401 += b.count401
	dst.count5xx += b.count5xx
	dst.count404 += b.count404
	dst.authFail += b.authFail
	dst.sensitivePath += b.sensitivePath
	dst.dangerousPattern += b.dangerousPattern
	dst.botUA += b.botUA
	dst.emptyReferer += b.emptyReferer
	dst.staticRes += b.staticRes
	dst.dangerousMethod += b.dangerousMethod
	dst.headMethod += b.headMethod
	dst.fileUploadBlocked += b.fileUploadBlocked
	dst.normalBrowser += b.normalBrowser
	w.head = (pos + 1) % w.windowSec
}

// sum 在当前 nowSec 下汇总窗口内未过期的计数。
func (w *ipWindow) sum(nowSec int64) WindowCounters {
	c := WindowCounters{WindowSec: w.windowSec}
	cutoff := nowSec - int64(w.windowSec)
	var latestTs int64
	for i := 0; i < w.windowSec; i++ {
		b := &w.buckets[i]
		if b.second <= cutoff {
			continue
		}
		c.TotalReq += b.totalReq
		c.Count4xx += b.count4xx
		c.Count401 += b.count401
		c.Count5xx += b.count5xx
		c.Count404 += b.count404
		c.AuthFail += b.authFail
		c.SensitivePathHit += b.sensitivePath
		c.DangerousPatternHit += b.dangerousPattern
		c.BotUAHit += b.botUA
		c.EmptyRefererHit += b.emptyReferer
		c.StaticResHit += b.staticRes
		c.DangerousMethod += b.dangerousMethod
		c.HeadMethod += b.headMethod
		c.FileUploadBlocked += b.fileUploadBlocked
		c.NormalBrowserHit += b.normalBrowser
		c.PathTraversalHit += b.pathTraversal
		// 跟踪窗口内最新的时间戳（用于昼夜判断）
		if b.second > latestTs {
			latestTs = b.second
		}
	}
	c.LatestTimestamp = latestTs
	return c
}

// ipEntry 单个 IP 在三档窗口下的完整状态。
type ipEntry struct {
	mu     sync.Mutex
	last   int64 // 上次写入 Unix 秒（用于 TTL 淘汰）
	window [3]*ipWindow

	// 404 路径归一化追踪：normalized_base → latest_unix_sec_seen
	// 同一根因导致的批量 404 在同一窗口内只计 1 次。
	fourOhFourBases map[string]int64

	// v1.1 新增：4xx 路径集中度追踪
	// 记录所有产生过 4xx 的归一化路径（含 404/401/400/403/499 等），
	// 供 Counters() 计算 distinct4xxPaths 供 Scorer 判断集中度降权。
	fourXXBases map[string]int64

	qpsEMA    float64 // 该 IP 的 QPS 指数移动平均
	seenCount int     // 该 IP 被记录的次数（seenCount > 20 才有足够历史）

	// v1.2 新增：Consistency 行为评分用的 per-IP 历史请求 ring buffer。
	// 零业务依赖，只在 SlidingWindow.Record 时 append，容量 512 固定。
	// evictLoop 清理 IP 时自动释放。
	pathHistory *pathRing
}

// SlidingWindow 多 IP × 三档窗口的滑动计数器。
// 线程安全；定期调用 Evict 清理长期无流量 IP，避免内存膨胀。
//
// v1.0 增强：可选集成 BodyScanner（请求体扫描 + 文件上传拦截）。
// 通过 SetBodyScanner 注入；nil 时 Record 内部零开销跳过。
type SlidingWindow struct {
	cfg               [3]WindowCfg
	mu                sync.RWMutex
	ips               map[string]*ipEntry
	stop              chan struct{}
	once              sync.Once
	knownHTTPClients  []string // 合法 HTTP 客户端 UA 白名单
	botUserAgents     []string // BotUA 关键词列表（三段式优先级：程序默认 → 用户配置 → 云端同步）
	sensitivePaths    []string // 敏感路径关键词列表
	dangerousPatterns []string // 危险攻击模式（解码后匹配）
	skipPaths         []string // 跳过检测的路径列表（精确或前缀匹配）
	honeypotPaths     []string // v1.3 新增：蜜罐路径列表（精确或前缀匹配，命中即封禁）
	normalBrowserUAs  []string // 正常浏览器 UA 特征列表（legitimateUserContext 判定）
	bodyScanner       *BodyScanner // v1.0 新增：可选请求体扫描器
	lastEventSec      int64       // 最近一次 Record 的 Event 时间戳（Counters 用它代替 time.Now，确保 Record/Cutoff 同一锚点）

	// v1.2 新增：Consistency 5 维评分的阈值/权重/工程参数。
	// 由 NewSlidingWindow 的最后一个参数传入，Merge 过用户配置。
	consistencyThresholds ConsistencyThresholds
}

// SetBotUserAgents 热更新 BotUA 关键词列表。传入 nil 时回退为 DefaultBotUserAgents()。
// 云端特征同步完成后应调用此方法刷新检测规则（三段式的最高优先级层）。
func (w *SlidingWindow) SetBotUserAgents(list []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if list == nil {
		w.botUserAgents = DefaultBotUserAgents()
	} else {
		w.botUserAgents = list
	}
}

// SetBodyScanner 注入 BodyScanner。传入 nil 时清空（禁用 Body 扫描）。
func (w *SlidingWindow) SetBodyScanner(bs *BodyScanner) {
	w.bodyScanner = bs
}

// SetNormalBrowserUAs 设置正常浏览器 UA 特征列表。
// 传入 nil 时回退到内置默认值 DefaultNormalBrowserUAs()。
func (w *SlidingWindow) SetNormalBrowserUAs(list []string) {
	if list == nil {
		list = normalBrowserUA
	}
	w.normalBrowserUAs = list
}

// NewSlidingWindow 基于三档窗口配置创建滑动窗口。
// knownClients 和 sensitivePathKws 为可配置特征列表；传入 nil 时使用包级默认值。
// skipPaths 为跳过检测的路径列表；传入 nil 时使用默认值。
// honeypotPaths 为蜜罐路径列表（v1.3 新增）；传入 nil 时表示不启用（零开销）。
func NewSlidingWindow(cfg [3]WindowCfg, knownClients, sensitivePathKws, dangerPatterns, skipPaths []string, honeypotPaths []string, thresholdArgs ...*ConsistencyThresholds) *SlidingWindow {
	for i := 0; i < 3; i++ {
		if cfg[i].Size <= 0 {
			cfg[i].Size = 1
		}
	}
	// 使用传入的配置列表，nil 时回退到包级默认值
	if knownClients == nil {
		knownClients = knownHTTPClients
	}
	if sensitivePathKws == nil {
		sensitivePathKws = sensitivePaths
	}
	if dangerPatterns == nil {
		dangerPatterns = defaultDangerousPatterns
	}
	if skipPaths == nil {
		skipPaths = DefaultSkipPaths()
	} else {
		// 用户显式配置（包括空切片 []string{}）：做校验规范化
		// sanitize 后若为空（用户配的全部无效），尊重用户意图保持空
		skipPaths = sanitizeSkipPaths(skipPaths)
	}

	// v1.3: 蜜罐路径列表 — 同样用 sanitizeSkipPaths 做防御性校验
	// nil = 不启用（保持 nil，IsHoneypotPath 直接返回 false，零开销）
	// 非 nil（包括空切片）= 启用但可能配了无效值
	if honeypotPaths != nil {
		honeypotPaths = sanitizeSkipPaths(honeypotPaths)
	}

	// Consistency 阈值合并：用户配置 → 默认值兜底
	var thresholds ConsistencyThresholds
	if len(thresholdArgs) > 0 {
		thresholds = MergeConsistencyThresholds(thresholdArgs[0], DefaultConsistencyThresholds())
	} else {
		thresholds = DefaultConsistencyThresholds()
	}

	w := &SlidingWindow{
		cfg:                   cfg,
		ips:                   make(map[string]*ipEntry),
		stop:                  make(chan struct{}),
		knownHTTPClients:      knownClients,
		botUserAgents:         DefaultBotUserAgents(), // 默认内置关键词；通过 SetBotUserAgents 热更新
		sensitivePaths:        sensitivePathKws,
		dangerousPatterns:     dangerPatterns,
		skipPaths:             skipPaths,
		honeypotPaths:         honeypotPaths,
		normalBrowserUAs:      normalBrowserUA, // 默认正常浏览器列表
		consistencyThresholds: thresholds,
	}
	go w.evictLoop(60 * time.Second)
	return w
}

// Close 停止后台 evict goroutine。重复调用安全。
func (s *SlidingWindow) Close() {
	s.once.Do(func() { close(s.stop) })
}

// evictLoop 周期运行 Evict；Close 关闭 stop 时退出。
func (s *SlidingWindow) evictLoop(interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.Evict(5 * 60)
		}
	}
}

// getOrCreateEntry 获取或创建 IP 对应状态（s.mu 写锁内部创建）。
func (s *SlidingWindow) getOrCreateEntry(ip string, nowSec int64) *ipEntry {
	s.mu.RLock()
	e, ok := s.ips[ip]
	s.mu.RUnlock()
	if ok {
		return e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e2, ok2 := s.ips[ip]; ok2 {
		return e2
	}
	e = &ipEntry{
		last:            nowSec,
		fourOhFourBases: make(map[string]int64),
		fourXXBases:     make(map[string]int64),
		pathHistory:     newPathRing(s.consistencyThresholds.RingCapacity),
	}
	for i := 0; i < 3; i++ {
		e.window[i] = newIPWindow(s.cfg[i].Size)
	}
	s.ips[ip] = e
	return e
}

// DefaultSkipPaths 返回默认跳过检测的路径列表。
// 这些路径是浏览器/爬虫的常规行为，不应计入攻击评分。
//   - /favicon.ico    浏览器自动请求网站图标
//   - /favicon.png    部分浏览器使用 png 格式图标
//   - /robots.txt     爬虫/搜索引擎自动请求
//   - /.well-known/   ACME/Let's Encrypt 等服务发现
func DefaultSkipPaths() []string {
	return []string{
		"/favicon.ico",
		"/favicon.png",
		"/robots.txt",
		"/.well-known/",
	}
}

// DefaultNormalBrowserUAs 返回内置的正常浏览器 UA 特征列表。
func DefaultNormalBrowserUAs() []string {
	result := make([]string, len(normalBrowserUA))
	copy(result, normalBrowserUA)
	return result
}

// normalizeRequestPath 对请求路径做完整规范化。
// 返回值：
//   - cleaned: 规范化后的安全路径（URL decode + Unicode/Hex/HTML实体解码 + 反斜杠转正斜杠 + path.Clean）
//   - hasTraversal: 原始路径中是否包含路径遍历攻击特征（../, ..\, %2e%2e, %252e 等）
//
// 检测维度：
//   - 去 query string 后的原始路径做**多轮 decode** + path.Clean，覆盖所有编码绕过。
//   - 同时检测原始路径里的穿越特征（clean 前捕获攻击意图，防止 clean 后消弭信号）。
//     例如攻击者尝试 /.well-known/../../api/internal/debug，clean 后变成 /api/internal/debug
//     如果后者不在 sensitivePaths 里，必须靠 hasTraversal 来保留"攻击者在尝试路径遍历"这个信号。
//
// 攻击者的所有编码绕过手段都会被还原：
//   - 明文穿越  /.well-known/../../admin/login.php
//   - URL编码  /.well-known/%2e%2e%2fadmin/login.php
//   - 双重编码  /.well-known/%252e%252e/admin/login.php
//   - Unicode/Hex  \u002e\u002e/admin  \x2e\x2e/admin
//   - 混合编码  /.well-known/%2e%2e/admin/%6c%6f%67%69%6e.php
//   - 反斜杠穿越 /.well-known/..\..\admin  /.well-known/%2e%2e%5cadmin
func normalizeRequestPath(raw string) (cleaned string, hasTraversal bool) {
	if raw == "" {
		return raw, false
	}
	// 去掉 query string
	p := raw
	if qIdx := strings.Index(raw, "?"); qIdx >= 0 {
		p = raw[:qIdx]
	}

	// ==== 穿越特征检测：在 decode/clean 之前做，保留原始攻击意图 ====
	// 检查原始路径中是否包含穿越攻击特征
	if containsPathTraversalIndicator(raw) {
		hasTraversal = true
	}

	// ==== 规范化链路 ====

	// 复用 decodePath 做完整解码（URL/Unicode/Hex/HTML实体，多轮直到稳定）
	// decodePath 定义在 decode.go，是包内已有的完整解码能力
	decoded := decodePath(p)

	// 反斜杠 → 正斜杠：Go path.Clean 只识别 /，攻击者可以用 \ 绕过
	// 比如 /.well-known/..\../etc/passwd 或 %2e%2e%5c（\ 编码）
	normalized := strings.ReplaceAll(decoded, "\\", "/")

	// 规范化：消除 ../、./、重复斜杠
	clean := path.Clean(normalized)
	// 保留原始末尾斜杠（path.Clean 会去掉末尾斜杠）
	if strings.HasSuffix(normalized, "/") && !strings.HasSuffix(clean, "/") {
		clean += "/"
	}
	return clean, hasTraversal
}

// containsPathTraversalIndicator 检测原始路径（含 query string）中是否包含路径穿越攻击特征。
// 在 decode/clean 之前调用，捕获攻击者的穿越意图。
// 覆盖的编码：明文 ../ ..\ 、URL 编码 %2e%2e、双重编码 %252e%252e、反斜杠编码 %5c 等。
//
// 不依赖 path.Clean（反斜杠场景 path.Clean 无效），直接在原始字节序列上做特征检测。
func containsPathTraversalIndicator(raw string) bool {
	// 多轮 decode 检测：处理双重/三重编码
	checkRound := raw
	for i := 0; i < 4; i++ {
		if containsTraversalPattern(checkRound) {
			return true
		}
		next := decodePath(checkRound)
		if next == checkRound {
			break
		}
		checkRound = next
	}
	return false
}

// containsTraversalPattern 在单轮解码后的路径上检测穿越特征。
// 精确匹配要求 "../" 或 "..\" 必须在路径段边界（不是路径段名的一部分如 /foo.bar）。
func containsTraversalPattern(s string) bool {
	for i := 0; i < len(s)-1; i++ {
		if s[i] != '.' || s[i+1] != '.' {
			continue
		}
		// 边界：前后是路径分隔符或字符串开头/结尾
		prevOk := i == 0 || s[i-1] == '/' || s[i-1] == '\\'
		nextOk := i+2 >= len(s) || s[i+2] == '/' || s[i+2] == '\\'
		if prevOk && nextOk {
			return true
		}
	}
	// URL 编码穿越特征（decode 前仍可见）
	lower := strings.ToLower(s)
	if strings.Contains(lower, "%2e%2e") {
		return true
	}
	return false
}

// sanitizeSkipPath 对用户配置的单个 skip path 做防御性校验和规范化：
//   - 必须以 "/" 开头，否则丢弃
//   - 包含 ".." 的路径穿越片段 → 丢弃（用户误配或恶意配置）
//   - 去除空白、path.Clean 规范化末尾斜杠
// 返回空字符串表示该配置项应被丢弃。
func sanitizeSkipPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	// 必须是绝对路径
	if !strings.HasPrefix(p, "/") {
		return ""
	}
	// 拒绝包含路径穿越片段的配置
	if strings.Contains(p, "..") {
		return ""
	}
	// 规范化
	clean := path.Clean(p)
	if strings.HasSuffix(p, "/") && !strings.HasSuffix(clean, "/") {
		clean += "/"
	}
	return clean
}

// sanitizeSkipPaths 批量校验和规范化用户配置的 skip path 列表。
// 无效配置项会被静默过滤，至少会返回空切片（不会返回 nil 导致回退默认值）。
func sanitizeSkipPaths(paths []string) []string {
	if len(paths) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if s := sanitizeSkipPath(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// ShouldSkipPath 检查路径是否应被跳过（完全不参与检测）。
// 支持两种匹配模式（大小写不敏感）：
//   - 前缀匹配：skipPath 以 "/" 结尾时，匹配 path 是否以该前缀开头
//     如 "/.well-known/" 匹配 "/.well-known/acme-challenge/xxx"
//   - 精确匹配：skipPath 不以 "/" 结尾时，匹配 path 去掉 query string 后的精确相等
//     如 "/favicon.ico" 匹配 "/favicon.ico" 和 "/favicon.ico?v=123"
//
// 安全机制：
//   - 请求路径先经 normalizeRequestPath 做 URL decode + path.Clean，
//     消除明文穿越（../）、URL 编码穿越（%2e%2e）、双重编码（%252e%252e）等。
//   - skipPaths 在 SetSkipPaths/NewSlidingWindow 时已经过 sanitizeSkipPaths 校验规范化。
func (s *SlidingWindow) ShouldSkipPath(pathStr string) bool {
	if len(s.skipPaths) == 0 {
		return false
	}
	cleanPath, _ := normalizeRequestPath(pathStr)
	lowerPath := strings.ToLower(cleanPath)

	for _, skip := range s.skipPaths {
		lowerSkip := strings.ToLower(skip)
		if strings.HasSuffix(lowerSkip, "/") {
			// 前缀匹配
			if strings.HasPrefix(lowerPath, lowerSkip) {
				return true
			}
		} else {
			// 精确匹配
			if lowerPath == lowerSkip {
				return true
			}
		}
	}
	return false
}

// SetSkipPaths 动态更新跳过路径列表（用于热加载）。
// 传入规则：
//   - nil 或长度 > 0 且 sanitize 后有有效值 → 正常设置
//   - 空切片 []string{} → 保持空（用户显式清空所有跳过路径的意图）
//   - 非空但 sanitize 后全无效 → 保持空（没有有效配置不如不用）
func (s *SlidingWindow) SetSkipPaths(paths []string) {
	if paths == nil {
		s.skipPaths = DefaultSkipPaths()
		return
	}
	s.skipPaths = sanitizeSkipPaths(paths)
}

// IsHoneypotPath 检查路径是否命中蜜罐路径列表。
// v1.3 新增：蜜罐路径是"触之必死"的绝对判定——
//   命中即判定为恶意扫描，直接触发封禁（绕过多事件确认、绕过 Consistency 降权 gate）。
//
// 匹配模式与 ShouldSkipPath 完全一致（大小写不敏感）：
//   - 精确匹配：honeypotPath 不以 "/" 结尾 → 精确相等
//     如 "/admin" 匹配 "/admin" 和 "/admin?v=1"
//   - 前缀匹配：honeypotPath 以 "/" 结尾 → 前缀开头
//     如 "/traps/" 匹配 "/traps/anything/here"
//
// 零开销保障：
//   - honeypotPaths 为 nil 或空切片 → 直接返回 false，不做任何字符串操作
//   - 正常部署（用户未配置）时此分支不会进入 for 循环
func (s *SlidingWindow) IsHoneypotPath(pathStr string) bool {
	if len(s.honeypotPaths) == 0 {
		return false
	}
	cleanPath, _ := normalizeRequestPath(pathStr)
	lowerPath := strings.ToLower(cleanPath)

	for _, hp := range s.honeypotPaths {
		lowerHP := strings.ToLower(hp)
		if strings.HasSuffix(lowerHP, "/") {
			// 前缀匹配
			if strings.HasPrefix(lowerPath, lowerHP) {
				return true
			}
		} else {
			// 精确匹配
			if lowerPath == lowerHP {
				return true
			}
		}
	}
	return false
}

// SetHoneypotPaths 动态更新蜜罐路径列表（用于热加载/云端同步）。
// 传入规则与 SetSkipPaths 一致：
//   - nil → 清空（回到"未启用"状态，IsHoneypotPath 零开销）
//   - 非 nil → 做 sanitizeSkipPaths 校验规范化
func (s *SlidingWindow) SetHoneypotPaths(paths []string) {
	if paths == nil {
		s.honeypotPaths = nil
		return
	}
	s.honeypotPaths = sanitizeSkipPaths(paths)
}

// Record 记录一次 Event。对 Event 分类后按来源写入对应计数。
func (s *SlidingWindow) Record(ev *Event) {
	if ev == nil {
		return
	}
	ip := ev.SourceIP
	if ip == "" {
		return
	}
	// 优先使用日志自带的时间戳（含 nginx 配置的时区偏移），回退到系统当前时间
	nowSec := ev.Timestamp
	if nowSec <= 0 {
		nowSec = time.Now().Unix()
	}
	// 记录最近一次 Event 的时间锚点（Counters 用它代替 time.Now，确保 Record/Cutoff 同一锚点）
	s.mu.Lock()
	if nowSec > s.lastEventSec {
		s.lastEventSec = nowSec
	}
	s.mu.Unlock()
	e := s.getOrCreateEntry(ip, nowSec)

	// v1.2: Consistency 行为评分的路径历史记录（旁路追踪）
	// 先 strip query 只存 bare path，避免 path 参数爆炸。
	barePath := ev.Path
	if i := strings.Index(barePath, "?"); i >= 0 {
		barePath = barePath[:i]
	}
	e.appendPathRecord(barePath, ev.Method, ev.Status)

	b := &ipBucket{totalReq: 1}

	// 状态码分类
	// 设计：Count404 和 Count4xx（非 404）互斥，独立计分避免重复。
	//   - Count404：404 状态码，偏向扫描器枚举 / 浏览器探测
	//   - Count4xx：非 404 的 4xx（401/403/429/...），偏向认证失败 / 越权 / 限流等攻击意图
	switch {
	case ev.Status == 404:
		b.count404 = 1
		// 404 路径归一化：记录 distinct base，同一窗口内同前缀只计 1 次
		base := normalize404Path(ev.Path)
		e.mu.Lock()
		if e.fourOhFourBases == nil {
			e.fourOhFourBases = make(map[string]int64)
		}
		e.fourOhFourBases[base] = nowSec // 永远更新为最新时间，确保"活跃"
		e.mu.Unlock()
	case ev.Status == 401:
		b.count401 = 1
		// v0.9: 401 从 Count4xx 排除（与 404 同级别独立）
		// 原因：401 大多是合法降级（session/token 过期），不应计入攻击型 4xx。
		// 认证相关评分统一走 Count401 通道（scorer 会把 Count401 + AuthFail 合并评分）。
		// 401 仍然记录 fourXXBases 供 concentrated4xx 使用（路径集中度降权不敏感具体状态码）。
		base := normalize404Path(ev.Path)
		e.mu.Lock()
		if e.fourXXBases == nil {
			e.fourXXBases = make(map[string]int64)
		}
		e.fourXXBases[base] = nowSec
		e.mu.Unlock()
	case ev.Status >= 400 && ev.Status < 500 && ev.Status != 404 && ev.Status != 499:
		b.count4xx = 1
		// 其他 4xx（400/403/409/429 等），记录归一化路径供 concentrated4xx 使用
		// 499 是 nginx 扩展状态码（客户端主动断开），不是服务端/扫描器异常，排除出 4xx 统计
		base := normalize404Path(ev.Path)
		e.mu.Lock()
		if e.fourXXBases == nil {
			e.fourXXBases = make(map[string]int64)
		}
		e.fourXXBases[base] = nowSec
		e.mu.Unlock()
	case ev.Status >= 500 && ev.Status < 600:
		b.count5xx = 1
	}

	// 认证失败
	if ev.Source == SourceLinuxAuth && isAuthFailure(ev.AuthAction) {
		b.authFail = 1
	}

	// 敏感路径检测 — 仅在异常状态码（>=400）时计数。
	if ev.Status >= 400 && s.hitSensitivePath(ev.Path) {
		b.sensitivePath = 1
	}

	// v1.3 新增：路径遍历攻击意图计数
	// 由 normalizeRequestPath 在 clean 前检测并置位
	// 独立于 SensitivePathHit：即使遍历目标不在 sensitivePaths 里，
	// "攻击者在尝试路径遍历"这个行为本身就是强攻击信号
	// 无论状态码多少都计数（200 响应的遍历尝试同样危险）
	if ev.PathTraversal {
		b.pathTraversal = 1
	}

	// 危险攻击模式检测 — 解码后匹配 SQL 注入/XSS/路径遍历等
	// 无论状态码多少都计数（200 响应的注入尝试同样危险）
	if hit, patterns := s.hitDangerousPattern(ev.Path); hit {
		b.dangerousPattern = 1
		if ev.SourceIP != "" {
			fmt.Fprintf(os.Stderr, "[DEBUG] dangerous_pattern_hit ip=%s patterns=%v path=%s\n", ev.SourceIP, patterns, ev.Path)
		}
	}

	// Bot UA 检测
	if s.isBotUserAgent(ev.UserAgent) {
		b.botUA = 1
	}

	// 正常浏览器 UA 检测（legitimateUserContext 判定用）
	if s.isNormalBrowserUserAgent(ev.UserAgent) {
		b.normalBrowser = 1
	}

	// 空 Referer 检测
	if ev.Referer == "" || ev.Referer == "-" {
		b.emptyReferer = 1
	}

	// 静态资源检测（真实用户特征）
	if isStaticResource(ev.Path) {
		b.staticRes = 1
	}

	// 危险 HTTP 方法检测（致命方法：DELETE/PUT/PATCH/CONNECT/TRACE/OPTIONS）
	if dangerousHTTPMethods[strings.ToUpper(ev.Method)] {
		b.dangerousMethod = 1
	}
	// HEAD 请求单独计数（非致命、低权重）
	if headHTTPMethod[strings.ToUpper(ev.Method)] {
		b.headMethod = 1
	}

	// Body 扫描 + 文件上传拦截（v1.0 新增）
	// 仅当 bodyScanner 启用且有 Body 或 FileName 时才执行，空值自动跳过
	if s.bodyScanner != nil {
		result := s.bodyScanner.Scan(ev.Body, ev.ContentType, ev.FileName, ev.FileExt, ev.FileMime)
		b.dangerousPattern += int64(result.DangerousPatternHits)
		if result.XXEHit {
			b.dangerousPattern++
		}
		if result.FileUploadBlocked {
			b.fileUploadBlocked = 1
		}
	}

	// P2-2: 畸形 HTTP 请求检测
	// 攻击者常发送非标准方法（TLS Client Hello 被当 request line、自定义协议探测等）
	// 或 path 含二进制控制字符，nginx 会返回 400。这两类请求不可能来自正常浏览器。
	if isMalformedHTTPRequest(ev.Method, ev.Path) {
		b.dangerousPattern++
	}

	e.mu.Lock()
	e.last = nowSec
	for i := 0; i < 3; i++ {
		e.window[i].record(nowSec, b)
	}
	e.seenCount++
	currentBucket := &e.window[0].buckets[nowSec%int64(e.window[0].windowSec)]
	currentRate := float64(currentBucket.totalReq) / float64(e.window[0].windowSec)
	alpha := 0.95
	e.qpsEMA = e.qpsEMA*alpha + currentRate*(1-alpha)
	e.mu.Unlock()
}

// isAuthFailure 从 auth 动作文本判断是否为失败类事件。
func isAuthFailure(action string) bool {
	if len(action) < len("Failed") {
		return false
	}
	prefixes := []string{
		"Failed password",
		"Invalid user",
		"Connection closed by authenticating user",
		"error: PAM: Authentication failure",
		"maximum authentication attempts",
	}
	for _, p := range prefixes {
		if len(action) >= len(p) && action[:len(p)] == p {
			return true
		}
	}
	return false
}

// validHTTPMethods 标准 HTTP/1.x / HTTP/2 方法集合。
var validHTTPMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "DELETE": true,
	"HEAD": true, "OPTIONS": true, "PATCH": true,
	"TRACE": true, "CONNECT": true,
}

// isMalformedHTTPRequest 检测畸形 HTTP 请求（不可能来自正常浏览器）。
// 返回 true 表示这是扫描器/探测请求，应计 dangerousPattern。
//
// 两类触发条件：
//  1. Method 不是标准 HTTP 方法
//     — Nmap 发送 TLS Client Hello 字节时被 nginx 当 request line 解析为
//       "\x16\x03\x01..." 或 "t3 12.1.2" 这种非方法；
//     — 正常浏览器的请求一定是 GET/POST/PUT 等之一。
//  2. Path 包含二进制控制字符（< 0x20 或 == 0x7F，排除 \t）
//     — 正常 URL 不会含 \x00~\x1F 的控制字节。
func isMalformedHTTPRequest(method, path string) bool {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method != "" && !validHTTPMethods[method] {
		return true
	}
	for _, b := range path {
		if b < 0x20 && b != '\t' {
			return true
		}
		if b == 0x7f {
			return true
		}
	}
	return false
}

// hitSensitivePath 检查路径是否命中敏感关键词（使用 SlidingWindow 可配置列表）。
func (s *SlidingWindow) hitSensitivePath(path string) bool {
	pathOnly := path
	if qIdx := strings.Index(path, "?"); qIdx >= 0 {
		pathOnly = path[:qIdx]
	}
	lower := strings.ToLower(pathOnly)
	segments := strings.Split(lower, "/")

	for _, kw := range s.sensitivePaths {
		if strings.Contains(kw, "/") {
			if strings.Contains(lower, kw) {
				return true
			}
			continue
		}
		for _, seg := range segments {
			if seg == kw {
				return true
			}
		}
	}
	return false
}

// isBotUserAgent 检查 User-Agent 是否为扫描器/Bot（使用 SlidingWindow 可配置白名单）。
//
// 判定策略：
//   1. 命中已知合法 HTTP 客户端白名单 → 直接返回 false
//   2. 命中已知扫描器/攻击工具关键词 → 返回 true
//   3. 空 UA / "-" 不算 BotUA（合法流量也可能不带 UA，空 UA 只说明"未知"，不是"恶意"）
//
// 空 UA 的"异常"属性通过 NormalBrowserHit=0 间接体现（legitimateUserContext 判定用），
// 不再直接算作 BotUA。这样 BotUAScore 的语义就是"命中已知扫描器关键词"。
func (s *SlidingWindow) isBotUserAgent(ua string) bool {
	lower := strings.ToLower(ua)

	// 已知合法 HTTP 客户端 — 直接返回 false
	for _, kw := range s.knownHTTPClients {
		if strings.Contains(lower, kw) {
			return false
		}
	}

	// 已知扫描器/攻击工具（从 SlidingWindow 自身的 botUserAgents 列表读取，支持热更新）
	for _, kw := range s.botUserAgents {
		if strings.Contains(lower, kw) {
			return true
		}
	}

	// 空 UA / "-" — 不算 BotUA（合法流量也可能不带 UA）
	return false
}

// isNormalBrowserUserAgent 检查 User-Agent 是否属于正常浏览器（桌面/移动端）。
// 用于识别"合法用户访问坏掉的后端"场景：浏览器 UA + 有效 Referer + 无攻击特征
// → legitimateUserContext 成立，对 4xx/404_ratio 降权处理。
//
// 判定策略（降低误报）：
//   1. 空 UA 一定不是正常浏览器（扫描器/Bot 通常也不带 UA）
//   2. 命中已知扫描器 BotUA 的一定不是
//   3. 命中 knownHTTPClients 的不是（API 客户端，不是浏览器）
//   4. 命中 normalBrowserUAs 关键词列表 → 是正常浏览器
//   5. 含 "safari/" 但不含 "chrome/" → Safari
//   6. 含 "trident/" + "rv:" → IE 11+
func (s *SlidingWindow) isNormalBrowserUserAgent(ua string) bool {
	if ua == "" || ua == "-" {
		return false
	}
	lower := strings.ToLower(ua)

	// 命中扫描器/Bot → 不是正常浏览器（从 SlidingWindow 自身的 botUserAgents 列表读取，支持热更新）
	for _, kw := range s.botUserAgents {
		if strings.Contains(lower, kw) {
			return false
		}
	}
	// 命中 knownHTTPClients → 是 API 客户端，不是浏览器
	for _, kw := range s.knownHTTPClients {
		if strings.Contains(lower, kw) {
			return false
		}
	}

	// Safari 特判：Safari UA 也含 Version 字符串，但不含 "chrome/"
	if strings.Contains(lower, "safari/") && !strings.Contains(lower, "chrome/") {
		return true
	}
	// IE 11+ 特判：含 trident/ 和 rv:
	if strings.Contains(lower, "trident/") && strings.Contains(lower, "rv:") {
		return true
	}

	// 遍历关键词列表
	for _, kw := range s.normalBrowserUAs {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// hitDangerousPattern 检查路径是否匹配危险攻击模式（解码后匹配）。
// 返回值：(matched bool, hitPatterns []string)
// 攻击者可能使用 URL 编码、Unicode 转义、Hex 转义等绕过简单字符串匹配。
// 此方法先解码路径，再与危险模式列表进行匹配。
func (s *SlidingWindow) hitDangerousPattern(path string) (bool, []string) {
	hits := decodeAndMatchDangerPatterns(path, s.dangerousPatterns)
	return len(hits) > 0, hits
}

// DefaultKnownHTTPClients 返回内置的合法 HTTP 客户端 UA 白名单。
// 供三段式合并引擎作为 Builtin 数据源使用。
func DefaultKnownHTTPClients() []string {
	result := make([]string, len(knownHTTPClients))
	copy(result, knownHTTPClients)
	return result
}

// DefaultSensitivePaths 返回内置的敏感路径关键词列表。
func DefaultSensitivePaths() []string {
	result := make([]string, len(sensitivePaths))
	copy(result, sensitivePaths)
	return result
}

// DefaultDangerousPatterns 返回内置的危险攻击模式列表。
func DefaultDangerousPatterns() []string {
	result := make([]string, len(defaultDangerousPatterns))
	copy(result, defaultDangerousPatterns)
	return result
}

// hitSensitivePath 使用默认敏感路径列表的包级版本。
// 注意：生产代码应使用 SlidingWindow.hitSensitivePath() 以支持可配置列表。
func hitSensitivePath(path string) bool {
	return hitSensitivePathWithList(path, sensitivePaths)
}

// isBotUserAgent 使用默认 HTTP 客户端白名单的包级版本。
// 注意：生产代码应使用 SlidingWindow.isBotUserAgent() 以支持可配置列表。
func isBotUserAgent(ua string) bool {
	return isBotUserAgentWithList(ua, knownHTTPClients)
}

// hitSensitivePathWithList 使用指定关键词列表进行敏感路径匹配（可复用）。
func hitSensitivePathWithList(path string, keywords []string) bool {
	pathOnly := path
	if qIdx := strings.Index(path, "?"); qIdx >= 0 {
		pathOnly = path[:qIdx]
	}
	lower := strings.ToLower(pathOnly)
	segments := strings.Split(lower, "/")

	for _, kw := range keywords {
		if strings.Contains(kw, "/") {
			if strings.Contains(lower, kw) {
				return true
			}
			continue
		}
		for _, seg := range segments {
			if seg == kw {
				return true
			}
		}
	}
	return false
}

// isBotUserAgentWithList 使用指定 HTTP 客户端白名单进行 Bot UA 检测（可复用）。
// BotUA 关键词使用内置默认值；生产代码应使用 SlidingWindow.isBotUserAgent() 以支持热更新列表。
func isBotUserAgentWithList(ua string, knownClients []string) bool {
	lower := strings.ToLower(ua)

	for _, kw := range knownClients {
		if strings.Contains(lower, kw) {
			return false
		}
	}
	for _, kw := range DefaultBotUserAgents() {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// isStaticResource 检查路径是否为静态资源（真实用户浏览器行为）。
func isStaticResource(path string) bool {
	lower := strings.ToLower(path)
	for _, ext := range staticResourceExt {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// GetIPBaseline 返回指定 IP 的 Per-IP QPS 历史基线（EMA）和累计出现次数。
// IP 不存在时返回 (0, 0)。
func (s *SlidingWindow) GetIPBaseline(ip string) (qpsEMA float64, seenCount int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.ips[ip]
	if !ok {
		return 0, 0
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.qpsEMA, e.seenCount
}

// Counters 返回指定 IP 三档窗口的当前计数。
// IP 不存在时返回零值窗口（不创建，避免 Get 导致内存膨胀）。
func (s *SlidingWindow) Counters(ip string) [3]WindowCounters {
	var out [3]WindowCounters
	for i := 0; i < 3; i++ {
		out[i].WindowSec = s.cfg[i].Size
	}
	if ip == "" {
		return out
	}
	s.mu.RLock()
	e, ok := s.ips[ip]
	// 取 lastEventSec 作为时间锚点，确保与 Record 写入桶时的时间一致
	nowSec := s.lastEventSec
	s.mu.RUnlock()
	if !ok {
		return out
	}
	if nowSec <= 0 {
		nowSec = time.Now().Unix()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := 0; i < 3; i++ {
		out[i] = e.window[i].sum(nowSec)
	}

	// --- 404 路径归一化：用 distinct base 数量替换原始 404 计数 ---
	// 同一根因（如前端 Bug）导致的批量 404 只计 1 次。
	if len(e.fourOhFourBases) > 0 {
		// 先对 3 个窗口分别计算 distinct 404 base
		type baseCount struct {
			count int64
		}
		var distinctCounts [3]baseCount

		// 用最大窗口的 cutoff 做一次性过期清理
		maxCutoff := nowSec - int64(s.cfg[2].Size)
		expiredBases := make([]string, 0)

		for base, ts := range e.fourOhFourBases {
			if ts <= maxCutoff {
				expiredBases = append(expiredBases, base)
				continue
			}
			// 每个窗口单独判断是否在有效期内
			for i := 0; i < 3; i++ {
				cutoff := nowSec - int64(s.cfg[i].Size)
				if ts > cutoff {
					distinctCounts[i].count++
				}
			}
		}
		// 清理过期 base
		for _, base := range expiredBases {
			delete(e.fourOhFourBases, base)
		}

		// 应用到输出 WindowCounters
		// Count404 归一化（同前缀 404 只计 1 次），Count4xx 不再包含 404，无需同步。
		for i := 0; i < 3; i++ {
			raw404 := out[i].Count404
			norm404 := distinctCounts[i].count
			if norm404 > raw404 {
				// 防御性：理论上 normalized 数量不应超过 raw 总数
				// （每个 distinct base 至少对应 1 个原始 404）
				norm404 = raw404
			}
			out[i].Count404 = norm404
		}
	}

	// --- v1.1: 4xx 路径集中度 ---
	// 计算每个窗口内产生 4xx 的 distinct 归一化路径数量，
	// 供 Scorer 判断是否属于"合法客户端调某一个坏端点"（≤2 条路径）。
	if len(e.fourXXBases) > 0 {
		type baseCount struct {
			count int64
		}
		var xxCnts [3]baseCount
		maxCutoff := nowSec - int64(s.cfg[2].Size)
		expiredXX := make([]string, 0)

		for base, ts := range e.fourXXBases {
			if ts <= maxCutoff {
				expiredXX = append(expiredXX, base)
				continue
			}
			for i := 0; i < 3; i++ {
				cutoff := nowSec - int64(s.cfg[i].Size)
				if ts > cutoff {
					xxCnts[i].count++
				}
			}
		}
		for _, base := range expiredXX {
			delete(e.fourXXBases, base)
		}

		for i := 0; i < 3; i++ {
			cnt := xxCnts[i].count
			// v0.9: fourXXBases 包含 401 路径 + 非 401/404/499 的 4xx 路径，
			// 而 Count4xx 只统计非 401/404/499 的 4xx（401 已独立进 Count401）。
			// 所以 Distinct4xxPaths 的正确上界 = Count4xx + Count401。
			upperBound := out[i].Count4xx + out[i].Count401
			if cnt > upperBound {
				cnt = upperBound
			}
			out[i].Distinct4xxPaths = cnt
		}
	}

	return out
}

// Evict 淘汰 idleSeconds 秒内无写入的 IP，释放内存。
func (s *SlidingWindow) Evict(idleSeconds int) int {
	cutoff := time.Now().Unix() - int64(idleSeconds)
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for ip, e := range s.ips {
		e.mu.Lock()
		idle := e.last <= cutoff
		e.mu.Unlock()
		if idle {
			delete(s.ips, ip)
			n++
		}
	}
	return n
}

// IPCount 返回当前跟踪的 IP 数量（仅用于统计/测试）。
func (s *SlidingWindow) IPCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.ips)
}

// AllCounters 导出当前所有活跃 IP 的三档计数。
// 返回值下标 [0/1/2] 对应三档窗口，map key 为 IP 字符串。
// 用于启动时预扫描后喂给 Baseline.Update() 建立初始基线。
// 注意：返回的 WindowCounters 中不含 404 归一化和 4xx 集中度处理（那些在 Counters(ip) 内），
// 但 Baseline.Update() 只需要基础计数即可完成分位数统计。
func (s *SlidingWindow) AllCounters() [3]map[string]WindowCounters {
	out := [3]map[string]WindowCounters{
		make(map[string]WindowCounters),
		make(map[string]WindowCounters),
		make(map[string]WindowCounters),
	}
	s.mu.RLock()
	ips := make([]string, 0, len(s.ips))
	for ip := range s.ips {
		ips = append(ips, ip)
	}
	s.mu.RUnlock()

	nowSec := s.lastEventSec
	if nowSec <= 0 {
		nowSec = time.Now().Unix()
	}
	for _, ip := range ips {
		s.mu.RLock()
		e, ok := s.ips[ip]
		s.mu.RUnlock()
		if !ok {
			continue
		}
		e.mu.Lock()
		for i := 0; i < 3; i++ {
			out[i][ip] = e.window[i].sum(nowSec)
		}
		e.mu.Unlock()
	}
	return out
}
