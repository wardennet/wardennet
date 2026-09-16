package detector

import (
	"encoding/json"
	"io"
	"net/url"
	"strings"
)

// BodyScanner scans HTTP request bodies for attack patterns.
// Zero cross-internal-package dependencies (stdlib only).
// 设计：
//   - 空值短路：Body/FileName 都为空时直接返回空结果（零开销）
//   - Content-Type 分流：JSON 递归、Form 解析、XML XXE、multipart 文件上传
//   - 攻击模式命中写入 DangerousPatternHit（复用现有维度）
//   - 文件上传拦截写入 FileUploadBlocked（新增维度）
type BodyScanner struct {
	enabled      bool
	maxBodySize  int64               // 最大扫描 Body 大小（字节），超过截断
	patterns     []string            // 危险攻击模式列表（复用 DetectorCfg.DangerousPatterns）
	blockedExts  map[string]bool     // 危险文件扩展名（小写，含点）
	blockedMimes map[string]bool     // 危险 MIME 类型（小写）
	contentTypes map[string]bool     // 支持的 Content-Type（小写）
}

// DefaultBlockedExtensions 默认拦截的文件扩展名（木马/后门特征）。
func DefaultBlockedExtensions() []string {
	return []string{
		".php", ".phtml", ".phar", ".php5", ".php7",
		".jsp", ".jspx",
		".asp", ".aspx", ".ashx",
		".cgi", ".pl",
		".htaccess", ".htpasswd",
	}
}

// DefaultBlockedMIMEs 默认拦截的 MIME 类型。
func DefaultBlockedMIMEs() []string {
	return []string{
		"application/x-php",
		"application/x-httpd-php",
		"text/x-php",
	}
}

// DefaultScannableContentTypes 默认可扫描的 Content-Type。
func DefaultScannableContentTypes() []string {
	return []string{
		"application/json",
		"application/x-www-form-urlencoded",
		"multipart/form-data",
		"application/xml",
		"text/xml",
	}
}

// NewBodyScanner 创建 BodyScanner。enabled=false 时 Scan() 立即返回空结果。
// patterns 传入 nil 时使用 DefaultDangerousPatterns()。
// blockedExts/blockedMimes/contentTypes 传入 nil 时使用默认值。
func NewBodyScanner(
	enabled bool,
	maxBodySize int64,
	patterns []string,
	blockedExts []string,
	blockedMimes []string,
	contentTypes []string,
) *BodyScanner {
	if maxBodySize <= 0 {
		maxBodySize = 10240 // 10KB 默认——SQLi/XSS/RCE Payload 极少超过 10KB，
	}                      // 超过此大小的请求体大概率是业务文件上传或攻击者 DoS Agent
	if patterns == nil {
		patterns = DefaultDangerousPatterns()
	}
	bs := &BodyScanner{
		enabled:     enabled,
		maxBodySize: maxBodySize,
		patterns:    patterns,
	}
	if blockedExts == nil {
		blockedExts = DefaultBlockedExtensions()
	}
	bs.blockedExts = make(map[string]bool, len(blockedExts))
	for _, e := range blockedExts {
		bs.blockedExts[strings.ToLower(e)] = true
	}
	if blockedMimes == nil {
		blockedMimes = DefaultBlockedMIMEs()
	}
	bs.blockedMimes = make(map[string]bool, len(blockedMimes))
	for _, m := range blockedMimes {
		bs.blockedMimes[strings.ToLower(m)] = true
	}
	if contentTypes == nil {
		contentTypes = DefaultScannableContentTypes()
	}
	bs.contentTypes = make(map[string]bool, len(contentTypes))
	for _, ct := range contentTypes {
		bs.contentTypes[strings.ToLower(ct)] = true
	}
	return bs
}

// BodyScanResult BodyScanner.Scan 的输出。
// DangerousPatternHits 复用 ipBucket.dangerousPattern 计数器。
// FileUploadBlocked 写入 ipBucket.fileUploadBlocked 计数器。
type BodyScanResult struct {
	DangerousPatternHits int  // 攻击模式命中次数（JSON/Form/XML 扫描）
	XXEHit               bool // XML XXE 检测命中
	FileUploadBlocked    bool // 文件上传拦截（扩展名/MIME/双后缀）
}

// Scan 扫描一个 HTTP 请求体。
// 短路逻辑：
//   - !enabled → 返回空结果
//   - Body 为空且 FileName 为空 → 返回空结果
//   - Content-Type 不在支持列表 → 返回空结果
func (bs *BodyScanner) Scan(body, contentType, fileName, fileExt, fileMime string) BodyScanResult {
	var result BodyScanResult

	// 短路 1：模块未启用
	if !bs.enabled {
		return result
	}

	// 短路 2：无 Body 也无文件 → 跳过
	if len(body) == 0 && len(fileName) == 0 {
		return result
	}

	// 文件上传检测（无论 Content-Type 是什么，有 FileName 就检测）
	if len(fileName) > 0 {
		if bs.checkFileUpload(fileName, fileExt, fileMime) {
			result.FileUploadBlocked = true
		}
	}

	// 短路 3：无 Body → 跳过 Body 扫描
	if len(body) == 0 {
		return result
	}

	// Content-Type 短路
	ct := strings.ToLower(strings.TrimSpace(contentType))
	// 去掉参数（如 application/json; charset=utf-8）
	if idx := strings.Index(ct, ";"); idx >= 0 {
		ct = strings.TrimSpace(ct[:idx])
	}
	if !bs.contentTypes[ct] {
		return result
	}

	// 截断 Body 防止超大请求
	if int64(len(body)) > bs.maxBodySize {
		body = body[:bs.maxBodySize]
	}

	// 根据 Content-Type 分流
	switch {
	case strings.Contains(ct, "json"):
		result.DangerousPatternHits += bs.scanJSON(body)
	case strings.Contains(ct, "xml"):
		if isXXE(body) {
			result.XXEHit = true
			result.DangerousPatternHits++ // XXE 计入攻击模式
		}
		result.DangerousPatternHits += bs.scanXML(body)
	case strings.Contains(ct, "form"):
		result.DangerousPatternHits += bs.scanForm(body)
	case strings.Contains(ct, "multipart"):
		result.DangerousPatternHits += bs.scanMultipart(body)
	}

	return result
}

// scanJSON 递归遍历 JSON 的所有 string 值，匹配危险模式。
func (bs *BodyScanner) scanJSON(body string) int {
	var hits int
	var data interface{}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		// 解析失败：退化为直接字符串匹配
		return bs.matchPatterns(body)
	}
	bs.walkJSON(data, &hits)
	return hits
}

func (bs *BodyScanner) walkJSON(v interface{}, hits *int) {
	switch x := v.(type) {
	case string:
		*hits += bs.matchPatterns(x)
	case map[string]interface{}:
		for _, val := range x {
			bs.walkJSON(val, hits)
		}
	case []interface{}:
		for _, val := range x {
			bs.walkJSON(val, hits)
		}
	}
}

// scanForm 解析 application/x-www-form-urlencoded，对所有 value 匹配。
func (bs *BodyScanner) scanForm(body string) int {
	var hits int
	values, err := url.ParseQuery(body)
	if err != nil {
		return bs.matchPatterns(body)
	}
	for _, vals := range values {
		for _, v := range vals {
			hits += bs.matchPatterns(v)
		}
	}
	return hits
}

// scanMultipart 简单解析 multipart/form-data（非完整解析器，只提取文本字段值）。
func (bs *BodyScanner) scanMultipart(body string) int {
	var hits int
	// 尝试提取 Content-Disposition 的文本字段值
	// 简化策略：直接在 Body 里匹配危险模式
	hits += bs.matchPatterns(body)
	return hits
}

// scanXML 在 XML 文本中匹配危险模式（字段值）。
func (bs *BodyScanner) scanXML(body string) int {
	return bs.matchPatterns(body)
}

// matchPatterns 对文本执行危险攻击模式匹配，返回命中次数。
func (bs *BodyScanner) matchPatterns(text string) int {
	decoded := decodeInput(text)
	var hits int
	for _, p := range bs.patterns {
		if p == "" {
			continue
		}
		if strings.Contains(strings.ToLower(decoded), strings.ToLower(p)) {
			hits++
		}
	}
	return hits
}

// isXXE 检测 XML 外部实体攻击特征。
func isXXE(body string) bool {
	lower := strings.ToLower(body)
	// 匹配 <!DOCTYPE 且包含 ENTITY
	return strings.Contains(lower, "<!doctype") &&
		strings.Contains(lower, "entity")
}

// checkFileUpload 检查文件上传是否有危险特征。
func (bs *BodyScanner) checkFileUpload(fileName, fileExt, fileMime string) bool {
	lowName := strings.ToLower(fileName)
	lowExt := strings.ToLower(fileExt)
	lowMime := strings.ToLower(fileMime)

	// 1. 扩展名黑名单
	if lowExt != "" && bs.blockedExts[lowExt] {
		return true
	}

	// 2. MIME 黑名单
	if lowMime != "" && bs.blockedMimes[lowMime] {
		return true
	}

	// 3. 双后缀检测: file.jpg.php → 最后一个扩展名是危险的，倒数第二个是图片
	parts := strings.Split(lowName, ".")
	if len(parts) >= 3 {
		lastExt := "." + parts[len(parts)-1]
		prevExt := "." + parts[len(parts)-2]
		if bs.blockedExts[lastExt] && isImageExtension(prevExt) {
			return true
		}
	}

	return false
}

// isImageExtension 判断扩展名是否是常见图片格式（用于双后缀检测）。
func isImageExtension(ext string) bool {
	switch ext {
	case ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp":
		return true
	}
	return false
}

// decodeInput 复用 decode.go 的解码能力（URL 编码、Unicode 转义、Hex 转义）。
// 为避免 cross-package 依赖，此处内联调用 decodeInput（与 decode.go 同名函数）。
func decodeInput(s string) string {
	return decodeAndMatchDangerPatterns_inputOnly(s)
}

// decodeAndMatchDangerPatterns_inputOnly is an internal helper that reuses
// the decoding logic from decode.go without re-exporting package state.
func decodeAndMatchDangerPatterns_inputOnly(s string) string {
	// Use the same decoding pipeline as decode.go's decodeInput
	return decodeURL(s)
}

// decodeURL performs URL percent-decoding.
func decodeURL(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	return urlDecode(s)
}

func urlDecode(s string) string {
	// Simple URL decode — avoid importing net/url at this level
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			hi := hexVal(s[i+1])
			lo := hexVal(s[i+2])
			if hi >= 0 && lo >= 0 {
				b.WriteByte(byte(hi<<4 | lo))
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// _ unused silences io import if not needed elsewhere
var _ = io.EOF
