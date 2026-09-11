// Package detector - decode.go 提供路径/UA 解码功能。
// 攻击者常使用各种编码（URL/Unicode/Hex/HTML Entity）绕过关键字检测。
// 解码后才能识别 SQL 注入、XSS、路径遍历、命令注入等攻击特征。
package detector

import (
	"encoding/hex"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// decodePath 解码常见编码后的路径。
// 处理顺序：URL 解码 → Unicode 转义 → Hex 转义 → HTML 实体 → 再次 URL 解码（处理双重编码）
// 攻击者可能使用多层编码，如 %2527 解码一次后变为 %27，需要再次解码才得到 '
func decodePath(path string) string {
	if path == "" {
		return path
	}
	// 循环解码最多 3 次，防止无限循环（处理三重编码）
	decoded := path
	for i := 0; i < 3; i++ {
		prev := decoded
		decoded = decodeOnce(decoded)
		if decoded == prev {
			break
		}
	}
	return decoded
}

// decodeOnce 执行一次完整的解码流程。
func decodeOnce(s string) string {
	// 1. URL 解码（处理 %xx 编码）
	// 使用 PathUnescape 而非 QueryUnescape，因为路径中的 + 应保留
	if u, err := url.PathUnescape(s); err == nil {
		s = u
	}

	// 2. URL 解码（处理 + 号为空格，查询串风格）
	if u, err := url.QueryUnescape(s); err == nil {
		s = u
	}

	// 3. Unicode 转义解码（\u003c、\u003c 等）
	s = decodeUnicodeEscapes(s)

	// 4. Hex 转义解码（\x3c、\x3C 等）
	s = decodeHexEscapes(s)

	// 5. HTML 实体解码（&#60;、&#x3c;、&amp; 等）
	s = decodeHTMLEntities(s)

	return s
}

// unicodeEscapeRe 匹配 \uXXXX 转义序列
var unicodeEscapeRe = regexp.MustCompile(`\\[uU]([0-9a-fA-F]{4})`)

// decodeUnicodeEscapes 解码 \uXXXX 和 \UXXXXXXXX 转义序列
func decodeUnicodeEscapes(s string) string {
	return unicodeEscapeRe.ReplaceAllStringFunc(s, func(match string) string {
		hexPart := match[2:]
		if len(hexPart) == 4 {
			if code, err := strconv.ParseUint(hexPart, 16, 32); err == nil {
				r := rune(code)
				if utf8.ValidRune(r) {
					return string(r)
				}
			}
		}
		return match
	})
}

// hexEscapeRe 匹配 \xHH 转义序列
var hexEscapeRe = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)

// decodeHexEscapes 解码 \xHH 转义序列（如 \x3c → <）
func decodeHexEscapes(s string) string {
	return hexEscapeRe.ReplaceAllStringFunc(s, func(match string) string {
		hexPart := match[2:]
		b, err := hex.DecodeString(hexPart)
		if err != nil {
			return match
		}
		if len(b) == 1 && unicode.IsPrint(rune(b[0])) {
			return string(b[0])
		}
		return match
	})
}

// htmlEntityRe 匹配 HTML 实体（&#dec;、&#xhex;、&name;）
var htmlEntityRe = regexp.MustCompile(`&#(x[0-9a-fA-F]+|\d+);|&([a-zA-Z]+);`)

// decodeHTMLEntities 解码 HTML 实体
func decodeHTMLEntities(s string) string {
	return htmlEntityRe.ReplaceAllStringFunc(s, func(match string) string {
		if strings.HasPrefix(match, "&#x") || strings.HasPrefix(match, "&#X") {
			// 十六进制实体
			hexPart := match[3 : len(match)-1]
			if code, err := strconv.ParseUint(hexPart, 16, 32); err == nil {
				r := rune(code)
				if utf8.ValidRune(r) {
					return string(r)
				}
			}
		} else if strings.HasPrefix(match, "&#") {
			// 十进制实体
			decPart := match[2 : len(match)-1]
			if code, err := strconv.ParseUint(decPart, 10, 32); err == nil {
				r := rune(code)
				if utf8.ValidRune(r) {
					return string(r)
				}
			}
		} else if strings.HasPrefix(match, "&") && !strings.HasPrefix(match, "&#") {
			// 命名实体（仅常用的几个）
			if r, ok := namedHTMLEntities[match[1:len(match)-1]]; ok {
				return string(r)
			}
		}
		return match
	})
}

// namedHTMLEntities 常用 HTML 命名实体
var namedHTMLEntities = map[string]rune{
	"amp":  '&',
	"lt":   '<',
	"gt":   '>',
	"quot": '"',
	"apos": '\'',
	"nbsp": ' ',
	"slash": '/',
	"backslash": '\\',
}

// --- 危险模式检测 ---

// 默认危险攻击模式（解码后匹配）
// 这些模式在解码后的路径中出现，表示存在注入攻击尝试
var defaultDangerousPatterns = []string{
	// SQL 注入
	"select ",
	"insert into",
	"update set",
	"delete from",
	"drop table",
	"drop database",
	"union select",
	"or 1=1",
	"or '1'='1",
	"' or ",
	"';--",
	"admin'--",
	"xp_cmdshell",
	"information_schema",
	"sleep(",
	"benchmark(",
	"extractvalue(",
	"load_file(",
	"concat(",
	// XSS 注入
	"<script",
	"</script>",
	"javascript:",
	"onerror=",
	"onload=",
	"onclick=",
	"alert(",
	"document.cookie",
	"eval(",
	// 路径遍历
	"../",
	"..\\",
	"%2e%2e",
	"etc/passwd",
	"etc/shadow",
	"proc/self",
	"boot.ini",
	"win.ini",
	"web.config",
	"wp-config.php",
	// 命令注入
	"; cat ",
	"; ls ",
	"; wget ",
	"; curl ",
	"; rm ",
	"|cat ",
	"|ls ",
	"|wget ",
	"|curl ",
	"|rm ",
	// "&cmd" and "&&cmd" removed: URL query-param based command injection patterns
	// are too ambiguous and easily collide with legitimate business params.
	// Shell injection is already well-covered by "; cmd ", "|cmd ", "system(" etc.
	"backtick",
	"$(",
	// 命令执行函数
	"system(",
	"exec(",
	"passthru(",
	"shell_exec(",
	"popen(",
	"proc_open(",
	// 文件包含/读取
	"file_get_contents(",
	"include(",
	"require(",
	"include_once(",
	"require_once(",
	// LDAP 注入
	"\\)(|(",
	"\\)(&(",
	// SSTI
	"${",
	"{{",
	"<%=",
	// SSRF/内网探测
	"127.0.0.1",
	"0.0.0.0",
	"localhost",
	"192.168.",
	"10.",
	"172.16.",
	"metadata",
	"169.254.",
}

// decodeAndMatchDangerPatterns 解码路径后检查是否匹配危险模式。
// 返回匹配到的模式列表（用于日志记录和评分）
func decodeAndMatchDangerPatterns(path string, patterns []string) []string {
	if path == "" || len(patterns) == 0 {
		return nil
	}
	decoded := decodePath(strings.ToLower(path))
	var matched []string
	for _, pat := range patterns {
		if pat == "" {
			continue
		}
		if strings.Contains(decoded, strings.ToLower(pat)) {
			matched = append(matched, pat)
		}
	}
	return matched
}

// decodePathNoLower 解码路径但不转换为小写（用于需要保留大小写的场景）
func decodePathNoLower(path string) string {
	return decodePath(path)
}