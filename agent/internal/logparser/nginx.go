// Package logparser - nginx_access 解析器。
// 支持 Common Log Format (CLF)、Combined Log Format，以及带 remote_port / x-forwarded-for
// 的扩展格式。v1.1 新增 Cloudflare-aware 扩展格式，支持 CF-Connecting-IP / True-Client-IP
// header 提取真实客户端 IP（Nginx 需在 log_format 中记录 $http_cf_connecting_ip 等变量）。
//
// 示例：
//
//	CLF:      127.0.0.1 - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 200 612
//	Combined: 127.0.0.1 - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0"
//	Ext:      127.0.0.1 12345 - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0" "-"
//	CF Ext:   127.0.0.1 12345 - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0" "6.6.6.6" "2.2.2.2" "8.8.8.8"
//	          (remote_addr port user time request status bytes referer ua xff cf_connecting_ip true_client_ip)
//
// 推荐 Cloudflare 场景 Nginx log_format：
//
//	log_format cf_ext '$remote_addr $remote_port - $remote_user [$time_local] '
//	                  '"$request" $status $bytes_sent '
//	                  '"$http_referer" "$http_user_agent" '
//	                  '"$http_x_forwarded_for" "$http_cf_connecting_ip" "$http_true_client_ip"';
package logparser

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// nginxReCLF 匹配标准 CLF + Combined 格式。
// `$remote_addr - $remote_user [$time_local] "$request" $status $bytes "$referer" "$ua"`
var nginxReCLF = regexp.MustCompile(
	`^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<request>[^"]*)"(?:\s+(?P<status>\d{3})(?:\s+(?P<bytes>\d+|-))?(?:\s+"(?P<referer>[^"]*)"\s+"(?P<uagent>[^"]*)")?)?`,
)

// nginxReExt 匹配扩展格式（带 remote_port + xff + cf_connecting_ip + true_client_ip）。
// 格式：
// `$remote_addr $remote_port - $remote_user [$time_local] "$request" $status $bytes "$referer" "$ua" "$xff" "$cf_connecting_ip" "$true_client_ip"`
// 后三个 header 字段（xff / cf_connecting_ip / true_client_ip）都是可选的，
// 适配不同用户的 Nginx log_format 配置。
var nginxReExt = regexp.MustCompile(
	`^(?P<ip>\S+)\s+\d+\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<request>[^"]*)"` +
		`(?:\s+(?P<status>\d{3})` +
		`(?:\s+(?P<bytes>\d+|-))?` +
		`(?:\s+"(?P<referer>[^"]*)"\s+"(?P<uagent>[^"]*)"` +
		`(?:\s+"(?P<xff>[^"]*)"` +
		`(?:\s+"(?P<cf>[^"]*)"` +
		`(?:\s+"(?P<tcip>[^"]*)")?)?)?)?)?`,
)

// nginxParser 实现 nginx access log 解析，支持多种格式自动切换。
type nginxParser struct{}

func (p *nginxParser) Name() string { return SourceNginxAccess }

// nginxMatchResult 统一匹配结果
type nginxMatchResult struct {
	ip      string // $remote_addr — Agent 直接看到的 IP（边缘节点 IP）
	timeStr string
	request string
	status  string
	bytes   string
	referer string
	uagent  string
	xff     string // $http_x_forwarded_for
	cf      string // $http_cf_connecting_ip
	tcip    string // $http_true_client_ip
}

// parseNginxMatch 从 regex 匹配结果中提取命名字段。
// m 是 nginxReExt 的 FindStringSubmatch 结果（包含所有命名捕获组）。
// 字段顺序由 nginxReExt 的命名组决定：ip(1) time(2) request(3) status(4) bytes(5) referer(6) uagent(7) xff(8) cf(9) tcip(10)
func parseNginxMatch(m []string) *nginxMatchResult {
	result := &nginxMatchResult{
		ip:      m[1],
		timeStr: m[2],
		request: m[3],
		status:  m[4],
		bytes:   m[5],
		referer: m[6],
		uagent:  m[7],
	}
	if len(m) > 8 {
		result.xff = m[8]
	}
	if len(m) > 9 {
		result.cf = m[9]
	}
	if len(m) > 10 {
		result.tcip = m[10]
	}
	return result
}

// pickRealIP 按可信度优先级选择真实客户端 IP：
// CF-Connecting-IP > True-Client-IP > X-Forwarded-For > remote_addr（直连）
// 返回：(真实IP, IP来源标记)
func pickRealIP(remoteAddr, xff, cf, tcip string) (realIP, source string) {
	// 1. Cloudflare CF-Connecting-IP — 最高可信度（CF 直接写入，无法伪造）
	if cf = strings.TrimSpace(cf); cf != "" && cf != "-" {
		return cf, "cf_connecting_ip"
	}
	// 2. True-Client-IP — Cloudflare 的备用 header
	if tcip = strings.TrimSpace(tcip); tcip != "" && tcip != "-" {
		return tcip, "true_client_ip"
	}
	// 3. X-Forwarded-For — 取第一个 IP（最靠近客户端的代理写入）
	if xff = strings.TrimSpace(xff); xff != "" && xff != "-" {
		xffIP := strings.Split(xff, ",")[0]
		xffIP = strings.TrimSpace(xffIP)
		if xffIP != "" && xffIP != "-" {
			return xffIP, "xff"
		}
	}
	// 4. remote_addr — 直连场景
	return remoteAddr, "direct"
}

func (p *nginxParser) Parse(line string) (Event, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return Event{}, ErrUnparsable
	}

	// 依次尝试各格式（CF-aware Ext → 原始 Ext → CLF/Combined）
	var match *nginxMatchResult
	if m := nginxReExt.FindStringSubmatch(line); m != nil {
		match = parseNginxMatch(m)
	} else if m := nginxReCLF.FindStringSubmatch(line); m != nil {
		match = &nginxMatchResult{
			ip:      m[1],
			timeStr: m[2],
			request: m[3],
			status:  m[4],
			bytes:   m[5],
			referer: m[6],
			uagent:  m[7],
		}
	}

	if match == nil {
		return Event{}, ErrUnparsable
	}

	// EdgeIP 永远是 remote_addr（Agent 直接看到的 IP）
	edgeIP := match.ip

	// 按优先级选择真实客户端 IP
	realIP, source := pickRealIP(match.ip, match.xff, match.cf, match.tcip)

	ev := Event{
		Source:    SourceNginxAccess,
		SourceIP:  realIP,
		EdgeIP:    edgeIP,
		ClientIPFrom: source,
		RawLine:   line,
		Referer:   stripDash(match.referer),
		UserAgent: stripDash(match.uagent),
	}

	// 时间格式：02/Jan/2006:15:04:05 -0700
	if t, err := time.Parse("02/Jan/2006:15:04:05 -0700", match.timeStr); err == nil {
		ev.Timestamp = t
	} else {
		ev.Timestamp = time.Now()
	}

	// 解析请求行：METHOD PATH PROTOCOL
	if req := strings.TrimSpace(match.request); req != "" {
		parts := strings.SplitN(req, " ", 3)
		if len(parts) >= 2 {
			ev.Method = parts[0]
			ev.Path = parts[1]
		}
	}

	if match.status != "" {
		if s, err := strconv.Atoi(match.status); err == nil {
			ev.Status = s
		}
	}
	if match.bytes != "" && match.bytes != "-" {
		if n, err := strconv.ParseInt(match.bytes, 10, 64); err == nil {
			ev.BytesSent = n
		}
	}

	return ev, nil
}

// stripDash 把单 "-"（空字段占位）转为空字符串。
func stripDash(s string) string {
	if strings.TrimSpace(s) == "-" || s == "" {
		return ""
	}
	return s
}
