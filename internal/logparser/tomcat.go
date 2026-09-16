// Package logparser - tomcat_access 解析器。
// Tomcat 默认 AccessLogValve pattern："%h %l %u %t %r %s %b %{Referer}i %{User-Agent}i"
// 时间格式：[10/Oct/2023:13:55:36 +0800]（与 nginx 一致）。
// 与 nginx CLF 主要差异：remote_user 字段可能含 quoted 字符串，IPv6 写法仍为 ::1。
package logparser

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// tomcatAccessRe 匹配 Tomcat access log。
// 时间字段与 nginx 同格式 [10/Oct/2023:13:55:36 +0800]；
// %{Referer}i 与 %{User-Agent}i 在原 pattern 中无引号，但 Tomcat 常被配置加引号，
// 此正则兼容 quoted / non-quoted 两种。
var tomcatAccessRe = regexp.MustCompile(
	`^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<bytes>\d+|-)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<uagent>[^"]*)")?`,
)

type tomcatParser struct{}

func (p *tomcatParser) Name() string { return SourceTomcatAccess }

func (p *tomcatParser) Parse(line string) (Event, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return Event{}, ErrUnparsable
	}
	m := tomcatAccessRe.FindStringSubmatch(line)
	if m == nil {
		return Event{}, ErrUnparsable
	}
	const (
		idxIP      = 1
		idxTime    = 2
		idxReq     = 3
		idxStatus  = 4
		idxBytes   = 5
		idxReferer = 6
		idxUA      = 7
	)

	ev := Event{
		Source:    SourceTomcatAccess,
		SourceIP:  m[idxIP],
		RawLine:   line,
		Referer:   stripDash(m[idxReferer]),
		UserAgent: stripDash(m[idxUA]),
	}

	if t, err := time.Parse("02/Jan/2006:15:04:05 -0700", m[idxTime]); err == nil {
		ev.Timestamp = t
	} else {
		ev.Timestamp = time.Now()
	}

	if req := strings.TrimSpace(m[idxReq]); req != "" {
		parts := strings.SplitN(req, " ", 3)
		if len(parts) >= 2 {
			ev.Method = parts[0]
			ev.Path = parts[1]
		}
	}
	if s, err := strconv.Atoi(m[idxStatus]); err == nil {
		ev.Status = s
	}
	if m[idxBytes] != "" && m[idxBytes] != "-" {
		if n, err := strconv.ParseInt(m[idxBytes], 10, 64); err == nil {
			ev.BytesSent = n
		}
	}
	return ev, nil
}
