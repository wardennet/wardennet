// Package logparser - custom.go 支持用户自定义日志格式的解析器。
// 用户可在 config.yaml 中指定 custom_regex 和 regex_groups 来解析任意格式的日志。
package logparser

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// customParser 基于用户自定义正则表达式的日志解析器。
// regexGroups 指定各字段在正则中的分组索引（从 1 开始）。
type customParser struct {
	name         string
	regex        *regexp.Regexp
	regexStr     string
	groups       map[string]int // 字段名 -> 分组索引
	timeLayout   string         // 时间格式布局，默认 "02/Jan/2006:15:04:05 -0700"
}

// NewCustomParser 创建自定义解析器。
// name: 解析器名称（用于日志标识）
// regexStr: 正则表达式字符串
// groups: 字段分组索引映射
// 支持的字段：ip, time, request, status, bytes, referer, uagent, xff
func NewCustomParser(name, regexStr string, groups map[string]int) (*customParser, error) {
	re, err := regexp.Compile(regexStr)
	if err != nil {
		return nil, err
	}
	return &customParser{
		name:       name,
		regex:      re,
		regexStr:   regexStr,
		groups:     groups,
		timeLayout: "02/Jan/2006:15:04:05 -0700",
	}, nil
}

// Name 返回解析器名称。
func (p *customParser) Name() string {
	return p.name
}

// Parse 使用自定义正则解析日志行。
func (p *customParser) Parse(line string) (Event, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return Event{}, ErrUnparsable
	}

	m := p.regex.FindStringSubmatch(line)
	if m == nil {
		return Event{}, ErrUnparsable
	}

	ev := Event{
		Source:  p.name,
		RawLine: line,
	}

	// 提取各字段
	if idx, ok := p.groups["ip"]; ok && idx < len(m) {
		ev.SourceIP = m[idx]
	}
	if idx, ok := p.groups["time"]; ok && idx < len(m) {
		if t, err := time.Parse(p.timeLayout, m[idx]); err == nil {
			ev.Timestamp = t
		} else {
			ev.Timestamp = time.Now()
		}
	} else {
		ev.Timestamp = time.Now()
	}
	if idx, ok := p.groups["request"]; ok && idx < len(m) {
		if req := strings.TrimSpace(m[idx]); req != "" {
			parts := strings.SplitN(req, " ", 3)
			if len(parts) >= 2 {
				ev.Method = parts[0]
				ev.Path = parts[1]
			}
		}
	}
	if idx, ok := p.groups["status"]; ok && idx < len(m) {
		if s, err := strconv.Atoi(m[idx]); err == nil {
			ev.Status = s
		}
	}
	if idx, ok := p.groups["bytes"]; ok && idx < len(m) {
		if m[idx] != "-" {
			if n, err := strconv.ParseInt(m[idx], 10, 64); err == nil {
				ev.BytesSent = n
			}
		}
	}
	if idx, ok := p.groups["referer"]; ok && idx < len(m) {
		ev.Referer = stripDash(m[idx])
	}
	if idx, ok := p.groups["uagent"]; ok && idx < len(m) {
		ev.UserAgent = stripDash(m[idx])
	}
	if idx, ok := p.groups["xff"]; ok && idx < len(m) {
		xffIP := strings.Split(m[idx], ",")[0]
		xffIP = strings.TrimSpace(xffIP)
		if xffIP != "" && xffIP != "-" {
			ev.SourceIP = xffIP
		}
	}

	return ev, nil
}
