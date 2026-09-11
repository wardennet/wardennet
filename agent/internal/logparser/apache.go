// Package logparser - apache_access 解析器。
// Apache httpd 默认 CLF + Combined，与 nginx 兼容；区别在于 IPv6 写法与时间格式。
// 这里复用 nginxAccessRe（兼容 IPv6）+ 单独 parser 名以便审计区分。
package logparser

import (
	"strings"
)

// apacheParser 复用 nginx 正则，独立 Name 便于审计与配置区分。
type apacheParser struct{}

func (p *apacheParser) Name() string { return SourceApacheAccess }

func (p *apacheParser) Parse(line string) (Event, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return Event{}, ErrUnparsable
	}
	// 复用 nginxParser 解析逻辑（CLF + Combined 兼容）。
	np := &nginxParser{}
	ev, err := np.Parse(line)
	if err != nil {
		return Event{}, err
	}
	ev.Source = SourceApacheAccess
	// Apache Combined 默认时间格式与 nginx 一致（[10/Oct/2023:13:55:36 +0000]），
	// 若不匹配则已由 nginxParser 回退 time.Now()。
	return ev, nil
}
