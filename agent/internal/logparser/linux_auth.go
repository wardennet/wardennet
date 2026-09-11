// Package logparser - linux_auth 解析器。
// 解析 /var/log/auth.log（rsyslog）中 sshd/pam 关键事件。
// 支持动作：Failed password / Accepted password / Invalid user / Connection closed / Disconnected
// 时间字段无年份，按当前年补全（跨年逻辑：若月份大于当前月则用上一年）。
package logparser

import (
	"regexp"
	"strings"
	"time"
)

// linuxAuthRe 匹配 rsyslog auth 行。
//
//	Mar 2 16:38:12 host sshd[1234]: Failed password for invalid user root from 1.2.3.4 port 12345 ssh2
var linuxAuthRe = regexp.MustCompile(
	`^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<proc>\S+?)(?:\[\d+\])?:\s+(?P<msg>.*)$`,
)

// linuxAuthIPRe 从消息体中提取 "from <ip> port <port>"。
var linuxAuthIPRe = regexp.MustCompile(`from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)\s+port\s+\d+`)

// linuxAuthUserRe 提取 "for [invalid user] <user>"。
var linuxAuthUserRe = regexp.MustCompile(`for\s+(?:invalid user\s+)?(?P<user>\S+)`)

// monthMap 月份缩写转数字。
var monthMap = map[string]time.Month{
	"Jan": time.January, "Feb": time.February, "Mar": time.March,
	"Apr": time.April, "May": time.May, "Jun": time.June,
	"Jul": time.July, "Aug": time.August, "Sep": time.September,
	"Oct": time.October, "Nov": time.November, "Dec": time.December,
}

type linuxAuthParser struct{}

func (p *linuxAuthParser) Name() string { return SourceLinuxAuth }

func (p *linuxAuthParser) Parse(line string) (Event, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return Event{}, ErrUnparsable
	}
	m := linuxAuthRe.FindStringSubmatch(line)
	if m == nil {
		return Event{}, ErrUnparsable
	}
	const (
		idxMon  = 1
		idxDay  = 2
		idxTime = 3
		idxHost = 4
		idxProc = 5
		idxMsg  = 6
	)

	ev := Event{
		Source:     SourceLinuxAuth,
		RawLine:    line,
		AuthAction: m[idxMsg],
		AuthUser:   extractUser(m[idxMsg]),
		SourceIP:   extractIP(m[idxMsg]),
	}
	ev.Timestamp = parseAuthTime(m[idxMon], m[idxDay], m[idxTime])

	// 仅 sshd / ssh 等关键事件标记 Source；非关键事件 SourceIP 可能为空，调用方决定是否消费。
	_ = m[idxHost]
	_ = m[idxProc]
	return ev, nil
}

// extractIP 从 "from 1.2.3.4 port 12345" 提取 IP。
func extractIP(msg string) string {
	if m := linuxAuthIPRe.FindStringSubmatch(msg); len(m) >= 2 {
		return m[1]
	}
	return ""
}

// extractUser 从 "for [invalid user] <user>" 提取用户名。
func extractUser(msg string) string {
	// 优先匹配 "for invalid user X" 或 "for X"
	if m := linuxAuthUserRe.FindStringSubmatch(msg); len(m) >= 2 {
		return m[1]
	}
	return ""
}

// parseAuthTime 将 "Mar 2 16:38:12" 解析为 time.Time，年份用当前年补全。
// 跨年回退：若月份大于当前月（如日志 Dec 当前 Feb），则用上一年。
func parseAuthTime(mon, day, timeStr string) time.Time {
	month, ok := monthMap[mon]
	if !ok {
		return time.Now()
	}
	now := time.Now()
	year := now.Year()
	// 简化跨年逻辑：若月份比当前月大 9 月以上，认为是去年的日志。
	if int(month) > int(now.Month())+9 {
		year--
	}
	t, err := time.ParseInLocation(
		"2006-01-02 15:04:05",
		formatInt(year, 4)+"-"+formatInt(int(month), 2)+"-"+padDay(day)+" "+timeStr,
		time.Local,
	)
	if err != nil {
		return time.Now()
	}
	return t
}

// formatInt 数字补零到指定宽度。
func formatInt(n, width int) string {
	s := []byte{}
	str := []byte{}
	if n == 0 {
		str = append(str, '0')
	}
	for n > 0 {
		str = append([]byte{byte('0' + n%10)}, str...)
		n /= 10
	}
	for i := 0; i < width-len(str); i++ {
		s = append(s, '0')
	}
	return string(s) + string(str)
}

// padDay 将 "2" 补为 "02"。
func padDay(day string) string {
	if len(day) == 1 {
		return "0" + day
	}
	return day
}
