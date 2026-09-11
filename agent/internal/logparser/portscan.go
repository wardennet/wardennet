// Package logparser parses various log formats into a unified Event struct.
//
// This file adds a parser for iptables netfilter LOG entries used by
// the port scan detection module. Input example (syslog format):
//
//	Aug 30 10:00:01 kernel: [PORT_SCAN]: IN=eth0 OUT= MAC=00:11:22:33
//	  SRC=192.168.1.100 DST=10.0.0.5 PROTO=TCP SPT=12345 DPT=22
package logparser

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// PortScanEvent a single parsed port access from netfilter LOG.
type PortScanEvent struct {
	SrcIP     string
	DstPort   int
	Timestamp int64 // Unix seconds
	RawLine   string
}

// PortScanParser parses iptables LOG syslog lines.
type PortScanParser struct {
	prefix string
	srcRe  *regexp.Regexp
	dptRe  *regexp.Regexp
}

var (
	portscanSrcRe  = regexp.MustCompile(`\bSRC=(\S+)`)
	portscanDptRe  = regexp.MustCompile(`\bDPT=(\d+)`)
)

// NewPortScanParser creates a parser matching the given iptables --log-prefix.
func NewPortScanParser(prefix string) *PortScanParser {
	if prefix == "" {
		prefix = "[PORT_SCAN]: "
	}
	return &PortScanParser{
		prefix: prefix,
		srcRe:  portscanSrcRe,
		dptRe:  portscanDptRe,
	}
}

// Parse extracts SRC IP and destination port from a single syslog line.
// Returns (event, true) on success; (PortScanEvent{}, false) if the line
// doesn't match the expected format.
func (p *PortScanParser) Parse(line string) (PortScanEvent, bool) {
	if line == "" {
		return PortScanEvent{}, false
	}
	if !strings.Contains(line, p.prefix) {
		return PortScanEvent{}, false
	}

	srcMatch := p.srcRe.FindStringSubmatch(line)
	dptMatch := p.dptRe.FindStringSubmatch(line)
	if len(srcMatch) < 2 || len(dptMatch) < 2 {
		return PortScanEvent{}, false
	}

	port, err := strconv.Atoi(dptMatch[1])
	if err != nil || port <= 0 || port > 65535 {
		return PortScanEvent{}, false
	}

	ts := parseSyslogTimestamp(line)
	return PortScanEvent{
		SrcIP:     srcMatch[1],
		DstPort:   port,
		Timestamp: ts,
		RawLine:   line,
	}, true
}

// parseSyslogTimestamp attempts to parse the leading syslog timestamp
// ("Mon  _2 15:04:05") without a year. Falls back to time.Now() on failure.
func parseSyslogTimestamp(line string) int64 {
	// syslog lines start like: "Aug 30 10:00:01 kernel: ..."
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return time.Now().Unix()
	}
	tsStr := fields[0] + " " + fields[1] + " " + fields[2]
	t, err := time.Parse("Jan 2 15:04:05", tsStr)
	if err != nil {
		return time.Now().Unix()
	}
	// syslog has no year — use current year
	now := time.Now()
	t = t.AddDate(now.Year(), 0, 0)
	// If the parsed time is more than 1 hour in the future (clock skew),
	// subtract a year — prevents issues around New Year boundary.
	if t.After(now.Add(1 * time.Hour)) {
		t = t.AddDate(-1, 0, 0)
	}
	return t.Unix()
}
