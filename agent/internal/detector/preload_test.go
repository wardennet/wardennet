// Package detector - Preload IP 多样性 / 反代检测 / 时间窗口过滤测试。
package detector

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

// ========== isReverseProxySuspicious 边界测试 ==========

func TestIsReverseProxySuspicious_Boundary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		uniqueIPs   int
		top1Ratio   float64
		top3Ratio   float64
		wantSuspici bool
	}{
		// 条件 A: UniqueIPs <= 3
		{"0 个 IP → 安全（无数据保守放行）", 0, 1.0, 1.0, false},
		{"1 个 IP → 反代", 1, 1.0, 1.0, true},
		{"2 个 IP → 反代", 2, 0.6, 1.0, true},
		{"3 个 IP → 反代（边界命中）", 3, 0.5, 1.0, true},

		// 条件 B: UniqueIPs <= 10 且 Top1Ratio >= 0.90
		{"4 IPs / Top1=92% → 反代 B", 4, 0.92, 1.0, true},
		{"8 IPs / Top1=91% → 反代 B", 8, 0.91, 0.99, true},
		{"10 IPs / Top1=95% → 反代 B（边界 10 命中）", 10, 0.95, 1.0, true},
		{"4 IPs / Top1=0.89 → 不满足 B，看下 C", 4, 0.89, 1.0, true}, // Top3Ratio=1.0 满足条件 C
		{"4 IPs / Top1=0.89 / Top3=0.97 → 安全", 4, 0.89, 0.97, false},

		// 条件 C: UniqueIPs <= 10 且 Top3Ratio >= 0.98
		{"7 IPs / Top3=99% → 反代 C", 7, 0.50, 0.99, true},
		{"10 IPs / Top3=0.98 → 反代 C（边界 0.98 命中）", 10, 0.40, 0.98, true},
		{"10 IPs / Top3=0.97 → 安全", 10, 0.40, 0.97, false},

		// UniqueIPs > 10 直接安全
		{"11 IPs / Top1=99% → 安全（超过 safe 阈值）", 11, 0.99, 1.0, false},
		{"20 IPs / Top1=95% → 安全", 20, 0.95, 0.98, false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := isReverseProxySuspicious(tt.uniqueIPs, tt.top1Ratio, tt.top3Ratio)
			if got != tt.wantSuspici {
				t.Errorf("isReverseProxySuspicious(%d, %.4f, %.4f) = %v, want %v",
					tt.uniqueIPs, tt.top1Ratio, tt.top3Ratio, got, tt.wantSuspici)
			}
		})
	}
}

// ========== PreloadFromLogFile IP 多样性 / 时间过滤测试 ==========

// logLineRe 匹配简化版 nginx combined log:
//   192.168.1.1 - - [2024-01-01 10:00:00] "GET / HTTP/1.1" 200 123 "-" "curl/7.68"
var logLineRe = regexp.MustCompile(
	`^(\S+) - - \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d+) \d+ ".*" "([^"]*)"$`,
)

// makeAccessLogFile + simpleLogParser 配套工具

func makeAccessLogFile(t *testing.T, events [][3]interface{}) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")

	var lines []string
	for _, e := range events {
		ts := e[0].(int64)
		ip := e[1].(string)
		status := e[2].(int)
		tm := time.Unix(ts, 0).Format("2006-01-02 15:04:05")
		line := fmt.Sprintf(`%s - - [%s] "GET / HTTP/1.1" %d 123 "-" "curl/7.68"`,
			ip, tm, status)
		lines = append(lines, line)
	}

	data := ""
	for _, l := range lines {
		data += l + "\n"
	}
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatalf("write temp access.log: %v", err)
	}
	return path
}

func simpleLogParser(line string) (Event, error) {
	m := logLineRe.FindStringSubmatch(line)
	if m == nil {
		return Event{}, fmt.Errorf("no match: %s", line)
	}
	ip := m[1]
	dateTime := m[2]
	var status int
	if _, err := fmt.Sscanf(m[6], "%d", &status); err != nil {
		return Event{}, fmt.Errorf("parse status: %w", err)
	}
	ts, err := time.Parse("2006-01-02 15:04:05", dateTime)
	if err != nil {
		return Event{}, fmt.Errorf("parse time: %w", err)
	}
	return Event{
		SourceIP:  ip,
		Timestamp: ts.Unix(),
		Status:    status,
		UserAgent: m[7],
	}, nil
}

// TestPreloadFromLogFile_IPDiversity_SingleIP 单反代场景
func TestPreloadFromLogFile_IPDiversity_SingleIP(t *testing.T) {
	t.Parallel()

	baseTS := int64(1704067200)
	var events [][3]interface{}
	for i := 0; i < 20; i++ {
		events = append(events, [3]interface{}{baseTS + int64(i*30), "198.51.100.42", 200})
	}
	path := makeAccessLogFile(t, events)

	cfg := DefaultDetectorCfg()
	d := NewLocalDetector(&cfg, nil)
	defer d.Close()

	stats, err := d.PreloadFromLogFile(path, LineParser(simpleLogParser), 10)
	if err != nil {
		t.Fatalf("PreloadFromLogFile: %v", err)
	}

	if stats.UniqueIPs != 1 {
		t.Errorf("UniqueIPs = %d, want 1", stats.UniqueIPs)
	}
	if !stats.ReverseProxyDetected {
		t.Errorf("ReverseProxyDetected = false, want true (single IP)")
	}
}

// TestPreloadFromLogFile_IPDiversity_ConditionB 条件 B: UniqueIPs<=10 且 Top1Ratio>=0.90
func TestPreloadFromLogFile_IPDiversity_ConditionB(t *testing.T) {
	t.Parallel()

	baseTS := int64(1704067200)
	var events [][3]interface{}

	// 反代节点都用公网 IP（198.51.100.x 属 RFC 5737 文档化网段，不会被 isPrivateOrLocal 过滤）
	for i := 0; i < 920; i++ {
		events = append(events, [3]interface{}{baseTS + int64(i*2), "198.51.100.1", 200})
	}
	for i, suffix := range []int{2, 3, 4, 5, 6, 7, 8} {
		ip := fmt.Sprintf("198.51.100.%d", suffix)
		for j := 0; j < 12; j++ {
			events = append(events, [3]interface{}{baseTS + int64(2000 + i*10 + j), ip, 200})
		}
	}

	path := makeAccessLogFile(t, events)
	cfg := DefaultDetectorCfg()
	d := NewLocalDetector(&cfg, nil)
	defer d.Close()

	stats, err := d.PreloadFromLogFile(path, LineParser(simpleLogParser), 10)
	if err != nil {
		t.Fatalf("PreloadFromLogFile: %v", err)
	}

	if stats.UniqueIPs != 8 {
		t.Errorf("UniqueIPs = %d, want 8", stats.UniqueIPs)
	}
	if stats.Top1Ratio < 0.90 {
		t.Errorf("Top1Ratio = %.4f, want >= 0.90", stats.Top1Ratio)
	}
	if !stats.ReverseProxyDetected {
		t.Errorf("ReverseProxyDetected = false, want true (condition B)")
	}
}

// TestPreloadFromLogFile_IPDiversity_ConditionC 条件 C: UniqueIPs<=10 且 Top3Ratio>=0.98
func TestPreloadFromLogFile_IPDiversity_ConditionC(t *testing.T) {
	t.Parallel()

	baseTS := int64(1704067200)
	var events [][3]interface{}

	ips := []struct {
		ip    string
		count int
	}{
		{"198.51.100.1", 400}, {"198.51.100.2", 300}, {"198.51.100.3", 290},
		{"198.51.100.4", 3}, {"198.51.100.5", 2}, {"198.51.100.6", 2},
		{"198.51.100.7", 1}, {"198.51.100.8", 1}, {"198.51.100.9", 1}, {"198.51.100.10", 1},
	}
	total := 0
	for _, e := range ips {
		for j := 0; j < e.count; j++ {
			events = append(events, [3]interface{}{baseTS + int64(total*2), e.ip, 200})
			total++
		}
	}

	path := makeAccessLogFile(t, events)
	cfg := DefaultDetectorCfg()
	d := NewLocalDetector(&cfg, nil)
	defer d.Close()

	stats, err := d.PreloadFromLogFile(path, LineParser(simpleLogParser), 10)
	if err != nil {
		t.Fatalf("PreloadFromLogFile: %v", err)
	}

	if stats.UniqueIPs != 10 {
		t.Errorf("UniqueIPs = %d, want 10", stats.UniqueIPs)
	}
	if stats.Top3Ratio < 0.98 {
		t.Errorf("Top3Ratio = %.4f, want >= 0.98", stats.Top3Ratio)
	}
	if !stats.ReverseProxyDetected {
		t.Errorf("ReverseProxyDetected = false, want true (condition C)")
	}
}

// TestPreloadFromLogFile_IPDiversity_Normal 正常多 IP 场景不触发
func TestPreloadFromLogFile_IPDiversity_Normal(t *testing.T) {
	t.Parallel()

	baseTS := int64(1704067200)
	var events [][3]interface{}

	for i := 0; i < 20; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i+1)
		for j := 0; j < 25; j++ {
			events = append(events, [3]interface{}{baseTS + int64(i*50+j*2), ip, 200})
		}
	}

	path := makeAccessLogFile(t, events)
	cfg := DefaultDetectorCfg()
	d := NewLocalDetector(&cfg, nil)
	defer d.Close()

	stats, err := d.PreloadFromLogFile(path, LineParser(simpleLogParser), 10)
	if err != nil {
		t.Fatalf("PreloadFromLogFile: %v", err)
	}

	if stats.UniqueIPs != 20 {
		t.Errorf("UniqueIPs = %d, want 20", stats.UniqueIPs)
	}
	if stats.ReverseProxyDetected {
		t.Errorf("ReverseProxyDetected = true, want false (normal diverse traffic)")
	}
}

// TestPreloadFromLogFile_IPDiversity_LoopbackIgnored loopback/private IP 不干扰
func TestPreloadFromLogFile_IPDiversity_LoopbackIgnored(t *testing.T) {
	t.Parallel()

	baseTS := int64(1704067200)
	var events [][3]interface{}

	// 500 次 loopback 健康检查
	for i := 0; i < 500; i++ {
		events = append(events, [3]interface{}{baseTS + int64(i), "127.0.0.1", 200})
	}
	// 500 次内网探针
	for i := 0; i < 500; i++ {
		events = append(events, [3]interface{}{baseTS + int64(1000 + i), "192.168.1.100", 200})
	}
	// 15 个公网 IP × 30 次
	for i := 0; i < 15; i++ {
		ip := fmt.Sprintf("198.51.100.%d", i+1)
		for j := 0; j < 30; j++ {
			events = append(events, [3]interface{}{baseTS + int64(2000 + i*30 + j), ip, 200})
		}
	}

	path := makeAccessLogFile(t, events)
	cfg := DefaultDetectorCfg()
	d := NewLocalDetector(&cfg, nil)
	defer d.Close()

	stats, err := d.PreloadFromLogFile(path, LineParser(simpleLogParser), 10)
	if err != nil {
		t.Fatalf("PreloadFromLogFile: %v", err)
	}

	if stats.UniqueIPs != 15 {
		t.Errorf("UniqueIPs = %d, want 15 (loopback/private should be excluded)", stats.UniqueIPs)
	}
	if stats.ReverseProxyDetected {
		t.Errorf("ReverseProxyDetected = true, want false")
	}
}

// TestPreloadFromLogFile_MinutesFilter 时间窗口过滤真正生效
func TestPreloadFromLogFile_MinutesFilter(t *testing.T) {
	t.Parallel()

	baseTS := int64(1704067200)
	var events [][3]interface{}

	// 前 10 分钟：低流量（每分钟 5 次）
	for i := 0; i < 10; i++ {
		for j := 0; j < 5; j++ {
			events = append(events, [3]interface{}{baseTS + int64(i*60 + j*12), "203.0.113.1", 200})
		}
	}
	// 后 20 分钟：高流量（每分钟 100 次）
	for i := 10; i < 30; i++ {
		for j := 0; j < 100; j++ {
			ip := fmt.Sprintf("203.0.113.%d", (j%20)+1)
			events = append(events, [3]interface{}{baseTS + int64(i*60 + j), ip, 200})
		}
	}

	path := makeAccessLogFile(t, events)
	cfg := DefaultDetectorCfg()
	d := NewLocalDetector(&cfg, nil)
	defer d.Close()

	stats, err := d.PreloadFromLogFile(path, LineParser(simpleLogParser), 10)
	if err != nil {
		t.Fatalf("PreloadFromLogFile: %v", err)
	}

	t.Logf("TimeStart=%s, TimeEnd=%s", stats.TimeStart, stats.TimeEnd)
	t.Logf("TotalBuckets=%d, HealthyBuckets=%d", stats.TotalBuckets, stats.HealthyBuckets)
	t.Logf("QPS P50=%.2f P95=%.2f P99=%.2f", stats.QPSP50, stats.QPSP95, stats.QPSP99)

	if stats.QPSP95 < 0.5 {
		t.Errorf("QPS P95=%.4f too low, minutes filter may not be working (expected ~1.5+)",
			stats.QPSP95)
	}
}

// TestPreloadFromLogFile_MinutesDefault minutes<=0 时使用默认值
func TestPreloadFromLogFile_MinutesDefault(t *testing.T) {
	t.Parallel()

	baseTS := int64(1704067200)
	var events [][3]interface{}
	for i := 0; i < 100; i++ {
		ip := fmt.Sprintf("198.51.100.%d", (i%15)+1)
		events = append(events, [3]interface{}{baseTS + int64(i*10), ip, 200})
	}
	path := makeAccessLogFile(t, events)

	cfg := DefaultDetectorCfg()

	for _, m := range []int{0, -1, -999} {
		m := m
		t.Run(fmt.Sprintf("minutes=%d", m), func(t *testing.T) {
			t.Parallel()
			d := NewLocalDetector(&cfg, nil)
			defer d.Close()
			_, err := d.PreloadFromLogFile(path, LineParser(simpleLogParser), m)
			if err != nil {
				t.Fatalf("PreloadFromLogFile(minutes=%d): %v", m, err)
			}
		})
	}
}
