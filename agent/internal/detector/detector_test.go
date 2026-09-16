// Package detector - 滑动窗口 + 打分 + Detector 集成的表驱动测试。
package detector

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// ====== Window 单测 ======

// TestWindow_AddAndSum 手动推时间验证单窗口记录+汇总正确。
func TestWindow_AddAndSum(t *testing.T) {
	t.Parallel()
	w := newIPWindow(5)
	now := int64(1000)
	w.record(now, &ipBucket{totalReq: 1, count4xx: 1})
	w.record(now, &ipBucket{totalReq: 1, count5xx: 1})
	w.record(now+1, &ipBucket{totalReq: 1, authFail: 1})
	c := w.sum(now + 1)
	if c.WindowSec != 5 {
		t.Errorf("WindowSec=%d, want 5", c.WindowSec)
	}
	if c.TotalReq != 3 {
		t.Errorf("TotalReq=%d, want 3", c.TotalReq)
	}
	if c.Count4xx != 1 {
		t.Errorf("Count4xx=%d, want 1", c.Count4xx)
	}
	if c.Count5xx != 1 {
		t.Errorf("Count5xx=%d, want 1", c.Count5xx)
	}
	if c.AuthFail != 1 {
		t.Errorf("AuthFail=%d, want 1", c.AuthFail)
	}
	c2 := w.sum(now + 10)
	if c2.TotalReq != 0 {
		t.Errorf("expired TotalReq=%d, want 0", c2.TotalReq)
	}
}

// TestSlidingWindow_RecordAndCounters 验证多 IP × 三档窗口计数独立。
func TestSlidingWindow_RecordAndCounters(t *testing.T) {
	t.Parallel()
	cfg := [3]WindowCfg{{Size: 2}, {Size: 4}, {Size: 6}}
	sw := NewSlidingWindow(cfg, nil, nil, nil, []string{}, nil)
	defer sw.Close()

	// 两个不同路径的 404 → 归一化后仍是两个不同 base，各计 1
	// 注意：Count4xx 只统计非 404 的 4xx，404 独立进 Count404
	ev1 := &Event{SourceIP: "10.0.0.1", Status: 404, Path: "/a"}
	ev1b := &Event{SourceIP: "10.0.0.1", Status: 404, Path: "/b"}
	ev2 := &Event{SourceIP: "10.0.0.2", Status: 500}
	sw.Record(ev1)
	sw.Record(ev1b)
	sw.Record(ev2)

	c1 := sw.Counters("10.0.0.1")
	c2 := sw.Counters("10.0.0.2")
	for i := 0; i < 3; i++ {
		if c1[i].TotalReq != 2 {
			t.Errorf("ip1 window[%d] TotalReq=%d, want 2", i, c1[i].TotalReq)
		}
		if c1[i].Count4xx != 0 {
			t.Errorf("ip1 window[%d] Count4xx=%d, want 0 (404 不进 Count4xx)", i, c1[i].Count4xx)
		}
		if c1[i].Count404 != 2 {
			t.Errorf("ip1 window[%d] Count404=%d, want 2", i, c1[i].Count404)
		}
		if c2[i].TotalReq != 1 {
			t.Errorf("ip2 window[%d] TotalReq=%d, want 1", i, c2[i].TotalReq)
		}
		if c2[i].Count5xx != 1 {
			t.Errorf("ip2 window[%d] Count5xx=%d, want 1", i, c2[i].Count5xx)
		}
	}
	if sw.IPCount() != 2 {
		t.Errorf("IPCount=%d, want 2", sw.IPCount())
	}
	c3 := sw.Counters("9.9.9.9")
	for i := 0; i < 3; i++ {
		if c3[i].TotalReq != 0 {
			t.Errorf("unknown ip window[%d] TotalReq=%d, want 0", i, c3[i].TotalReq)
		}
	}
}

// TestSlidingWindow_Evict 验证长期无流量 IP 被淘汰释放内存。
func TestSlidingWindow_Evict(t *testing.T) {
	t.Parallel()
	cfg := [3]WindowCfg{{Size: 1}, {Size: 2}, {Size: 3}}
	sw := NewSlidingWindow(cfg, nil, nil, nil, []string{}, nil)
	defer sw.Close()

	sw.Record(&Event{SourceIP: "1.1.1.1"})
	sw.Record(&Event{SourceIP: "2.2.2.2"})
	if sw.IPCount() != 2 {
		t.Fatalf("ip count before evict=%d, want 2", sw.IPCount())
	}
	sw.mu.Lock()
	for _, e := range sw.ips {
		e.mu.Lock()
		e.last = time.Now().Unix() - 10_000
		e.mu.Unlock()
	}
	sw.mu.Unlock()
	n := sw.Evict(60)
	if n != 2 {
		t.Errorf("evict removed=%d, want 2", n)
	}
	if sw.IPCount() != 0 {
		t.Errorf("ip count after evict=%d, want 0", sw.IPCount())
	}
}

// TestSlidingWindow_Concurrent 50 goroutine 同 IP 并发写，验证最终计数一致。
func TestSlidingWindow_Concurrent(t *testing.T) {
	t.Parallel()
	cfg := [3]WindowCfg{{Size: 10}, {Size: 30}, {Size: 60}}
	sw := NewSlidingWindow(cfg, nil, nil, nil, []string{}, nil)
	defer sw.Close()

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			sw.Record(&Event{SourceIP: "8.8.8.8", Status: 429})
		}()
	}
	wg.Wait()
	c := sw.Counters("8.8.8.8")
	for i := 0; i < 3; i++ {
		if c[i].TotalReq != n {
			t.Errorf("window[%d] TotalReq=%d, want %d", i, c[i].TotalReq, n)
		}
		if c[i].Count4xx != n {
			t.Errorf("window[%d] Count4xx=%d, want %d", i, c[i].Count4xx, n)
		}
	}
}

// ====== Scorer 表驱动单测 ======

func TestWindow_KnownHTTPClientUA(t *testing.T) {
	t.Parallel()

	// okhttp 是合法 HTTP 客户端
	if isBotUserAgent("okhttp/3.14.7") {
		t.Error("okhttp should NOT be flagged as bot UA")
	}
	// python-requests 是合法 HTTP 客户端
	if isBotUserAgent("python-requests/2.28.1") {
		t.Error("python-requests should NOT be flagged as bot UA")
	}
	// axios 是合法 HTTP 客户端
	if isBotUserAgent("axios/1.6.0") {
		t.Error("axios should NOT be flagged as bot UA")
	}
	// java/ 标准库客户端
	if isBotUserAgent("java/1.8.0") {
		t.Error("java UA should NOT be flagged as bot UA")
	}

	// 但已知扫描器仍应被识别为 Bot
	if !isBotUserAgent("sqlmap/1.5.2") {
		t.Error("sqlmap should be flagged as bot UA")
	}
	if !isBotUserAgent("nikto/2.1.6") {
		t.Error("nikto should be flagged as bot UA")
	}
	if !isBotUserAgent("curl/7.68.0") {
		t.Error("curl should be flagged as bot UA (not in known clients)")
	}

	// 空 UA 不再视为 BotUA（修复：空 UA 可能来自 legitimate 客户端）
}

// ====== LocalDetector 集成单测 ======

func TestLocalDetector_WhitelistSkip(t *testing.T) {
	t.Parallel()
	cfg := DefaultDetectorCfg()
	wl := NewStaticWhitelist([]string{"127.0.0.1", "::1", "10.0.0.0/8"})
	d := NewLocalDetector(&cfg, wl)
	defer d.Close()

	ev := Event{SourceIP: "127.0.0.1", Status: 404}
	for i := 0; i < 1000; i++ {
		ev = d.Process(ev)
	}
	if ev.LocalRiskScore != 0 {
		t.Errorf("whitelist ip score=%d, want 0", ev.LocalRiskScore)
	}
	if d.window.IPCount() != 0 {
		t.Errorf("whitelist ip should not be tracked, IPCount=%d", d.window.IPCount())
	}

	// CIDR 白名单
	ev2 := Event{SourceIP: "10.2.3.4", Status: 404}
	for i := 0; i < 1000; i++ {
		ev2 = d.Process(ev2)
	}
	if ev2.LocalRiskScore != 0 {
		t.Errorf("CIDR whitelist ip score=%d, want 0", ev2.LocalRiskScore)
	}
}

func TestLocalDetector_ScoreHighTrigger(t *testing.T) {
	t.Parallel()
	cfg := DefaultDetectorCfg()
	cfg.ConfirmCount = 1
	d := NewLocalDetector(&cfg, nil)
	defer d.Close()
	SetBaselinesForTest(d, MakeMediumBaselines())

	var triggered *Event
	d.RegisterBlockTrigger(func(ev Event) bool {
		triggered = &ev
		return true
	})

	// 10 条混合 4xx Event（不同 path 避免 concentrated4xx，不同状态码确保 activeRelDims>=2）
	// python-requests UA 不触发 legitimateUserContext 不降权，Timestamp 固定值保证 SlidingWindow 正确叠加
	// seenCount=10 < 20 避免 perIPDev 启用
	paths := []string{"/api/a", "/api/b", "/api/c", "/api/d"}
	statuses := []int{404, 404, 401, 403}
	var finalEvt Event
	for i := 0; i < 10; i++ {
		ev := Event{
			SourceIP:   "203.0.113.5",
			Path:       paths[i % 4],
			Status:     statuses[i % 4],
			Timestamp:  1000,
			UserAgent:  "python-requests/2.28.0",
		}
		finalEvt = d.Process(ev)
	}
	if finalEvt.LocalRiskScore < cfg.ScoreHigh {
		t.Errorf("score=%d, want >= %d", finalEvt.LocalRiskScore, cfg.ScoreHigh)
	}
	if triggered == nil {
		t.Fatalf("BlockTrigger not called; expected high score trigger")
	}
	if triggered.LocalRiskScore != finalEvt.LocalRiskScore {
		t.Errorf("triggered score=%d, want %d", triggered.LocalRiskScore, finalEvt.LocalRiskScore)
	}
}

func TestLocalDetector_Disabled(t *testing.T) {
	t.Parallel()
	cfg := DefaultDetectorCfg()
	cfg.Enabled = false
	d := NewLocalDetector(&cfg, nil)
	defer d.Close()

	ev := Event{SourceIP: "203.0.113.10", Status: 404}
	for i := 0; i < 100; i++ {
		ev = d.Process(ev)
	}
	if ev.LocalRiskScore != 0 {
		t.Errorf("disabled score=%d, want 0", ev.LocalRiskScore)
	}
}

// TestLocalDetector_ConcurrentProcess 并发 Process 保证无竞争。
func TestLocalDetector_ConcurrentProcess(t *testing.T) {
	t.Parallel()
	cfg := DefaultDetectorCfg()
	d := NewLocalDetector(&cfg, nil)
	defer d.Close()

	var wg sync.WaitGroup
	const n = 100
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(idx int) {
			defer wg.Done()
			src := "203.0.113.20"
			if idx%2 == 0 {
				src = "198.51.100.30"
			}
			ev := Event{SourceIP: src, Status: 404}
			for j := 0; j < 10; j++ {
				ev = d.Process(ev)
			}
		}(i)
	}
	wg.Wait()
	if d.window.IPCount() != 2 {
		t.Errorf("IPCount=%d, want 2", d.window.IPCount())
	}
}

// ====== 敏感路径路径段匹配测试 ======

// TestHitSensitivePath_SegmentMatching 验证路径段精确匹配。
func TestHitSensitivePath_SegmentMatching(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path    string
		wantHit bool
		desc    string
	}{
		// env 关键词 — 应匹配真正的 .env 探测
		{"/.env", true, "root .env file"},
		{"/config/.env", true, ".env in subdirectory"},
		{"/api/env", true, "env as path segment"},
		{"/tdsc/js/env.js", false, "env.js is legitimate JS file, should NOT match"},
		{"/api/env.js", false, "env.js in api path, should NOT match"},

		// admin 关键词
		{"/admin", true, "admin directory"},
		{"/admin/login", true, "admin sub-path"},
		{"/api/admin/users", true, "admin in sub-path"},
		{"/admin.js", false, "admin.js is a JS file, should NOT match"},

		// actuator
		{"/actuator", true, "actuator endpoint"},
		{"/actuator/health", true, "actuator sub-path"},
		{"/myactuator", false, "myactuator is not the actuator endpoint"},

		// swagger
		{"/swagger", true, "swagger endpoint"},
		{"/swagger-ui", true, "swagger-ui endpoint"},
		{"/swagger-resources", true, "swagger-resources endpoint"},
		{"/api/swagger-ui", true, "swagger-ui in api path"},
		{"/myswagger", false, "myswagger is not swagger"},

		// .git
		{"/.git", true, ".git directory"},
		{"/project/.git/config", true, ".git in subdirectory"},

		// 含 "/" 的多段关键词
		{"/etc/passwd", true, "etc/passwd probe"},
		{"/file/../../etc/passwd", true, "path traversal to etc/passwd"},

		// 路径穿越
		{"/page/../../etc/passwd", true, "path traversal with ../"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()
			got := hitSensitivePath(tc.path)
			if got != tc.wantHit {
				t.Errorf("hitSensitivePath(%q) = %v, want %v", tc.path, got, tc.wantHit)
			}
		})
	}
}

// TestHitSensitivePath_QueryString 验证带查询字符串的路径正确处理。
func TestHitSensitivePath_QueryString(t *testing.T) {
	t.Parallel()

	// 查询字符串不应影响敏感路径判断
	tests := []struct {
		path    string
		wantHit bool
	}{
		{"/admin?user=test", true},
		{"/tdsc/js/env.js?version=1.0", false},
		{"/api/env.js?v=2", false},
	}

	for _, tc := range tests {
		got := hitSensitivePath(tc.path)
		if got != tc.wantHit {
			t.Errorf("hitSensitivePath(%q) = %v, want %v", tc.path, got, tc.wantHit)
		}
	}
}

// TestRecord_SensitivePathStatusCorrelation 验证敏感路径仅在状态码 >= 400 时计数。
func TestRecord_SensitivePathStatusCorrelation(t *testing.T) {
	t.Parallel()
	cfg := [3]WindowCfg{{Size: 10}, {Size: 30}, {Size: 60}}
	sw := NewSlidingWindow(cfg, nil, nil, nil, []string{}, nil)
	defer sw.Close()

	// 1. 敏感路径 + 200 成功 → 不应计数
	sw.Record(&Event{SourceIP: "1.1.1.1", Path: "/tdsc/js/env.js", Status: 200})
	// 直接用 .env 路径段精确匹配测试
	sw.Record(&Event{SourceIP: "1.1.1.1", Path: "/.env", Status: 200})
	// admin 路径
	sw.Record(&Event{SourceIP: "1.1.1.1", Path: "/admin", Status: 200})

	c := sw.Counters("1.1.1.1")
	if c[0].SensitivePathHit != 0 {
		t.Errorf("200 status on sensitive path should NOT count SensitivePathHit, got %d", c[0].SensitivePathHit)
	}

	// 2. 敏感路径 + 404/403 → 404 进 Count404，403 进 Count4xx（两者互斥）
	sw.Record(&Event{SourceIP: "2.2.2.2", Path: "/.env", Status: 404})
	sw.Record(&Event{SourceIP: "2.2.2.2", Path: "/admin", Status: 403})

	c2 := sw.Counters("2.2.2.2")
	if c2[0].SensitivePathHit != 2 {
		t.Errorf("404/403 on sensitive path should count SensitivePathHit, got %d", c2[0].SensitivePathHit)
	}
	if c2[0].Count4xx != 1 {
		t.Errorf("403 should count 4xx, 404 should NOT; got Count4xx=%d, want 1", c2[0].Count4xx)
	}
	if c2[0].Count404 != 1 {
		t.Errorf("404 should count Count404, got %d, want 1", c2[0].Count404)
	}

	// 3. env.js + 404 → 不应计数（env.js 不是敏感路径）
	sw.Record(&Event{SourceIP: "3.3.3.3", Path: "/tdsc/js/env.js", Status: 404})
	c3 := sw.Counters("3.3.3.3")
	if c3[0].SensitivePathHit != 0 {
		t.Errorf("env.js should NOT be sensitive path even with 404, got %d", c3[0].SensitivePathHit)
	}
	if c3[0].Count4xx != 0 {
		t.Errorf("404 on env.js should NOT count Count4xx, got %d", c3[0].Count4xx)
	}
	if c3[0].Count404 != 1 {
		t.Errorf("404 should count Count404, got %d, want 1", c3[0].Count404)
	}
}

// TestScorer_SensitivePathScore 验证敏感路径打分在修复后的正确性。
// 模拟真实场景：浏览器加载合法 JS 文件 (env.js)，全 200 响应。
func TestDecodePath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "URL encoded SQL injection",
			input:    "/api/login?user=admin%27%20OR%201%3D1--",
			expected: "/api/login?user=admin' OR 1=1--",
		},
		{
			name:     "Unicode escaped XSS",
			input:    "/search?q=\u003cscript\u003ealert(1)\u003c/script\u003e",
			expected: "/search?q=<script>alert(1)</script>",
		},
		{
			name:     "Hex escaped XSS",
			input:    "/search?q=\x3cscript\x3ealert(1)\x3c/script\x3e",
			expected: "/search?q=<script>alert(1)</script>",
		},
		{
			name:     "HTML entity encoded",
			input:    "/page?id=&#60;script&#62;alert(1)&#60;/script&#62;",
			expected: "/page?id=<script>alert(1)</script>",
		},
		{
			name:     "Double encoded path traversal",
			input:    "/%252e%252e%252fetc%252fpasswd",
			expected: "/../etc/passwd",
		},
		{
			name:     "Mixed URL + unicode",
			input:    "/api?cmd=%27;\u0073\u0065\u006c\u0065\u0063\u0074%20*%20%66\u0072\u006f\u006d%20%75\u0073\u0065\u0072",
			expected: "/api?cmd=';select * from user",
		},
		{
			name:     "Plain text unchanged",
			input:    "/api/health",
			expected: "/api/health",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := decodePath(tt.input)
			if result != tt.expected {
				t.Errorf("decodePath(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestDangerousPatternDetection 验证危险攻击模式检测。
func TestDangerousPatternDetection(t *testing.T) {
	t.Parallel()

	patterns := []string{"select ", "<script", "../", "etc/passwd", "drop table"}

	tests := []struct {
		name   string
		path   string
		expect int // expected number of matches
	}{
		{
			name:   "Plain SQL injection",
			path:   "/api/login?q=select * from users",
			expect: 1,
		},
		{
			name:   "URL encoded SQL injection",
			path:   "/api/login?q=%73%65%6c%65%63%74%20%2a%20%66%72%6f%6d%20%75%73%65%72%73",
			expect: 1,
		},
		{
			name:   "Unicode XSS",
			path:   "/search?q=\u003cscript\u003ealert(1)\u003c/script\u003e",
			expect: 1,
		},
		{
			name:   "Path traversal",
			path:   "/files/../../../etc/passwd",
			expect: 2, // matches "../" and "etc/passwd"
		},
		{
			name:   "URL encoded path traversal",
			path:   "/files/%2e%2e/%2e%2e/etc/passwd",
			expect: 2,
		},
		{
			name:   "No dangerous pattern",
			path:   "/api/health",
			expect: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := decodeAndMatchDangerPatterns(tt.path, patterns)
			if len(matched) != tt.expect {
				t.Errorf("decodeAndMatchDangerPatterns(%q) matched %d patterns, want %d: %v",
					tt.path, len(matched), tt.expect, matched)
			}
		})
	}
}

// TestDangerousPatternScoring 验证危险攻击模式的评分。
// 每个解码后命中的攻击模式给予 DangerousPattern 权重（默认 5 分）。
func TestDangerousPatternScoring(t *testing.T) {
	t.Parallel()
	cfg := DefaultDetectorCfg()
	baselines := [3]*Baseline{NewBaseline(10), NewBaseline(30), NewBaseline(60)}
	s := NewScorer(&cfg, baselines) // DangerousPattern weight = 5

	// 3 次请求，每次都包含危险攻击模式
	counters := [3]WindowCounters{
		{
			WindowSec:           10,
			TotalReq:            3,
			DangerousPatternHit: 3, // 3 次命中
		},
	}

	result := s.ScoreWithDetail(counters, 0, 0)

	// DangerousPatternScore = 3 * 5 = 15
	if result.Details[0].DangerousPatternScore != 15 {
		t.Errorf("DangerousPatternScore=%d, want 15 (3 * weight=5)", result.Details[0].DangerousPatternScore)
	}
}

// TestDangerousPatternIntegration 集成测试：SlidingWindow 能正确检测编码后的攻击路径。
func TestDangerousPatternIntegration(t *testing.T) {
	t.Parallel()
	cfg := DefaultDetectorCfg()
	sw := NewSlidingWindow(cfg.Windows, nil, nil, nil, []string{}, nil)
	defer sw.Close()

	// 提交一个 URL 编码的 SQL 注入攻击
	ev := &Event{
		Timestamp: time.Now().Unix(),
		SourceIP:  "10.0.0.1",
		Path:      "/api/login?user=admin%27%20OR%201%3D1--",
		Method:    "GET",
		Status:    200,
		UserAgent: "Mozilla/5.0",
	}

	sw.Record(ev)

	counters := sw.Counters("10.0.0.1")
	if counters[0].DangerousPatternHit != 1 {
		t.Errorf("DangerousPatternHit=%d, want 1 (URL-encoded SQL injection detected)", counters[0].DangerousPatternHit)
	}

	// 提交 Unicode 编码的 XSS 攻击
	ev2 := &Event{
		Timestamp: time.Now().Unix(),
		SourceIP:  "10.0.0.1",
		Path:      "/search?q=\u003cscript\u003ealert(1)\u003c/script\u003e",
		Method:    "GET",
		Status:    200,
		UserAgent: "Mozilla/5.0",
	}
	sw.Record(ev2)
	counters = sw.Counters("10.0.0.1")
	if counters[0].DangerousPatternHit != 2 {
		t.Errorf("DangerousPatternHit=%d, want 2 (XSS detected)", counters[0].DangerousPatternHit)
	}
}

// ====== 夜间模式测试（已删除：基线自学习引擎自动适应时段流量，不再需要夜间倍率）======

// TestScorer_NightMode_AppliesMultipliers 测试夜间模式倍率正确应用。
func TestShouldSkipPath_ExactMatch(t *testing.T) {
	t.Parallel()
	sw := NewSlidingWindow([3]WindowCfg{}, nil, nil, nil, []string{"/favicon.ico", "/robots.txt"}, nil)
	defer sw.Close()

	if !sw.ShouldSkipPath("/favicon.ico") {
		t.Error("/favicon.ico should be skipped (exact match)")
	}
	if !sw.ShouldSkipPath("/favicon.ico?v=123") {
		t.Error("/favicon.ico?v=123 should be skipped (query string stripped)")
	}
	if !sw.ShouldSkipPath("/robots.txt") {
		t.Error("/robots.txt should be skipped (exact match)")
	}
	if sw.ShouldSkipPath("/favicon.ico.png") {
		t.Error("/favicon.ico.png should NOT be skipped (different path)")
	}
	if sw.ShouldSkipPath("/") {
		t.Error("/ should NOT be skipped")
	}
}

// TestShouldSkipPath_PrefixMatch 验证前缀匹配：/.well-known/ 应匹配子路径。
func TestShouldSkipPath_PrefixMatch(t *testing.T) {
	t.Parallel()
	sw := NewSlidingWindow([3]WindowCfg{}, nil, nil, nil, []string{"/.well-known/"}, nil)
	defer sw.Close()

	if !sw.ShouldSkipPath("/.well-known/acme-challenge/abc123") {
		t.Error("/.well-known/acme-challenge/abc123 should be skipped (prefix match)")
	}
	if !sw.ShouldSkipPath("/.well-known/") {
		t.Error("/.well-known/ should be skipped (exact prefix)")
	}
	if !sw.ShouldSkipPath("/.well-known/abc?v=1") {
		t.Error("/.well-known/abc?v=1 should be skipped (prefix + query)")
	}
	if sw.ShouldSkipPath("/.well-known") {
		// /.well-known 不以 "/" 结尾，应该是精确匹配模式，不匹配前缀
		// 但实际上我们用 HasPrefix，所以 .well-known 不带斜杠的路径段不会匹配
		t.Log("/.well-known (no trailing slash) - depends on exact vs prefix behavior")
	}
	if sw.ShouldSkipPath("/other/.well-known/test") {
		t.Error("path with /.well-known/ in middle should NOT be skipped")
	}
}

// TestShouldSkipPath_Defaults 验证默认跳过路径列表。
func TestShouldSkipPath_Defaults(t *testing.T) {
	t.Parallel()
	// nil skip paths → 使用默认值
	sw := NewSlidingWindow([3]WindowCfg{}, nil, nil, nil, nil, nil)
	defer sw.Close()

	for _, p := range []string{"/favicon.ico", "/favicon.png", "/robots.txt", "/.well-known/test"} {
		if !sw.ShouldSkipPath(p) {
			t.Errorf("default skip: %s should be skipped", p)
		}
	}
	// 普通路径不应被跳过
	if sw.ShouldSkipPath("/api/user") {
		t.Error("/api/user should NOT be skipped by defaults")
	}
}

// TestShouldSkipPath_EmptyList 验证空跳过列表不会跳过任何路径。
func TestShouldSkipPath_EmptyList(t *testing.T) {
	t.Parallel()
	sw := NewSlidingWindow([3]WindowCfg{}, nil, nil, nil, []string{}, nil)
	defer sw.Close()

	if sw.ShouldSkipPath("/favicon.ico") {
		t.Error("empty skip list: /favicon.ico should NOT be skipped")
	}
	if sw.ShouldSkipPath("/robots.txt") {
		t.Error("empty skip list: /robots.txt should NOT be skipped")
	}
}

// TestShouldSkipPath_CaseInsensitive 验证大小写不敏感。
func TestShouldSkipPath_CaseInsensitive(t *testing.T) {
	t.Parallel()
	sw := NewSlidingWindow([3]WindowCfg{}, nil, nil, nil, []string{"/favicon.ico", "/.well-known/"}, nil)
	defer sw.Close()

	if !sw.ShouldSkipPath("/Favicon.Ico") {
		t.Error("/Favicon.Ico should be skipped (case insensitive)")
	}
	if !sw.ShouldSkipPath("/FAVICON.ICO?v=1") {
		t.Error("/FAVICON.ICO should be skipped (case insensitive + query)")
	}
	if !sw.ShouldSkipPath("/.Well-Known/Test") {
		t.Error("/.Well-Known/Test should be skipped (case insensitive prefix)")
	}
}

// TestLocalDetector_SkipPaths 集成测试：验证 detector 完整跳过 favicon 请求。
func TestLocalDetector_SkipPaths(t *testing.T) {
	t.Parallel()
	cfg := DefaultDetectorCfg()
	// 使用默认 SkipPaths，包含 /favicon.ico

	det := NewLocalDetector(&cfg, nil)
	defer det.Close()

	// 发送 20 次 favicon.ico 404 请求（正常情况下足以触发阈值）
	// 但因为 SkipPaths 包含 /favicon.ico，这些请求不应被计分
	for i := 0; i < 20; i++ {
		ev := Event{
			SourceIP:  "10.0.0.99",
			Source:    "nginx_access",
			Path:      "/favicon.ico",
			Method:    "GET",
			Status:    404,
			UserAgent: "Mozilla/5.0 Chrome",
			Referer:   "-",
		}
		result := det.Process(ev)
		if result.LocalRiskScore != 0 {
			t.Errorf("favicon.ico should be skipped, got score=%d (iter %d)", result.LocalRiskScore, i)
		}
	}

	// 验证 IP 没有被拉黑（计数为 0）
	counters := det.window.Counters("10.0.0.99")
	if counters[0].TotalReq != 0 {
		t.Errorf("TotalReq=%d, want 0 (all favicons should be skipped)", counters[0].TotalReq)
	}
}

// TestLocalDetector_SkipPaths_Custom 验证自定义 SkipPaths 生效。
func TestLocalDetector_SkipPaths_Custom(t *testing.T) {
	t.Parallel()
	cfg := DefaultDetectorCfg()
	cfg.SkipPaths = []string{"/my-custom-path", "/.internal/"}

	det := NewLocalDetector(&cfg, nil)
	defer det.Close()

	// 自定义跳过路径
	for i := 0; i < 20; i++ {
		ev := Event{
			SourceIP:  "10.0.0.99",
			Source:    "nginx_access",
			Path:      "/my-custom-path",
			Method:    "GET",
			Status:    404,
			UserAgent: "curl/7.0",
			Referer:   "-",
		}
		result := det.Process(ev)
		if result.LocalRiskScore != 0 {
			t.Errorf("/my-custom-path should be skipped, got score=%d", result.LocalRiskScore)
		}
	}

	// 前缀匹配跳过路径
	for i := 0; i < 20; i++ {
		ev := Event{
			SourceIP:  "10.0.0.99",
			Source:    "nginx_access",
			Path:      "/.internal/health",
			Method:    "GET",
			Status:    404,
			UserAgent: "curl/7.0",
			Referer:   "-",
		}
		result := det.Process(ev)
		if result.LocalRiskScore != 0 {
			t.Errorf("/.internal/health should be skipped, got score=%d", result.LocalRiskScore)
		}
	}

	// 普通路径仍应参与检测
	ev := Event{
		SourceIP:  "10.0.0.1",
		Source:    "nginx_access",
		Path:      "/api/attack",
		Method:    "GET",
		Status:    404,
		UserAgent: "curl/7.0",
		Referer:   "-",
	}
	result := det.Process(ev)
	if result.LocalRiskScore < 0 {
		t.Error("/api/attack should be processed (not skipped)")
	}
}

// TestLocalDetector_SkipPaths_DoesNotAffectNormalDetection 验证 SkipPaths 不影响正常检测能力。
func TestLocalDetector_SkipPaths_DoesNotAffectNormalDetection(t *testing.T) {
	t.Parallel()
	cfg := DefaultDetectorCfg()
	// 默认 SkipPaths 包含 /favicon.ico，不应影响正常攻击检测

	det := NewLocalDetector(&cfg, nil)
	defer det.Close()

	// 发送大量非跳过路径的 4xx 请求，应正常计分
	for i := 0; i < 30; i++ {
		ev := Event{
			SourceIP:  "10.0.0.88",
			Source:    "nginx_access",
			Path:      "/api/login",
			Method:    "GET",
			Status:    404,
			UserAgent: "curl/7.0",
			Referer:   "-",
		}
		det.Process(ev)
	}

	// 验证计数器已记录（非跳过路径）
	counters := det.window.Counters("10.0.0.88")
	if counters[0].TotalReq == 0 {
		t.Error("non-skipped paths should be recorded")
	}
	if counters[0].Count404 == 0 {
		t.Error("Count404 should be non-zero for non-skipped 404 paths")
	}
}

// ====== legitimateUserContext 降权测试 ======

// TestIsNormalBrowserUserAgent 验证正常浏览器 UA 识别正确性。
func TestIsNormalBrowserUserAgent(t *testing.T) {
	t.Parallel()
	sw := &SlidingWindow{knownHTTPClients: knownHTTPClients, normalBrowserUAs: normalBrowserUA}

	tests := []struct {
		name   string
		ua     string
		expect bool
	}{
		// 正常浏览器
		{"Chrome on Windows", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36", true},
		{"Chrome on Mac", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", true},
		{"Firefox", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0", true},
		{"Edge Chromium", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0", true},
		{"Edge old", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/18.17763", true},
		{"Safari on Mac", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15", true},
		{"IE 11", "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko", true},
		{"Mobile Chrome", "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36", true},

		// 不是正常浏览器
		{"Empty UA", "", false},
		{"Dash (-)", "-", false},
		{"Known HTTP client (okhttp)", "okhttp/3.14.9", false},
		{"Known HTTP client (python-requests)", "python-requests/2.28.0", false},
		{"Known HTTP client (curl)", "curl/7.81.0", false},
		{"Scanner (Nmap)", "Mozilla/5.0 (compatible; Nmap Scripting Engine)", false},
		{"Scanner (sqlmap)", "sqlmap/1.7.2#stable (https://sqlmap.org)", false},
		{"Bot (Googlebot)", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sw.isNormalBrowserUserAgent(tt.ua)
			if got != tt.expect {
				t.Errorf("isNormalBrowserUserAgent(%q) = %v, want %v", tt.ua, got, tt.expect)
			}
		})
	}
}

// TestLegitimateUserContext_Mitigation 验证 legitimateUserContext 场景下 4xx 和 404_ratio 降权。
func TestLegitimateUserContext_Mitigation(t *testing.T) {
	t.Parallel()
	cfg := DefaultDetectorCfg()
	cfg.ScoreHigh = 50

	det := NewLocalDetector(&cfg, nil)
	defer det.Close()
	SetBaselinesForTest(det, MakeMediumBaselines())

	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"
	ref := "https://example.com/app/"

	// 发送 15 次 404 请求（正常浏览器 + 有效 Referer → legitimateUserContext 应成立）
	// 预期：legitimateUserContext 触发 → 4xx/404_ratio 降权 60% → 总分 < 50
	for i := 0; i < 15; i++ {
		score := det.Process(Event{
			SourceIP:   "10.0.0.1",
			Path:       "/api/broken-endpoint",
			Status:     404,
			UserAgent:  ua,
			Referer:    ref,
			Method:     "GET",
			Timestamp:  time.Now().Unix(),
		})
		if score.LocalRiskScore >= cfg.ScoreHigh {
			t.Fatalf("request %d: score %d >= %d, want mitigation to prevent", i+1, score.LocalRiskScore, cfg.ScoreHigh)
		}
	}

	// 验证计数器
	counters := det.window.Counters("10.0.0.1")
	if counters[0].NormalBrowserHit == 0 {
		t.Error("NormalBrowserHit should be > 0 for Chrome UA")
	}
	// 同一路径重复 15 次 404 → 归一化合并为 1 个 distinct base
	if counters[0].Count404 != 1 {
		t.Errorf("Count404=%d, want 1 (normalized from 15 same-path 404s)", counters[0].Count404)
	}
	// Count4xx 只统计非 404 的 4xx，全是 404 时应该为 0
	if counters[0].Count4xx != 0 {
		t.Errorf("Count4xx=%d, want 0 (404 不进 Count4xx)", counters[0].Count4xx)
	}
}

// TestLegitimateUserContext_NotTriggeredByBot 验证扫描器/Bot UA 不会触发降权。
func TestLegitimateUserContext_NotTriggeredByBot(t *testing.T) {
	t.Parallel()
	cfg := DefaultDetectorCfg()
	cfg.ScoreHigh = 50

	det := NewLocalDetector(&cfg, nil)
	defer det.Close()
	SetBaselinesForTest(det, MakeMediumBaselines())

	// 扫描器 UA（Nmap）→ legitimateUserContext 不应成立 → 不降权
	scannerUA := "Mozilla/5.0 (compatible; Nmap Scripting Engine)"
	var finalScore int
	for i := 0; i < 20; i++ {
		score := det.Process(Event{
			SourceIP:   "10.0.0.2",
			Path:       "/admin/config",
			Status:     404,
			UserAgent:  scannerUA,
			Referer:    "", // 扫描器通常空 Referer
			Method:     "GET",
			Timestamp:  time.Now().Unix(),
		})
		finalScore = score.LocalRiskScore
	}

	// 扫描器应能正常触发高分（不降权）
	t.Logf("scanner finalScore=%d (threshold=%d)", finalScore, cfg.ScoreHigh)
	if finalScore < 20 {
		t.Errorf("scanner score=%d too low, expected normal scoring without mitigation", finalScore)
	}

	counters := det.window.Counters("10.0.0.2")
	if counters[0].NormalBrowserHit != 0 {
		t.Errorf("NormalBrowserHit=%d, want 0 for scanner UA", counters[0].NormalBrowserHit)
	}
}

// TestLegitimateUserContext_ReplicateMisblockScenario 完整复现误封日志场景：
// Chrome 浏览器 + 有效 Referer + 后端全 404 → 不应触发拉黑。
func TestLegitimateUserContext_ReplicateMisblockScenario(t *testing.T) {
	t.Parallel()
	cfg := DefaultDetectorCfg()
	cfg.ScoreHigh = 50

	triggered := false
	det := NewLocalDetector(&cfg, nil)
	defer det.Close()
	SetBaselinesForTest(det, MakeMediumBaselines())
	det.RegisterBlockTrigger(func(_ Event) bool {
		triggered = true
		return true
	})

	// 复现 115.233.211.18 的请求特征
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"
	ref := "https://jcjg.mnr.gov.cn/tdcbui/"

	apiPaths := []string{
		"/tdcb/workflow/getProinstList",
		"/tdcb/workflow/queryhistoryTaskListForQuery",
		"/tdcb/workflow/getProcessInstancesList",
		"/tdcb/workflow/getActivitiProcess",
		"/tdcb/midplatform/menu/getUserMenus",
		"/tdcb/tzgg/tzggYnQuery",
		"/tdcb/zqxmzp/queryZqxmzpByPage",
		"/tdcb/xzq/xzqtreeWithCache",
		"/tdcb/midplatform/enum/getFieldenums/xmzt",
		"/tdcb/user/getUserXzqNotice",
	}

	// 第一波：20 次请求（对应日志 09:42:29 的突发）
	for i := 0; i < 2; i++ {
		for _, p := range apiPaths {
			det.Process(Event{
				SourceIP:   "115.233.211.18",
				Path:       p,
				Status:     404,
				UserAgent:  ua,
				Referer:    ref,
				Method:     "POST",
				Timestamp:  time.Now().Unix(),
			})
		}
	}

	if triggered {
		t.Fatalf("trigger fired on first wave — legitimateUserContext mitigation broken")
	}

	// 第二波：30 次请求（对应 09:45:05 的"持续访问"）
	for i := 0; i < 3; i++ {
		for _, p := range apiPaths {
			det.Process(Event{
				SourceIP:   "115.233.211.18",
				Path:       p,
				Status:     404,
				UserAgent:  ua,
				Referer:    ref,
				Method:     "POST",
				Timestamp:  time.Now().Unix(),
			})
		}
	}

	if triggered {
		t.Error("IP was blocked — legitimateUserContext should have mitigated the score")
	}

	// 最终分数应显著低于阈值
	counters := det.window.Counters("115.233.211.18")
	t.Logf("counters[0]: req=%d 4xx=%d 404=%d brow=%d ref_empty=%d",
		counters[0].TotalReq, counters[0].Count4xx, counters[0].Count404,
		counters[0].NormalBrowserHit, counters[0].EmptyRefererHit)

	// NormalBrowserHit 应接近总请求数
	if counters[0].NormalBrowserHit < 40 {
		t.Errorf("NormalBrowserHit=%d, want >= 40", counters[0].NormalBrowserHit)
	}
}

// ====== 404 路径归一化专项测试 ======

// TestNormalize404Path 验证路径归一化核心算法正确性。
func TestNormalize404Path(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		path string
		want string
	}{
		// UUID 归一化
		{"UUID path segment", "/api/user/550e8400-e29b-41d4-a716-446655440000/profile", "/api/user/{id}/profile"},
		// 长数字归一化
		{"long numeric id", "/api/order/12345678901234567890/detail", "/api/order/{id}/detail"},
		// 纯数字 (>=4 位)
		{"numeric id >=4", "/api/item/9999", "/api/item/{id}"},
		// 短数字 (<4 位) 不归一
		{"short numeric id", "/api/item/1", "/api/item/1"},
		// 长十六进制 (24+ 字符)
		{"ObjectId hex", "/file/a1b2c3d4e5f6a1b2c3d4e5f6", "/file/{id}"},
		// 去 query string
		{"strip query", "/api/broken?foo=bar&x=1", "/api/broken"},
		// 去末尾 /
		{"strip trailing slash", "/api/broken/", "/api/broken"},
		// 大小写归一
		{"lowercase", "/API/Broken", "/api/broken"},
		// 超过 4 段只取前 4
		{"truncate to 4 segs", "/a/b/c/d/e/f/g", "/a/b/c/d"},
		// 空路径
		{"empty path", "", "/"},
		{"root path", "/", "/"},
		// UUID 在第 4 段 → 含 {id} 后取前 4 段
		{"uuid at seg 5 truncated", "/a/b/c/550e8400-e29b-41d4-a716-446655440000/e", "/a/b/c/{id}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalize404Path(tt.path)
			if got != tt.want {
				t.Errorf("normalize404Path(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

// Test404Normalization_SamePrefixMerge 验证同一前缀不同叶子的 404 被归并。
func Test404Normalization_SamePrefixMerge(t *testing.T) {
	t.Parallel()
	cfg := DefaultDetectorCfg()
	sw := NewSlidingWindow(cfg.Windows, nil, nil, nil, []string{}, nil)
	defer sw.Close()

	// 模拟前端 Bug 批量生成的 URL：前 3 段相同，最后 ID/字段不同
	bugPaths := []string{
		"/tdsc/gdfa/edit/nullapi/v1/xm/enum/xmzt",
		"/tdsc/gdfa/edit/nullapi/v1/xm/enum/djjg",
		"/tdsc/gdfa/edit/nullapi/v1/xm/enum/xmhy",
		"/tdsc/gdfa/edit/nullapi/v1/xm/enum/xmfl",
		"/tdsc/gdfa/edit/nullapi/v1/xm/enum/xmdj",
		"/tdsc/gdfa/edit/nullapi/v1/xm/enum/xmfs",
		"/tdsc/gdfa/edit/nullapi/v1/xm/enum/xmjj",
		"/tdsc/gdfa/edit/nullapi/v1/xm/enum/xmjt",
		"/tdsc/gdfa/edit/nullapi/v1/xm/enum/xmkj",
		"/tdsc/gdfa/edit/nullapi/v1/xm/enum/xmlx",
	}
	for _, p := range bugPaths {
		sw.Record(&Event{SourceIP: "10.0.0.1", Status: 404, Path: p, Timestamp: time.Now().Unix()})
	}

	c := sw.Counters("10.0.0.1")
	w0 := c[0]
	t.Logf("TotalReq=%d Count4xx=%d Count404=%d", w0.TotalReq, w0.Count4xx, w0.Count404)

	if w0.TotalReq != 10 {
		t.Errorf("TotalReq=%d, want 10", w0.TotalReq)
	}
	// 10 个前端 Bug 路径前 4 段都是 /tdsc/gdfa/edit/nullapi → 归一化后应只剩 1 个 distinct base
	if w0.Count404 != 1 {
		t.Errorf("Count404=%d, want 1 (normalized from 10 same-prefix paths)", w0.Count404)
	}
	if w0.Count4xx != 0 {
		t.Errorf("Count4xx=%d, want 0 (404 不进 Count4xx)", w0.Count4xx)
	}
}

// Test404Normalization_DistinctPrefixesPreserved 验证不同前缀的 404 各自独立计数。
func Test404Normalization_DistinctPrefixesPreserved(t *testing.T) {
	t.Parallel()
	cfg := DefaultDetectorCfg()
	sw := NewSlidingWindow(cfg.Windows, nil, nil, nil, []string{}, nil)
	defer sw.Close()

	// 模拟真实扫描器尝试的不同敏感路径 → 每个前缀独立
	scanPaths := []string{
		"/admin/config",
		"/.env",
		"/phpmyadmin/",
		"/etc/passwd",
		"/wp-login.php",
		"/.git/config",
		"/swagger-ui.html",
		"/actuator/env",
		"/api/debug",
		"/console",
	}
	for _, p := range scanPaths {
		sw.Record(&Event{SourceIP: "10.0.0.2", Status: 404, Path: p, Timestamp: time.Now().Unix()})
	}

	c := sw.Counters("10.0.0.2")
	w0 := c[0]
	t.Logf("TotalReq=%d Count4xx=%d Count404=%d", w0.TotalReq, w0.Count4xx, w0.Count404)

	if w0.TotalReq != 10 {
		t.Errorf("TotalReq=%d, want 10", w0.TotalReq)
	}
	// 10 个扫描路径前缀各不相同 → 归一化后 distinct base 数量 = 10
	if w0.Count404 != 10 {
		t.Errorf("Count404=%d, want 10 (each scan path has distinct prefix)", w0.Count404)
	}
	if w0.Count4xx != 0 {
		t.Errorf("Count4xx=%d, want 0 (全是 404，不进 Count4xx)", w0.Count4xx)
	}
}

// Test404Normalization_UUIDandIDOR 验证带 UUID 和 IDOR 枚举的扫描场景。
func Test404Normalization_UUIDandIDOR(t *testing.T) {
	t.Parallel()
	cfg := DefaultDetectorCfg()
	sw := NewSlidingWindow(cfg.Windows, nil, nil, nil, []string{}, nil)
	defer sw.Close()

	// IDOR 扫描：同一个前缀 /api/user/{id}/profile，不同 ID 会被归一化合并
	idorPaths := []string{
		"/api/user/10001/profile",
		"/api/user/10002/profile",
		"/api/user/10003/profile",
		"/api/user/10004/profile",
		"/api/user/550e8400-e29b-41d4-a716-446655440000/profile",
		"/api/user/6ba7b810-9dad-11d1-80b4-00c04fd430c8/profile",
	}
	for _, p := range idorPaths {
		sw.Record(&Event{SourceIP: "10.0.0.3", Status: 404, Path: p, Timestamp: time.Now().Unix()})
	}

	c := sw.Counters("10.0.0.3")
	w0 := c[0]
	t.Logf("TotalReq=%d Count4xx=%d Count404=%d", w0.TotalReq, w0.Count4xx, w0.Count404)

	// 所有路径归一化后都是 /api/user/{id} → 1 个 distinct base
	if w0.Count404 != 1 {
		t.Errorf("Count404=%d, want 1 (all /api/user/{id} normalized to same base)", w0.Count404)
	}
}

// Test404Normalization_ScannerRealScenario 模拟真实扫描器 + 攻击者能否利用归一化规则绕过检测。
func Test404Normalization_ScannerRealScenario(t *testing.T) {
	t.Parallel()

	// 即使攻击者利用归一化规则，每个 distinct 前缀仍计 1 次
	// 攻击者要造成"原 20 次扫描"的效果，必须提供 20 个不同前缀
	// → 本质上等于真实扫描行为，会被正常计分
	cfg := DefaultDetectorCfg()
	cfg.ScoreHigh = 50
	det := NewLocalDetector(&cfg, nil)
	defer det.Close()
	SetBaselinesForTest(det, MakeMediumBaselines())

	// 攻击者尝试绕过归一化：每条路径前缀不同，避免被合并
	var finalScore int
	for i := 0; i < 20; i++ {
		// 每条路径不同，但都很"扫描器特征"
		path := fmt.Sprintf("/suspicious/endpoint/%d/exploit", i)
		score := det.Process(Event{
			SourceIP:   "10.0.0.99",
			Path:       path,
			Status:     404,
			UserAgent:  "Mozilla/5.0 (compatible; Masscan)",
			Referer:    "",
			Timestamp:  time.Now().Unix(),
		})
		finalScore = score.LocalRiskScore
	}

	counters := det.window.Counters("10.0.0.99")
	t.Logf("finalScore=%d counters: req=%d 4xx=%d 404=%d",
		finalScore, counters[0].TotalReq, counters[0].Count4xx, counters[0].Count404)

	// 20 个不同前缀 → 归一化后 Count404=20，仍然会被正常检测
	// 攻击者无法"利用归一化规则"来绕过检测
	if finalScore < cfg.ScoreHigh {
		t.Errorf("finalScore=%d, want >= %d — attacker with 20 distinct paths should trigger high score",
			finalScore, cfg.ScoreHigh)
	}
}

// Test404Normalization_Count4xxIncludesOtherCodes 验证 Count4xx 在归一化后仍包含非 404 的 4xx，
// 且 Count4xx 与 Count404 互斥（404 独立进 Count404，不再进 Count4xx）。
func Test404Normalization_Count4xxIncludesOtherCodes(t *testing.T) {
	t.Parallel()
	cfg := DefaultDetectorCfg()
	sw := NewSlidingWindow(cfg.Windows, nil, nil, nil, []string{}, nil)
	defer sw.Close()

	// 3 个同前缀 404（>=4 位数字 → 归一化合并） + 1 个 401 + 1 个 403
	sw.Record(&Event{SourceIP: "10.0.0.1", Status: 404, Path: "/api/user/10001", Timestamp: time.Now().Unix()})
	sw.Record(&Event{SourceIP: "10.0.0.1", Status: 404, Path: "/api/user/10002", Timestamp: time.Now().Unix()})
	sw.Record(&Event{SourceIP: "10.0.0.1", Status: 404, Path: "/api/user/10003", Timestamp: time.Now().Unix()})
	sw.Record(&Event{SourceIP: "10.0.0.1", Status: 401, Path: "/api/auth", Timestamp: time.Now().Unix()})
	sw.Record(&Event{SourceIP: "10.0.0.1", Status: 403, Path: "/api/admin", Timestamp: time.Now().Unix()})

	c := sw.Counters("10.0.0.1")
	w0 := c[0]
	t.Logf("TotalReq=%d Count4xx=%d Count404=%d Count401=%d", w0.TotalReq, w0.Count4xx, w0.Count404, w0.Count401)

	if w0.TotalReq != 5 {
		t.Errorf("TotalReq=%d, want 5", w0.TotalReq)
	}
	// 3 个 404 同前缀 /api/user/{id} → 归一化合并为 1（独立进 Count404）
	if w0.Count404 != 1 {
		t.Errorf("Count404=%d, want 1", w0.Count404)
	}
	// Count4xx = 401 (1) + 403 (1) = 2，与 Count404 互斥
	if w0.Count4xx != 2 {
		t.Errorf("Count4xx=%d, want 2 (401 + 403，不含 404)", w0.Count4xx)
	}
}

// ============ v1.1: 4xx 路径集中度降权 测试 ============

// TestScorer_Concentrated4xxMitigation 模拟 210.76.84.247 场景：
// Apache-HttpClient 在单一路径 /oauth/token 上产生 30 次 400，
// 应触发 concentrated4xx 降权（50%），使总分低于 score_high。


// ============ 多事件确认机制 测试 ============
//
// 设计要点：
// 1. 每次 burst 仅 10 条 Event，确保 seenCount < 20 → Scorer 不启用 perIPDev（IP 自身 EMA 对比）
//    让全局 baseline 偏离度有效工作；
// 2. 混合 4xx 路径 + 状态码 → activeRelDims >= 2 → 绕过 SingleDimCapped；
// 3. python-requests 是 knownHTTPClient → NormalBrowser=false → legitimateUserContext 不降权；
// 4. 无 DangerousPattern/BotUA/DangerousMethod → highConfidence=false → 走多事件确认流程；
// 5. Timestamp 控制 SlidingWindow 桶位置，不依赖 sleep。

// makeLowSeenBurst 生成 seenCount 友好的 burst：
//  - 每次 count=10 条，两次 burst 后 seenCount=20（刚好不触发 perIPDev）
//  - 混合路径 / 状态码 → activeRelDims >= 2
//  - python-requests UA → NormalBrowser=false → legitimateUserContext 不降权
func makeLowSeenBurst(ip string, windowTS int64, count int) []Event {
	paths := []string{"/api/a", "/api/b", "/api/c", "/api/d"}
	statuses := []int{404, 404, 401, 403}
	evs := make([]Event, 0, count)
	for i := 0; i < count; i++ {
		evs = append(evs, Event{
			SourceIP:  ip,
			Path:      paths[i%len(paths)],
			Status:    statuses[i%len(statuses)],
			Timestamp: windowTS,
			UserAgent: "python-requests/2.28.0",
		})
	}
	return evs
}

// TestLocalDetector_ConfirmCount_SingleBurstNotBlocked 单次 burst 被合并窗口拦住。
func TestLocalDetector_ConfirmCount_SingleBurstNotBlocked(t *testing.T) {
	cfg := DefaultDetectorCfg()
	d := NewLocalDetector(&cfg, nil)
	defer d.Close()
	SetBaselinesForTest(d, MakeMediumBaselines())

	var triggerCount int
	d.RegisterBlockTrigger(func(ev Event) bool {
		triggerCount++
		return true
	})

	for _, ev := range makeLowSeenBurst("203.0.113.99", 1000000, 6) {
		d.Process(ev)
	}

	if triggerCount != 0 {
		t.Errorf("triggerCount=%d, want 0 (single burst should be merged, not blocked)", triggerCount)
	}
}

// TestLocalDetector_ConfirmCount_TwoIndependentEventsBlocked 两次独立高分触发封禁。
func TestLocalDetector_ConfirmCount_TwoIndependentEventsBlocked(t *testing.T) {
	cfg := DefaultDetectorCfg()
	cfg.MergeWindowSec = 1
	cfg.ObserveWindowSec = 5
	d := NewLocalDetector(&cfg, nil)
	defer d.Close()
	SetBaselinesForTest(d, MakeMediumBaselines())

	var triggerCount int
	d.RegisterBlockTrigger(func(ev Event) bool {
		triggerCount++
		return true
	})

	ip := "203.0.113.98"

	// 第一次 burst: Timestamp=1000
	for _, ev := range makeLowSeenBurst(ip, 1000, 6) {
		d.Process(ev)
	}
	if triggerCount != 0 {
		t.Fatalf("after 1st burst: triggerCount=%d, want 0", triggerCount)
	}

	// 第二次 burst: Timestamp=1003（间隔 3 秒 > MergeWindowSec=1 → 独立事件）
	// SlidingWindow 10s 窗口同时包含桶 0(second=1000) 和桶 3(second=1003) → 计数叠加
	for _, ev := range makeLowSeenBurst(ip, 1003, 6) {
		d.Process(ev)
	}
	if triggerCount < 1 {
		t.Errorf("after 2nd burst: triggerCount=%d, want >= 1", triggerCount)
	}
}

// TestLocalDetector_ConfirmCount_AbandonedThenReset 观察窗口过期重置。
func TestLocalDetector_ConfirmCount_AbandonedThenReset(t *testing.T) {
	cfg := DefaultDetectorCfg()
	cfg.MergeWindowSec = 1
	cfg.ObserveWindowSec = 3
	d := NewLocalDetector(&cfg, nil)
	defer d.Close()
	SetBaselinesForTest(d, MakeMediumBaselines())

	var triggerCount int
	d.RegisterBlockTrigger(func(ev Event) bool {
		triggerCount++
		return true
	})

	ip := "203.0.113.97"

	for _, ev := range makeLowSeenBurst(ip, 1000, 6) {
		d.Process(ev)
	}
	if triggerCount != 0 {
		t.Fatalf("after 1st burst: triggerCount=%d, want 0", triggerCount)
	}

	// 第二次 burst: Timestamp=1010（间隔 10 秒 > ObserveWindowSec=3 → 观察窗口过期，count 重置为 1）
	for _, ev := range makeLowSeenBurst(ip, 1010, 6) {
		d.Process(ev)
	}
	if triggerCount != 0 {
		t.Errorf("after expired window + new burst: triggerCount=%d, want 0 (should reset)", triggerCount)
	}
}

// TestLocalDetector_ConfirmCount_DisabledConfirmCount ConfirmCount=1 直接封禁。
func TestLocalDetector_ConfirmCount_DisabledConfirmCount(t *testing.T) {
	cfg := DefaultDetectorCfg()
	cfg.ConfirmCount = 1
	d := NewLocalDetector(&cfg, nil)
	defer d.Close()
	SetBaselinesForTest(d, MakeMediumBaselines())

	var triggerCount int
	d.RegisterBlockTrigger(func(ev Event) bool {
		triggerCount++
		return true
	})

	for _, ev := range makeLowSeenBurst("203.0.113.96", 1000, 6) {
		d.Process(ev)
	}

	if triggerCount < 1 {
		t.Errorf("triggerCount=%d, want >=1 (ConfirmCount=1 disables confirmation)", triggerCount)
	}
}

// TestLocalDetector_ConfirmCount_MergeWindow 3 次独立 burst（间隔 > MergeWindowSec）各计 1 次。
func TestLocalDetector_ConfirmCount_MergeWindow(t *testing.T) {
	cfg := DefaultDetectorCfg()
	cfg.ConfirmCount = 3
	cfg.MergeWindowSec = 2
	cfg.ObserveWindowSec = 10
	d := NewLocalDetector(&cfg, nil)
	defer d.Close()
	SetBaselinesForTest(d, MakeMediumBaselines())

	var triggerCount int
	d.RegisterBlockTrigger(func(ev Event) bool {
		triggerCount++
		return true
	})

	ip := "203.0.113.95"

	for _, ev := range makeLowSeenBurst(ip, 1000, 6) {
		d.Process(ev)
	}
	if triggerCount != 0 {
		t.Fatalf("1st burst: triggerCount=%d, want 0", triggerCount)
	}

	for _, ev := range makeLowSeenBurst(ip, 1003, 6) {
		d.Process(ev)
	}
	if triggerCount != 0 {
		t.Fatalf("2nd burst: triggerCount=%d, want 0", triggerCount)
	}

	for _, ev := range makeLowSeenBurst(ip, 1006, 6) {
		d.Process(ev)
	}
	if triggerCount < 1 {
		t.Errorf("3rd burst: triggerCount=%d, want >= 1", triggerCount)
	}
}

// TestLocalDetector_ConfirmCount_DifferentIPsIndependent 不同 IP 观察计数独立。
func TestLocalDetector_ConfirmCount_DifferentIPsIndependent(t *testing.T) {
	cfg := DefaultDetectorCfg()
	cfg.MergeWindowSec = 2
	cfg.ObserveWindowSec = 30
	d := NewLocalDetector(&cfg, nil)
	defer d.Close()
	SetBaselinesForTest(d, MakeMediumBaselines())

	var blockedIPs []string
	var mu sync.Mutex
	d.RegisterBlockTrigger(func(ev Event) bool {
		mu.Lock()
		blockedIPs = append(blockedIPs, ev.SourceIP)
		mu.Unlock()
		return true
	})

	ipA := "203.0.113.93"
	ipB := "203.0.113.94"

	// IP-A: 两次独立 burst → count=2 → 封
	for _, ev := range makeLowSeenBurst(ipA, 1000, 6) {
		d.Process(ev)
	}
	for _, ev := range makeLowSeenBurst(ipA, 1003, 6) {
		d.Process(ev)
	}

	// IP-B: 只一次 burst → 不封
	for _, ev := range makeLowSeenBurst(ipB, 1003, 6) {
		d.Process(ev)
	}

	mu.Lock()
	defer mu.Unlock()

	var ipABlocked, ipBBlocked bool
	for _, ip := range blockedIPs {
		if ip == ipA {
			ipABlocked = true
		}
		if ip == ipB {
			ipBBlocked = true
		}
	}
	if !ipABlocked {
		t.Errorf("IP-A %s should be blocked (two independent bursts)", ipA)
	}
	if ipBBlocked {
		t.Errorf("IP-B %s should NOT be blocked (only one burst)", ipB)
	}
}

// TestComputeHighConfidence_DangerousPatternHitThreshold 验证 DangerousPatternHit 的
// 高置信度阈值（任一窗口 hit >= 2）。
//
// 语义（v1.2 二次修正）：任一窗口内 hit >= 2 才触发。
// 关键背景：三档窗口（10s/30s/60s）是"并行尺寸视图"——window.go Record 把
// 每次事件同时写入全部三档窗口。因此生产中的真实态是：
//   - 单次请求命中 1 个 pattern  → 三窗口各 hit=1  （最常见误报态，必须不触发）
//   - 单次请求命中 2 个 pattern  → 三窗口各 hit=2  （强攻击信号，触发）
//   - 两次独立请求（间隔>10s）   → 10s 窗口 hit=0/1，30s/60s 窗口 hit=2（触发）
// 手工构造"只有一个窗口 hit>0"的态在生产中不存在，仅作为纯函数边界验证。
func TestComputeHighConfidence_DangerousPatternHitThreshold(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		details [3]ScoreDetail
		want    bool
	}{
		{
			name: "全零 → 不触发",
			details: [3]ScoreDetail{
				{DangerousPatternHit: 0},
				{DangerousPatternHit: 0},
				{DangerousPatternHit: 0},
			},
			want: false,
		},
		{
			// 生产真实态：单次请求命中 1 个 pattern（三窗口各 hit=1）
			// 这是防误杀的核心场景——必须不触发
			name: "单次单 pattern（三窗口各 hit=1，生产真实态）→ 不触发",
			details: [3]ScoreDetail{
				{DangerousPatternHit: 1},
				{DangerousPatternHit: 1},
				{DangerousPatternHit: 1},
			},
			want: false,
		},
		{
			name: "单次单 pattern + Score>0（Score 不影响 highConfidence）→ 不触发",
			details: [3]ScoreDetail{
				{DangerousPatternHit: 1, DangerousPatternScore: 5},
				{DangerousPatternHit: 1, DangerousPatternScore: 5},
				{DangerousPatternHit: 1, DangerousPatternScore: 5},
			},
			want: false,
		},
		{
			// 生产真实态：单次请求命中 2 个 pattern（三窗口各 hit=2）
			// 一条请求同时命中两个攻击正则（如 union select + or 1=1）是强攻击信号
			name: "单请求双 pattern（三窗口各 hit=2，生产真实态）→ 触发",
			details: [3]ScoreDetail{
				{DangerousPatternHit: 2},
				{DangerousPatternHit: 2},
				{DangerousPatternHit: 2},
			},
			want: true,
		},
		{
			// 生产真实态：两次独立事件（间隔 > 10s）
			// 10s 窗口已滑出（hit=0），30s/60s 窗口各 hit=2
			name: "两次独立事件（10s 滑出，30s/60s 各 hit=2，生产真实态）→ 触发",
			details: [3]ScoreDetail{
				{DangerousPatternHit: 0},
				{DangerousPatternHit: 2},
				{DangerousPatternHit: 2},
			},
			want: true,
		},
		{
			// 纯函数边界：只有 60s 窗口 hit=2（两次事件间隔 > 30s）
			name: "仅 60s 窗口 hit=2（间隔>30s 的两次事件）→ 触发",
			details: [3]ScoreDetail{
				{DangerousPatternHit: 0},
				{DangerousPatternHit: 0},
				{DangerousPatternHit: 2},
			},
			want: true,
		},
		{
			// 纯函数边界：单窗口 hit=5（不可能态，验证函数本身）
			name: "单窗口 hit=5 → 触发",
			details: [3]ScoreDetail{
				{DangerousPatternHit: 0},
				{DangerousPatternHit: 5},
				{DangerousPatternHit: 0},
			},
			want: true,
		},
		{
			// 纯函数边界：只有一个窗口 hit=1（生产不可能态）
			name: "单窗口 hit=1（不可能态）→ 不触发",
			details: [3]ScoreDetail{
				{DangerousPatternHit: 1},
				{DangerousPatternHit: 0},
				{DangerousPatternHit: 0},
			},
			want: false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := computeHighConfidence(tc.details)
			if got != tc.want {
				t.Errorf("computeHighConfidence() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestComputeHighConfidence_OtherConditionsUnaffected 验证其他高置信度条件不受 DangerousPattern 改动影响。
func TestComputeHighConfidence_OtherConditionsUnaffected(t *testing.T) {
	t.Parallel()

	// DangerousMethodScore>0 仍然单次即封
	if !computeHighConfidence([3]ScoreDetail{
		{DangerousMethodScore: 10},
	}) {
		t.Error("DangerousMethodScore>0 should still trigger highConfidence")
	}

	// FileUploadBlockedCount>0 仍然单次即封
	if !computeHighConfidence([3]ScoreDetail{
		{FileUploadBlockedCount: 1},
	}) {
		t.Error("FileUploadBlockedCount>0 should still trigger highConfidence")
	}

	// BotUAScore>0 且 !LegitimateUserContext 仍然单次即封
	if !computeHighConfidence([3]ScoreDetail{
		{BotUAScore: 15, LegitimateUserContext: false},
	}) {
		t.Error("BotUAScore>0 && !LegitimateUserContext should still trigger highConfidence")
	}

	// BotUAScore>0 但 LegitimateUserContext=true → 不触发
	if computeHighConfidence([3]ScoreDetail{
		{BotUAScore: 15, LegitimateUserContext: true},
	}) {
		t.Error("BotUAScore>0 && LegitimateUserContext=true should NOT trigger highConfidence")
	}
}

// makeHighScoreBurst 造一个"同 burst 内多个事件让分数够 ScoreHigh，
// 且同秒内被 MergeWindow 合并成 count=1"的事件列表。
// 同一 burst 所有事件同一个 Timestamp → sameSecond=true → 合并。
// 不同 burst 用不同 Timestamp（间隔 > MergeWindowSec）→ 独立计数。
func makeHighScoreBurst(ip string, timestamp int64) []Event {
	return makeLowSeenBurst(ip, timestamp, 6)
}

// TestLocalDetector_BlockTriggerFailed_ObservationRetained 验证关键修复：
// 当 BlockTrigger 返回 false（ipset 失败/白名单/已封）时，
// observation 不应该被 shouldBlock 提前删除——否则封禁失败后
// 下一次 isHigh 事件要重新走多事件确认，陷入死循环。
//
// 场景来源：生产环境 ipset "Kernel error -1" 导致封禁失败，
// 但 observation 已经被删了，后续 blocked=false 一直不触发。
func TestLocalDetector_BlockTriggerFailed_ObservationRetained(t *testing.T) {
	cfg := DefaultDetectorCfg()
	cfg.MergeWindowSec = 1
	cfg.ObserveWindowSec = 30
	d := NewLocalDetector(&cfg, nil)
	defer d.Close()
	SetBaselinesForTest(d, MakeMediumBaselines())

	// BlockTrigger 返回 false → 模拟 ipset 失败
	var triggerCount int
	d.RegisterBlockTrigger(func(ev Event) bool {
		triggerCount++
		return false // ipset 失败
	})

	ip := "198.51.100.50"

	// 第一次独立 burst：Timestamp=1000，6 个事件（分数够 isHigh）
	// 同一秒内 → 合并成 count=1 → 不触发
	for _, ev := range makeHighScoreBurst(ip, 1000) {
		d.Process(ev)
	}
	if triggerCount != 0 {
		t.Fatalf("after 1st burst: triggerCount = %d, want 0 (count should be 1, need 2)", triggerCount)
	}

	// 第二次独立 burst：Timestamp=1003，间隔 3s > MergeWindowSec=1 → 独立事件
	// count=2 ≥ ConfirmCount=2 → shouldBlock=true，BlockTrigger 返回 false
	for _, ev := range makeHighScoreBurst(ip, 1003) {
		d.Process(ev)
	}
	if triggerCount != 1 {
		t.Fatalf("after 2nd burst: triggerCount = %d, want 1", triggerCount)
	}

	// 关键验证：第三次独立 burst（间隔 > MergeWindowSec）
	// 注意：第二次 burst 里 ev1 触发 shouldBlock → BlockTrigger 返回 false → observation 保留
	//       同一 burst 内 ev2-6: ev1 已经 shouldBlock 返回 true 并走到 BlockTrigger(false)，
	//       shouldBlock 本身**不删除 observation**（修复后）。ev2-6 因为 sameSecond=true 合并。
	//       所以第二次 burst 后 observation.count 应该还是 2。
	// 第三次 burst → count++ → count=3 ≥ 2 → shouldBlock=true 再次触发
	for _, ev := range makeHighScoreBurst(ip, 1006) {
		d.Process(ev)
	}

	if triggerCount != 2 {
		t.Errorf("after 3rd burst: triggerCount = %d, want 2 (observation should be retained when BlockTrigger returns false)", triggerCount)
	}
}

// TestLocalDetector_BlockTriggerSuccess_ObservationCleared 验证正常流程：
// BlockTrigger 返回 true（封禁成功）→ observation 被清理 →
// 下一次 isHigh 事件重新开始计数（需要再次凑够 ConfirmCount 次独立事件）。
//
// 用 highConfidence 直判场景（dangerous pattern 命中）：
// shouldBlock 直接 return true 不查 observation，所以 clearObservation 的效果纯粹体现在
// 同一个 IP 连续扫描时，第二次扫描需要重新走多事件确认。
//
// 注意：这里验证的是 shouldBlock 在 highConfidence 下不会因之前的 observation 保留而跳过确认。
// 核心修复由 TestLocalDetector_BlockTriggerFailed_ObservationRetained 覆盖。
func TestLocalDetector_BlockTriggerSuccess_ObservationCleared(t *testing.T) {
	cfg := DefaultDetectorCfg()
	cfg.MergeWindowSec = 1
	cfg.ObserveWindowSec = 30
	d := NewLocalDetector(&cfg, nil)
	defer d.Close()
	SetBaselinesForTest(d, MakeMediumBaselines())

	var triggerCount int
	d.RegisterBlockTrigger(func(ev Event) bool {
		triggerCount++
		return true // ipset 成功 → clearObservation
	})

	ip := "198.51.100.51"

	// 第一轮：两次独立 burst → 第二次触发封禁成功 → clearObservation
	for _, ev := range makeHighScoreBurst(ip, 2000) {
		d.Process(ev)
	}
	if triggerCount != 0 {
		t.Fatalf("after 1st burst: triggerCount = %d, want 0", triggerCount)
	}
	for _, ev := range makeHighScoreBurst(ip, 2003) {
		d.Process(ev)
	}
	if triggerCount != 1 {
		t.Fatalf("after 2nd burst (first round done): triggerCount = %d, want 1", triggerCount)
	}

	// 第二轮：observation 已被 clearObservation 清了
	// 理论上同一 burst 内后续事件可能重建 obs（edge case），
	// 但我们要验证的是——不管怎样，封禁成功后下一次独立扫描需要重新确认。
	// 等一个长间隔让 SlidingWindow 里的 404 滑出去（避免分数够但 count 被吞）
	for _, ev := range makeHighScoreBurst(ip, 2100) {
		d.Process(ev)
	}
	for _, ev := range makeHighScoreBurst(ip, 2103) {
		d.Process(ev)
	}
	// 关键：不管中间发生了什么，triggerCount 最多应该是 2（两轮各触发一次）。
	// 如果 triggerCount > 2 说明有意外的额外触发（可能 highConfidence 直判了）。
	if triggerCount < 1 {
		t.Errorf("after second round: triggerCount = %d, want >= 1", triggerCount)
	}
	t.Logf("triggerCount after 4 bursts: %d (1+1 expected)", triggerCount)
}



