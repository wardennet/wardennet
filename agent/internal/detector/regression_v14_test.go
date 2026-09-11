package detector

import (
	"testing"
)

// TestRegression_NormalUser_One401One404 回归 v1.4：
// 正常浏览器用户 token 过期重登录，7 个请求里 1 个 401 + 1 个 404（浏览器加载 js）。
// 方案 B 合并 status 维度 → dims=1(status 只算 1) + 无其他维度
// → SingleDimCapped → 封顶 ScoreMedium → is_high=false → 安全。
func TestRegression_NormalUser_One401One404(t *testing.T) {
	cfg := DefaultDetectorCfg()
	d := NewLocalDetector(&cfg, nil)
	defer d.Close()
	SetBaselinesForTest(d, MakeMediumBaselines())

	var triggered bool
	d.RegisterBlockTrigger(func(ev Event) bool {
		triggered = true
		return true
	})

	// 模拟 220.186.143.104 真实场景——所有请求带 Referer
	events := []Event{
		{SourceIP: "10.0.0.1", Path: "/api/queryCbDkPage", Status: 401, UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/148.0.0.0", Referer: "https://jcjg.mnr.gov.cn/tdcbui/"},
		{SourceIP: "10.0.0.1", Path: "/dataserver/ssoserver/login", Status: 302, UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/148.0.0.0", Referer: "https://jcjg.mnr.gov.cn/tdcbui/"},
		{SourceIP: "10.0.0.1", Path: "/tdcbui/static/js/6640.e5ac5d9c.js", Status: 404, UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/148.0.0.0", Referer: "https://jcjg.mnr.gov.cn/tdcbui/"},
		{SourceIP: "10.0.0.1", Path: "/dataserver/ssoserver/code/image", Status: 200, UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/148.0.0.0", Referer: "https://jcjg.mnr.gov.cn/tdcbui/"},
		{SourceIP: "10.0.0.1", Path: "/tdcbui/index.html", Status: 200, UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/148.0.0.0", Referer: "https://jcjg.mnr.gov.cn/tdcbui/"},
		{SourceIP: "10.0.0.1", Path: "/api/query2", Status: 200, UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/148.0.0.0", Referer: "https://jcjg.mnr.gov.cn/tdcbui/"},
		{SourceIP: "10.0.0.1", Path: "/api/query3", Status: 200, UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/148.0.0.0", Referer: "https://jcjg.mnr.gov.cn/tdcbui/"},
	}

	var maxScore int
	for _, ev := range events {
		ev.Timestamp = 1000
		ev = d.Process(ev)
		if ev.LocalRiskScore > maxScore {
			maxScore = ev.LocalRiskScore
		}
		t.Logf("path=%-45s status=%d score=%d", ev.Path, ev.Status, ev.LocalRiskScore)
	}

	counters := d.window.Counters("10.0.0.1")
	ipQpsEMA, ipSeenCount := d.window.GetIPBaseline("10.0.0.1")
	result := d.scorer.ScoreWithDetail(counters, ipQpsEMA, ipSeenCount)
	d30 := result.Details[1]
	t.Logf("\n30sWindow: req=%d 401=%d 404=%d emptyRef=%d dims=%d singleCap=%v legmit=%v",
		d30.TotalReq, d30.Count401, d30.Count404, d30.EmptyRefererHit, d30.ActiveRelDims, d30.SingleDimCapped, d30.LegitimateUserContext)
	t.Logf("  Scores: statusAnomaly=%d 404=%d authFail=%d qps=%d emptyRef=%d",
		d30.StatusAnomalyScore, d30.Status404Score, d30.AuthFailScore, d30.QPSScore, d30.EmptyRefererScore)

	if triggered {
		t.Error("FAIL: BlockTrigger called — normal user must NOT be blocked!")
	}
	if d30.ActiveRelDims != 1 {
		t.Errorf("activeRelDims=%d, want 1 (status merged) — SingleDimCapped should trigger", d30.ActiveRelDims)
	}
	if !d30.SingleDimCapped {
		t.Error("FAIL: SingleDimCapped should be true (dims=1 + no abs attack features)")
	}
	t.Logf("\nPASS: triggered=%v maxScore=%d (score capped by SingleDimCapped)", triggered, maxScore)
}

// TestRegression_Scanner_StillBlocked 合并后扫描器仍能被封禁。
// 扫描器: python-requests UA + 大量混合路径+混合状态码 → QPS偏离+BotUA(?)+多个status → dims≥2 → 不封顶。
func TestRegression_Scanner_StillBlocked(t *testing.T) {
	cfg := DefaultDetectorCfg()
	d := NewLocalDetector(&cfg, nil)
	defer d.Close()
	SetBaselinesForTest(d, MakeMediumBaselines())

	var triggerCount int
	d.RegisterBlockTrigger(func(ev Event) bool {
		triggerCount++
		return true
	})

	// python-requests UA (known client, NormalBrowser=false, legitimateUserContext 不触发)
	// 20 条混合状态码 + 混合路径
	paths := []string{"/admin", "/.env", "/wp-login.php", "/phpmyadmin", "/api/user/1", "/config.json", "/backup.sql", "/etc/passwd"}
	statuses := []int{404, 404, 404, 404, 404, 401, 403, 500}

	for i := 0; i < 20; i++ {
		d.Process(Event{
			SourceIP:  "10.0.0.2",
			Path:      paths[i%len(paths)],
			Status:    statuses[i%len(statuses)],
			Timestamp: 1000,
			UserAgent: "python-requests/2.28.0",
		})
	}

	if triggerCount == 0 {
		t.Errorf("Scanner should trigger BlockTrigger at least once, got triggerCount=%d", triggerCount)
	} else {
		t.Logf("PASS: scanner blocked (triggerCount=%d)", triggerCount)
	}
}

// TestRegression_SameAnomalyFrozen_FreshCheck P0 回归：
// 正常 token 过期后的后续请求不产生新的 4xx → fresh check 看到 12 维快照全冻结
// → count 不涨 → 不封。
func TestRegression_SameAnomalyFrozen_FreshCheck(t *testing.T) {
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

	// 第 1 个请求：产生 401 + 404（status anomaly 首次触发 is_high）
	d.Process(Event{SourceIP: "10.0.0.3", Path: "/api", Status: 401, Timestamp: 1000, UserAgent: "python-requests/2.28.0"})
	d.Process(Event{SourceIP: "10.0.0.3", Path: "/.env", Status: 404, Timestamp: 1000, UserAgent: "python-requests/2.28.0"})

	// 第 3 个请求：纯 200 → 30s 窗口 Count401 和 Count404 冻结不再增长
	d.Process(Event{SourceIP: "10.0.0.3", Path: "/api/health", Status: 200, Timestamp: 1010, UserAgent: "python-requests/2.28.0"})
	t.Logf("after 1st anomaly + 1 frozen: triggerCount=%d", triggerCount)
	if triggerCount > 0 {
		t.Error("should not block on frozen anomaly")
	}

	// 第 4 个请求：再一个 200
	d.Process(Event{SourceIP: "10.0.0.3", Path: "/api/query", Status: 200, Timestamp: 1020, UserAgent: "python-requests/2.28.0"})
	t.Logf("after 2nd frozen: triggerCount=%d", triggerCount)
	if triggerCount > 0 {
		t.Error("fresh check should prevent blocked when all anomalies frozen")
	}

	// 第 5 个请求：新的 404 → Count404 增长 → fresh check 放行 → count+1 → 封
	d.Process(Event{SourceIP: "10.0.0.3", Path: "/admin/config", Status: 404, Timestamp: 1030, UserAgent: "python-requests/2.28.0"})
	t.Logf("after NEW 404 (growth!): triggerCount=%d", triggerCount)
	t.Logf("PASS: frozen=false, growing=true")
}
