package detector

import (
	"testing"
)

// --- pathRing 基础测试 ---

func TestPathRingAppendAndAll(t *testing.T) {
	r := newPathRing(0)
	for i := 0; i < 30; i++ {
		r.append("/api/users", "GET", 200)
	}
	got := r.all()
	if len(got) != 30 {
		t.Fatalf("expected 30 records, got %d", len(got))
	}
	if got[0].path != "/api/users" {
		t.Errorf("expected path /api/users, got %s", got[0].path)
	}
	if got[0].method != 'G' {
		t.Errorf("expected method 'G', got %c", got[0].method)
	}
	if got[0].status != 200 {
		t.Errorf("expected status 200, got %d", got[0].status)
	}
}

func TestPathRingOverflow(t *testing.T) {
	r := newPathRing(0)
	// 写入 DefaultConsistencyThresholds().RingCapacity + 20 条，应该覆盖最早的 20 条
	for i := 0; i < DefaultConsistencyThresholds().RingCapacity; i++ {
		r.append("/path_a", "GET", 200)
	}
	for i := 0; i < 20; i++ {
		r.append("/path_b", "GET", 200)
	}
	got := r.all()
	if len(got) != DefaultConsistencyThresholds().RingCapacity {
		t.Fatalf("expected %d after overflow, got %d", DefaultConsistencyThresholds().RingCapacity, len(got))
	}
	// ring full 后，最旧的在 head 位置，新数据在 buf[:head]
	// all() 返回的顺序是 buf[head:]（旧数据） + buf[:head]（新数据）
	// 所以最后 20 条是 /path_b，前 capacity-20 条是 /path_a
	for i := 0; i < DefaultConsistencyThresholds().RingCapacity-20; i++ {
		if got[i].path != "/path_a" {
			t.Errorf("record %d: expected /path_a (old), got %s", i, got[i].path)
		}
	}
	for i := DefaultConsistencyThresholds().RingCapacity - 20; i < DefaultConsistencyThresholds().RingCapacity; i++ {
		if got[i].path != "/path_b" {
			t.Errorf("record %d: expected /path_b (new), got %s", i, got[i].path)
		}
	}
}

// --- Consistency Score 关键场景 ---

// addBatch 辅助：批量写相同 path
func addBatch(r *pathRing, path string, method string, status int, n int) {
	for i := 0; i < n; i++ {
		r.append(path, method, status)
	}
}

func TestConsistencyBenignHumanBrowser(t *testing.T) {
	// 模拟真人浏览器用户的行为序列：
	// 登录 → 首页静态资源 → 业务菜单接口 → 报表导出
	// 多个前缀，但都在 /tdsc /pubcomquerylist /pubcomupload 扎堆
	r := newPathRing(0)

	// 登录流程
	addBatch(r, "/tdsc/login", "GET", 200, 2)
	addBatch(r, "/tdsc/js/env.js", "GET", 200, 3)
	addBatch(r, "/tdsc/css/index.css", "GET", 200, 3)
	addBatch(r, "/tdsc/api/captcha/image", "GET", 200, 1)
	addBatch(r, "/tdsc/api/auth/authLogin", "POST", 200, 1)
	addBatch(r, "/tdsc/api/auth/verifySms", "POST", 200, 1)
	// 首页加载
	addBatch(r, "/tdsc/indexZh", "GET", 200, 1)
	addBatch(r, "/tdsc/img/index/bg.png", "GET", 200, 2)
	addBatch(r, "/tdsc/fonts/SourceHanSerifCN-SemiBold.otf", "GET", 200, 1)
	addBatch(r, "/pubcomquerylist/api/user/query", "GET", 200, 5)
	addBatch(r, "/pubcomquerylist/api/user/btns", "GET", 200, 4)
	addBatch(r, "/pubcomquerylist/api/user/field/list", "GET", 200, 3)
	addBatch(r, "/pubcomquerylist/nobody.css", "GET", 404, 5) // 前端缺失资源
	// 业务菜单
	addBatch(r, "/pubcomquerylist/queryindex", "GET", 200, 2)
	addBatch(r, "/tdsc/api/tgdjcRcxc/list", "GET", 200, 4)
	addBatch(r, "/pubcomupload//api/datumConfig/selectOne", "GET", 200, 3)
	addBatch(r, "/maque/api/v1/xm/menu", "GET", 200, 2)
	addBatch(r, "/tdsc/api/common/updateAuthNoticeViews", "POST", 200, 3)

	// 再加 favicon 探测（真人浏览器行为，不多）
	addBatch(r, "/favicon.ico", "GET", 404, 2)

	res := r.Score(DefaultConsistencyThresholds())

	if !res.HasSamples {
		t.Fatal("expected HasSamples=true (total >= 20)")
	}
	if !res.IsBenign {
		t.Errorf("expected BENIGN score >= 4, got score=%d details: %+v", res.Score, res)
	}
	if res.Score < 4 {
		t.Errorf("score should be >= 4 for human browser, got %d", res.Score)
	}
}

func TestConsistencyBenignAPIClient(t *testing.T) {
	// 模拟合法 API 客户端（okhttp）调用同一个前缀的多个接口
	r := newPathRing(0)

	// 主要在 /dataserver 前缀下，GET+POST 混合，全部 200
	for i := 0; i < 200; i++ {
		r.append("/dataserver/api/v1/users", "GET", 200)
	}
	for i := 0; i < 150; i++ {
		r.append("/dataserver/api/v1/orders", "POST", 200)
	}
	for i := 0; i < 50; i++ {
		r.append("/dataserver/api/v1/products", "GET", 200)
	}
	for i := 0; i < 40; i++ {
		r.append("/dataserver/health", "GET", 200)
	}

	res := r.Score(DefaultConsistencyThresholds())

	if !res.HasSamples {
		t.Fatal("expected HasSamples=true")
	}
	if !res.IsBenign {
		t.Errorf("expected BENIGN for legitimate API client, got score=%d details: %+v", res.Score, res)
	}
}

func TestConsistencySuspicCurlScanSinglePath(t *testing.T) {
	// 模拟 curl 反复扫同一个动态路径（不是 favicon/robots，是业务路径），全 404
	// 反信号应该触发 → -5 + 额外 -3（单路径+全错）→ 分数很低
	r := newPathRing(0)
	for i := 0; i < 100; i++ {
		r.append("/WebReport/ReportServer", "GET", 403)
	}

	res := r.Score(DefaultConsistencyThresholds())

	if !res.HasSamples {
		t.Fatal("expected HasSamples=true")
	}
	if res.IsBenign {
		t.Errorf("expected SUSPIC for curl scan, got BENIGN score=%d", res.Score)
	}
	if !res.AlwaysSameError {
		t.Error("expected AlwaysSameError=true")
	}
}

func TestConsistencySuspicCurlScanRootPath(t *testing.T) {
	// curl 反复扫 /，全 404
	r := newPathRing(0)
	for i := 0; i < 150; i++ {
		r.append("/", "GET", 404)
	}

	res := r.Score(DefaultConsistencyThresholds())

	if !res.HasSamples {
		t.Fatal("expected HasSamples=true")
	}
	if res.IsBenign {
		t.Errorf("expected SUSPIC for curl / scan, got BENIGN score=%d", res.Score)
	}
}

func TestConsistencySuspicFloodFavicon(t *testing.T) {
	// 反复打 favicon.ico 100 次（超过公共探测 10 次阈值）
	r := newPathRing(0)
	for i := 0; i < 100; i++ {
		r.append("/favicon.ico", "GET", 404)
	}

	res := r.Score(DefaultConsistencyThresholds())

	if !res.HasSamples {
		t.Fatal("expected HasSamples=true")
	}
	if res.IsBenign {
		t.Errorf("expected SUSPIC for favicon flood (>=10 times), got BENIGN score=%d", res.Score)
	}
	if !res.AlwaysSameError {
		t.Error("expected AlwaysSameError=true for favicon flood")
	}
}

func TestConsistencyBenignFewFavicons(t *testing.T) {
	// 真人浏览器打 5 次 favicon.ico（<10 公共探测阈值），其他请求正常
	// 不应该触发反信号
	r := newPathRing(0)
	addBatch(r, "/favicon.ico", "GET", 404, 5)
	addBatch(r, "/tdsc/indexZh", "GET", 200, 10)
	addBatch(r, "/tdsc/js/env.js", "GET", 200, 10)
	addBatch(r, "/tdsc/api/user/query", "GET", 200, 10)

	res := r.Score(DefaultConsistencyThresholds())

	if !res.HasSamples {
		t.Fatal("expected HasSamples=true")
	}
	// favicon 只有 5 次 < 10 阈值，不会触发反信号
	// 其他维度（前缀连贯、新颖度收敛、路径集中、状态同质、方法语义）都满足
	if !res.IsBenign {
		t.Errorf("expected BENIGN for human with few favicons, got score=%d details: %+v", res.Score, res)
	}
}

func TestConsistencyStaticResource404NotAntisignal(t *testing.T) {
	// 反复扫 nobody.css 20 次全 404 — 但 .css 是静态资源扩展名，不计反信号
	// 其他维度（前缀连贯、新颖度收敛等）仍然应该是 BENIGN
	r := newPathRing(0)
	addBatch(r, "/pubcomquerylist/nobody.css", "GET", 404, 20)
	addBatch(r, "/pubcomquerylist/api/user/query", "GET", 200, 15)
	addBatch(r, "/pubcomquerylist/api/user/btns", "GET", 200, 15)

	res := r.Score(DefaultConsistencyThresholds())

	if !res.HasSamples {
		t.Fatal("expected HasSamples=true")
	}
	if res.AlwaysSameError {
		t.Error("static resource .css 404 should NOT trigger AlwaysSameError")
	}
	if !res.IsBenign {
		t.Errorf("expected BENIGN (static resource 404 excluded), got score=%d", res.Score)
	}
}

func TestConsistencySuspicWildPathExploration(t *testing.T) {
	// 模拟扫描器随机爆破 200 条不同路径，每条打 1 次
	r := newPathRing(0)
	paths := []string{
		"/admin", "/admin/login", "/admin/config", "/phpmyadmin", "/phpMyAdmin",
		"/wp-login.php", "/wp-admin", "/manager/html", "/tomcat/manager/html",
		"/backup", "/config.php", "/etc/passwd", "/cgi-bin/test.cgi",
		"/shell.php", "/cmd.php", "/uploader.php", "/editor.php",
		"/db.php", "/mysql.php", "/pma", "/pma/index.php",
		"/ckeditor", "/ueditor", "/fckeditor",
		"/.git/config", "/.env", "/.htaccess", "/.bash_history",
		"/robots.txt", "/sitemap.xml", "/crossdomain.xml",
		"/api/v1/users", "/api/v1/orders", "/api/v1/products",
		"/login", "/register", "/forgot", "/reset",
		"/download", "/upload", "/export", "/import",
		"/static/js/app.js", "/static/css/app.css", "/static/img/logo.png",
	}
	for i := 0; i < 200; i++ {
		p := paths[i%len(paths)]
		r.append(p, "GET", 404)
	}

	res := r.Score(DefaultConsistencyThresholds())

	if !res.HasSamples {
		t.Fatal("expected HasSamples=true")
	}
	if res.IsBenign {
		t.Errorf("expected SUSPIC for wild path scanner, got BENIGN score=%d details: %+v", res.Score, res)
	}
}

func TestConsistencyInsufficientSamples(t *testing.T) {
	// 只有 10 条请求，不足 20 样本 → HasSamples=false
	r := newPathRing(0)
	for i := 0; i < 10; i++ {
		r.append("/api/test", "GET", 200)
	}

	res := r.Score(DefaultConsistencyThresholds())

	if res.HasSamples {
		t.Error("expected HasSamples=false for total < 20")
	}
}

// --- SlidingWindow 集成测试 ---

func TestSlidingWindowComputeConsistency(t *testing.T) {
	cfg := [3]WindowCfg{
		{Size: 10},
		{Size: 30},
		{Size: 120},
	}
	sw := NewSlidingWindow(cfg, nil, nil, nil, nil, nil)

	// 构造 Event 序列：真人浏览器
	for i := 0; i < 50; i++ {
		sw.Record(&Event{SourceIP: "203.0.113.1", Path: "/tdsc/indexZh", Method: "GET", Status: 200})
	}
	for i := 0; i < 50; i++ {
		sw.Record(&Event{SourceIP: "203.0.113.1", Path: "/tdsc/api/user/query", Method: "GET", Status: 200})
	}
	for i := 0; i < 30; i++ {
		sw.Record(&Event{SourceIP: "203.0.113.1", Path: "/tdsc/api/data/list", Method: "GET", Status: 200})
	}

	res := sw.ComputeConsistency("203.0.113.1")

	if !res.HasSamples {
		t.Fatal("expected HasSamples=true")
	}
	if !res.IsBenign {
		t.Errorf("expected BENIGN via SlidingWindow, got score=%d", res.Score)
	}
}

func TestSlidingWindowComputeConsistencyScanner(t *testing.T) {
	cfg := [3]WindowCfg{
		{Size: 10},
		{Size: 30},
		{Size: 120},
	}
	sw := NewSlidingWindow(cfg, nil, nil, nil, nil, nil)

	// 构造 Event 序列：curl 扫 /WebReport/ReportServer 全 403
	for i := 0; i < 100; i++ {
		sw.Record(&Event{SourceIP: "198.51.100.2", Path: "/WebReport/ReportServer", Method: "GET", Status: 403})
	}

	res := sw.ComputeConsistency("198.51.100.2")

	if !res.HasSamples {
		t.Fatal("expected HasSamples=true")
	}
	if res.IsBenign {
		t.Errorf("expected SUSPIC via SlidingWindow, got BENIGN score=%d", res.Score)
	}
}

func TestIsPrivateOrLocal(t *testing.T) {
	tests := []struct {
		ip    string
		want  bool
		label string
	}{
		{"127.0.0.1", true, "loopback"},
		{"127.0.0.53", true, "loopback range"},
		{"::1", true, "IPv6 loopback"},
		{"10.0.0.1", true, "class A private"},
		{"10.255.255.255", true, "class A private edge"},
		{"172.16.0.1", true, "class B private"},
		{"172.31.255.255", true, "class B private edge"},
		{"192.168.0.1", true, "class C private"},
		{"192.168.255.255", true, "class C private edge"},
		{"169.254.1.1", true, "link local"},
		{"0.0.0.0", true, "unspecified"},
		{"::", true, "IPv6 unspecified"},
		{"203.0.113.1", false, "public (TEST-NET-3)"},
		{"1.1.1.1", false, "public"},
		{"", false, "empty"},
		{"not-an-ip", false, "invalid"},
		{"::ffff:127.0.0.1", true, "IPv4-mapped loopback"},
		{"fc00::1", true, "IPv6 private"},
	}
	for _, tc := range tests {
		got := isPrivateOrLocal(tc.ip)
		if got != tc.want {
			t.Errorf("isPrivateOrLocal(%q) [label=%s]: got %v, want %v", tc.ip, tc.label, got, tc.want)
		}
	}
}
