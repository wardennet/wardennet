// Package logparser - 解析器表驱动测试。
// 覆盖 nginx/apache/tomcat/linux_auth 四种解析器的 CLF/Combined/auth 行格式，
// 以及 Registry 注册/查找/重复注册/并发安全。
package logparser

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// ===== Registry 测试 =====

// TestNewRegistry_BuiltinParsers 验证 NewRegistry 注册全部 4 种内置解析器。
func TestNewRegistry_BuiltinParsers(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	want := map[string]bool{
		SourceNginxAccess:  true,
		SourceApacheAccess: true,
		SourceTomcatAccess: true,
		SourceLinuxAuth:    true,
	}
	for name := range want {
		if p, ok := r.Get(name); !ok || p == nil {
			t.Errorf("Get(%q) missing or nil", name)
		}
	}
	if got := len(r.Names()); got != len(want) {
		t.Errorf("Names() len = %d, want %d", got, len(want))
	}
}

// TestRegistry_RegisterDuplicate 验证重复注册同名解析器返回 error。
func TestRegistry_RegisterDuplicate(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	if err := r.Register(&nginxParser{}); err == nil {
		t.Errorf("Register duplicate nginxParser: want error, got nil")
	}
}

// TestRegistry_GetUnknown 验证未知名返回 ok=false。
func TestRegistry_GetUnknown(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	if _, ok := r.Get("unknown_parser"); ok {
		t.Errorf("Get(unknown) = true, want false")
	}
}

// TestRegistry_ConcurrentAccess 并发读写 Registry，验证 -race 无竞争。
func TestRegistry_ConcurrentAccess(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = r.Get(SourceNginxAccess)
		}()
		go func(i int) {
			defer wg.Done()
			// 自定义名避免与内置冲突
			_ = r.Register(&fakeParser{name: "fake" + itoa(i)})
		}(i)
	}
	wg.Wait()
}

// fakeParser 仅用于 Registry 并发测试，不实现真实解析。
type fakeParser struct{ name string }

func (p *fakeParser) Name() string                     { return p.name }
func (p *fakeParser) Parse(line string) (Event, error) { return Event{}, ErrUnparsable }

// itoa 极简 int->string，避免引入 strconv 仅用于测试命名。
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// mustParseTime 测试用辅助函数，解析时间字符串失败则 panic。
func mustParseTime(t *testing.T, s string) time.Time {
	t.Helper()
	parsed, err := time.Parse("02/Jan/2006:15:04:05 -0700", s)
	if err != nil {
		t.Fatalf("mustParseTime(%q) failed: %v", s, err)
	}
	return parsed
}

// ===== nginx_access 解析器表驱动测试 =====

func TestNginxParser_Table(t *testing.T) {
	t.Parallel()
	wantCLF, _ := time.Parse("02/Jan/2006:15:04:05 -0700", "10/Oct/2023:13:55:36 +0000")
	wantCombined := wantCLF

	cases := []struct {
		name    string
		line    string
		wantErr error
		want    Event
	}{
		{
			name: "CLF basic",
			line: `127.0.0.1 - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 200 612`,
			want: Event{
				Source: SourceNginxAccess, SourceIP: "127.0.0.1",
				Method: "GET", Path: "/", Status: 200, BytesSent: 612,
				Timestamp: wantCLF,
				RawLine:   `127.0.0.1 - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 200 612`,
			},
		},
		{
			name: "Combined with referer and ua",
			line: `127.0.0.1 - - [10/Oct/2023:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 612 "-" "Mozilla/5.0"`,
			want: Event{
				Source: SourceNginxAccess, SourceIP: "127.0.0.1",
				Method: "GET", Path: "/index.html", Status: 200, BytesSent: 612,
				Referer: "", UserAgent: "Mozilla/5.0",
				Timestamp: wantCombined,
				RawLine:   `127.0.0.1 - - [10/Oct/2023:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 612 "-" "Mozilla/5.0"`,
			},
		},
		{
			name: "Bytes dash placeholder",
			line: `127.0.0.1 - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 200 -`,
			want: Event{
				Source: SourceNginxAccess, SourceIP: "127.0.0.1",
				Method: "GET", Path: "/", Status: 200, BytesSent: 0,
				Timestamp: wantCLF,
			},
		},
		{
			name: "No status bytes (request only)",
			line: `127.0.0.1 - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1"`,
			want: Event{
				Source: SourceNginxAccess, SourceIP: "127.0.0.1",
				Method: "GET", Path: "/", Status: 0, BytesSent: 0,
				Timestamp: wantCLF,
			},
		},
		{
			name: "IPv6 client",
			line: `::1 - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 200 612`,
			want: Event{
				Source: SourceNginxAccess, SourceIP: "::1",
				Method: "GET", Path: "/", Status: 200, BytesSent: 612,
				Timestamp: wantCLF,
			},
		},
		{
			name: "POST with 302",
			line: `192.168.1.5 - - [10/Oct/2023:13:55:36 +0000] "POST /login HTTP/1.1" 302 0`,
			want: Event{
				Source: SourceNginxAccess, SourceIP: "192.168.1.5",
				Method: "POST", Path: "/login", Status: 302, BytesSent: 0,
				Timestamp: wantCLF,
			},
		},
		{
			name: "Extended with remote_port and x-forwarded-for",
			line: `203.0.113.100 54321 - - [28/Aug/2026:09:10:00 +0800] "GET /api/users HTTP/1.1" 200 1234 "https://example.com" "Mozilla/5.0" "10.0.0.1, 172.16.0.1"`,
			want: Event{
				Source: SourceNginxAccess, SourceIP: "10.0.0.1", // 优先使用 x-forwarded-for
				EdgeIP: "203.0.113.100", ClientIPFrom: "xff",
				Method: "GET", Path: "/api/users", Status: 200, BytesSent: 1234,
				Referer: "https://example.com", UserAgent: "Mozilla/5.0",
				Timestamp: mustParseTime(t, "28/Aug/2026:09:10:00 +0800"),
			},
		},
		{
			name: "Extended without x-forwarded-for",
			line: `203.0.113.100 12345 - admin [28/Aug/2026:09:10:00 +0800] "POST /api/login HTTP/1.1" 401 45 "-" "curl/7.68.0"`,
			want: Event{
				Source: SourceNginxAccess, SourceIP: "203.0.113.100",
				EdgeIP: "203.0.113.100", ClientIPFrom: "direct",
				Method: "POST", Path: "/api/login", Status: 401, BytesSent: 45,
				Referer: "", UserAgent: "curl/7.68.0",
				Timestamp: mustParseTime(t, "28/Aug/2026:09:10:00 +0800"),
			},
		},
		// v1.1 新增：Cloudflare 场景测试
		{
			name: "Cloudflare Ext with CF-Connecting-IP",
			line: `104.16.132.229 54321 - - [28/Aug/2026:09:10:00 +0800] "GET /admin/api/v1/users HTTP/1.1" 200 1234 "https://example.com" "Mozilla/5.0" "222.132.94.196" "222.132.94.196" ""`,
			want: Event{
				Source: SourceNginxAccess,
				SourceIP: "222.132.94.196", // CF-Connecting-IP 优先于 xff
				EdgeIP:   "104.16.132.229", // Cloudflare 边缘节点 IP
				ClientIPFrom: "cf_connecting_ip",
				Method: "GET", Path: "/admin/api/v1/users", Status: 200, BytesSent: 1234,
				Referer: "https://example.com", UserAgent: "Mozilla/5.0",
				Timestamp: mustParseTime(t, "28/Aug/2026:09:10:00 +0800"),
			},
		},
		{
			name: "Cloudflare Ext CF-Connecting-IP empty, fallback to True-Client-IP",
			line: `104.16.132.229 54321 - - [28/Aug/2026:09:10:00 +0800] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0" "6.6.6.6" "-" "8.8.8.8"`,
			want: Event{
				Source: SourceNginxAccess,
				SourceIP: "8.8.8.8", // cf 为空 → 用 True-Client-IP
				EdgeIP:   "104.16.132.229",
				ClientIPFrom: "true_client_ip",
				Method: "GET", Path: "/", Status: 200, BytesSent: 612,
				Referer: "", UserAgent: "Mozilla/5.0",
				Timestamp: mustParseTime(t, "28/Aug/2026:09:10:00 +0800"),
			},
		},
		{
			name: "Cloudflare Ext CF+TCIP empty, fallback to xff",
			line: `104.16.132.229 54321 - - [28/Aug/2026:09:10:00 +0800] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0" "1.2.3.4" "-" "-"`,
			want: Event{
				Source: SourceNginxAccess,
				SourceIP: "1.2.3.4", // cf 和 tcip 都是空 → 用 xff
				EdgeIP:   "104.16.132.229",
				ClientIPFrom: "xff",
				Method: "GET", Path: "/", Status: 200, BytesSent: 612,
				Referer: "", UserAgent: "Mozilla/5.0",
				Timestamp: mustParseTime(t, "28/Aug/2026:09:10:00 +0800"),
			},
		},
		{
			name: "Cloudflare Ext all headers empty, fallback to direct",
			line: `104.16.132.229 54321 - - [28/Aug/2026:09:10:00 +0800] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0" "-" "-" "-"`,
			want: Event{
				Source: SourceNginxAccess,
				SourceIP: "104.16.132.229", // 全部为空 → 用 remote_addr
				EdgeIP:   "104.16.132.229",
				ClientIPFrom: "direct",
				Method: "GET", Path: "/", Status: 200, BytesSent: 612,
				Referer: "", UserAgent: "Mozilla/5.0",
				Timestamp: mustParseTime(t, "28/Aug/2026:09:10:00 +0800"),
			},
		},
		{
			name:    "Empty line",
			line:    "   ",
			wantErr: ErrUnparsable,
		},
		{
			name:    "Unparsable garbage",
			line:    "garbage without structure",
			wantErr: ErrUnparsable,
		},
	}

	p := &nginxParser{}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ev, err := p.Parse(tc.line)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Parse err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse err = %v, want nil", err)
			}
			// RawLine 在 want 中显式设置时比较，否则跳过（含 TrimSpace 差异）
			if tc.want.RawLine != "" && ev.RawLine != tc.want.RawLine {
				t.Errorf("RawLine = %q, want %q", ev.RawLine, tc.want.RawLine)
			}
			if ev.Source != tc.want.Source {
				t.Errorf("Source = %q, want %q", ev.Source, tc.want.Source)
			}
			if ev.SourceIP != tc.want.SourceIP {
				t.Errorf("SourceIP = %q, want %q", ev.SourceIP, tc.want.SourceIP)
			}
			if ev.Method != tc.want.Method {
				t.Errorf("Method = %q, want %q", ev.Method, tc.want.Method)
			}
			if ev.Path != tc.want.Path {
				t.Errorf("Path = %q, want %q", ev.Path, tc.want.Path)
			}
			if ev.Status != tc.want.Status {
				t.Errorf("Status = %d, want %d", ev.Status, tc.want.Status)
			}
			if ev.BytesSent != tc.want.BytesSent {
				t.Errorf("BytesSent = %d, want %d", ev.BytesSent, tc.want.BytesSent)
			}
			if ev.Referer != tc.want.Referer {
				t.Errorf("Referer = %q, want %q", ev.Referer, tc.want.Referer)
			}
			if ev.UserAgent != tc.want.UserAgent {
				t.Errorf("UserAgent = %q, want %q", ev.UserAgent, tc.want.UserAgent)
			}
			if !ev.Timestamp.Equal(tc.want.Timestamp) {
				t.Errorf("Timestamp = %v, want %v", ev.Timestamp, tc.want.Timestamp)
			}
		})
	}
}

// ===== apache_access 解析器表驱动测试 =====

func TestApacheParser_Table(t *testing.T) {
	t.Parallel()
	wantT, _ := time.Parse("02/Jan/2006:15:04:05 -0700", "10/Oct/2023:13:55:36 +0000")

	cases := []struct {
		name string
		line string
		want Event
	}{
		{
			name: "CLF basic (Source=apache_access)",
			line: `10.0.0.5 - - [10/Oct/2023:13:55:36 +0000] "GET / Apache/2.4" 200 1024`,
			want: Event{
				Source: SourceApacheAccess, SourceIP: "10.0.0.5",
				Method: "GET", Path: "/", Status: 200, BytesSent: 1024,
				Timestamp: wantT,
			},
		},
		{
			name: "Combined IPv6",
			line: `2001:db8::1 - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 404 0 "-" "curl/7.79"`,
			want: Event{
				Source: SourceApacheAccess, SourceIP: "2001:db8::1",
				Method: "GET", Path: "/", Status: 404, BytesSent: 0,
				UserAgent: "curl/7.79", Timestamp: wantT,
			},
		},
	}

	p := &apacheParser{}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ev, err := p.Parse(tc.line)
			if err != nil {
				t.Fatalf("Parse err = %v, want nil", err)
			}
			if ev.Source != tc.want.Source {
				t.Errorf("Source = %q, want %q (apacheParser must set own Source)", ev.Source, tc.want.Source)
			}
			if ev.SourceIP != tc.want.SourceIP {
				t.Errorf("SourceIP = %q, want %q", ev.SourceIP, tc.want.SourceIP)
			}
			if ev.Method != tc.want.Method {
				t.Errorf("Method = %q, want %q", ev.Method, tc.want.Method)
			}
			if ev.Status != tc.want.Status {
				t.Errorf("Status = %d, want %d", ev.Status, tc.want.Status)
			}
			if ev.BytesSent != tc.want.BytesSent {
				t.Errorf("BytesSent = %d, want %d", ev.BytesSent, tc.want.BytesSent)
			}
			if ev.UserAgent != tc.want.UserAgent {
				t.Errorf("UserAgent = %q, want %q", ev.UserAgent, tc.want.UserAgent)
			}
			if !ev.Timestamp.Equal(tc.want.Timestamp) {
				t.Errorf("Timestamp = %v, want %v", ev.Timestamp, tc.want.Timestamp)
			}
		})
	}
}

// ===== tomcat_access 解析器表驱动测试 =====

func TestTomcatParser_Table(t *testing.T) {
	t.Parallel()
	wantT, _ := time.Parse("02/Jan/2006:15:04:05 -0700", "10/Oct/2023:13:55:36 +0800")

	cases := []struct {
		name    string
		line    string
		wantErr error
		want    Event
	}{
		{
			name: "Standard CLF",
			line: `127.0.0.1 - - [10/Oct/2023:13:55:36 +0800] "GET / HTTP/1.1" 200 612`,
			want: Event{
				Source: SourceTomcatAccess, SourceIP: "127.0.0.1",
				Method: "GET", Path: "/", Status: 200, BytesSent: 612,
				Timestamp: wantT,
			},
		},
		{
			name: "With referer and ua",
			line: `127.0.0.1 - - [10/Oct/2023:13:55:36 +0800] "GET /app HTTP/1.1" 500 0 "-" "Java/1.8"`,
			want: Event{
				Source: SourceTomcatAccess, SourceIP: "127.0.0.1",
				Method: "GET", Path: "/app", Status: 500, BytesSent: 0,
				UserAgent: "Java/1.8", Timestamp: wantT,
			},
		},
		{
			name: "Bytes dash",
			line: `127.0.0.1 - - [10/Oct/2023:13:55:36 +0800] "GET / HTTP/1.1" 200 -`,
			want: Event{
				Source: SourceTomcatAccess, SourceIP: "127.0.0.1",
				Method: "GET", Path: "/", Status: 200, BytesSent: 0,
				Timestamp: wantT,
			},
		},
		{
			name: "IPv6 ::1",
			line: `::1 - - [10/Oct/2023:13:55:36 +0800] "POST /api HTTP/1.1" 201 42`,
			want: Event{
				Source: SourceTomcatAccess, SourceIP: "::1",
				Method: "POST", Path: "/api", Status: 201, BytesSent: 42,
				Timestamp: wantT,
			},
		},
		{
			name: "POST with referer",
			line: `192.168.0.1 - - [10/Oct/2023:13:55:36 +0800] "POST /login HTTP/1.1" 200 88 "https://example.com/" "Tomcat/9"`,
			want: Event{
				Source: SourceTomcatAccess, SourceIP: "192.168.0.1",
				Method: "POST", Path: "/login", Status: 200, BytesSent: 88,
				Referer: "https://example.com/", UserAgent: "Tomcat/9", Timestamp: wantT,
			},
		},
		{
			name:    "Missing status (tomcat requires status)",
			line:    `127.0.0.1 - - [10/Oct/2023:13:55:36 +0800] "GET / HTTP/1.1"`,
			wantErr: ErrUnparsable,
		},
		{
			name:    "Empty",
			line:    "",
			wantErr: ErrUnparsable,
		},
	}

	p := &tomcatParser{}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ev, err := p.Parse(tc.line)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Parse err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse err = %v, want nil", err)
			}
			if ev.Source != tc.want.Source {
				t.Errorf("Source = %q, want %q", ev.Source, tc.want.Source)
			}
			if ev.SourceIP != tc.want.SourceIP {
				t.Errorf("SourceIP = %q, want %q", ev.SourceIP, tc.want.SourceIP)
			}
			if ev.Method != tc.want.Method {
				t.Errorf("Method = %q, want %q", ev.Method, tc.want.Method)
			}
			if ev.Path != tc.want.Path {
				t.Errorf("Path = %q, want %q", ev.Path, tc.want.Path)
			}
			if ev.Status != tc.want.Status {
				t.Errorf("Status = %d, want %d", ev.Status, tc.want.Status)
			}
			if ev.BytesSent != tc.want.BytesSent {
				t.Errorf("BytesSent = %d, want %d", ev.BytesSent, tc.want.BytesSent)
			}
			if ev.Referer != tc.want.Referer {
				t.Errorf("Referer = %q, want %q", ev.Referer, tc.want.Referer)
			}
			if ev.UserAgent != tc.want.UserAgent {
				t.Errorf("UserAgent = %q, want %q", ev.UserAgent, tc.want.UserAgent)
			}
			if !ev.Timestamp.Equal(tc.want.Timestamp) {
				t.Errorf("Timestamp = %v, want %v", ev.Timestamp, tc.want.Timestamp)
			}
		})
	}
}

// ===== linux_auth 解析器表驱动测试 =====

func TestLinuxAuthParser_Table(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		line      string
		wantErr   error
		wantIP    string
		wantUser  string
		wantFrag  string // AuthAction 片段包含校验
		wantMonth time.Month
	}{
		{
			name:      "Failed password invalid user",
			line:      `Mar 2 16:38:12 host sshd[1234]: Failed password for invalid user root from 1.2.3.4 port 12345 ssh2`,
			wantIP:    "1.2.3.4",
			wantUser:  "root",
			wantFrag:  "Failed password",
			wantMonth: time.March,
		},
		{
			name:      "Accepted password",
			line:      `Mar 2 16:38:12 host sshd[1234]: Accepted password for root from 1.2.3.4 port 12345 ssh2`,
			wantIP:    "1.2.3.4",
			wantUser:  "root",
			wantFrag:  "Accepted password",
			wantMonth: time.March,
		},
		{
			name:      "Failed password valid user",
			line:      `Dec 31 23:59:59 web01 sshd[99]: Failed password for admin from 10.0.0.1 port 54321 ssh2`,
			wantIP:    "10.0.0.1",
			wantUser:  "admin",
			wantFrag:  "Failed password",
			wantMonth: time.December,
		},
		{
			name:      "No user no ip (connection closed)",
			line:      `Mar 2 16:38:12 host sshd[1234]: Connection closed by 1.2.3.4 [preauth]`,
			wantIP:    "",
			wantUser:  "",
			wantFrag:  "Connection closed",
			wantMonth: time.March,
		},
		{
			name:      "IPv6 source address",
			line:      `Mar 2 16:38:12 host sshd[1234]: Failed password for root from 2001:db8::1 port 54321 ssh2`,
			wantIP:    "2001:db8::1",
			wantUser:  "root",
			wantFrag:  "Failed password",
			wantMonth: time.March,
		},
		{
			name:    "Empty line",
			line:    "  ",
			wantErr: ErrUnparsable,
		},
		{
			name:    "Unparsable garbage",
			line:    "not a syslog line",
			wantErr: ErrUnparsable,
		},
	}

	p := &linuxAuthParser{}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ev, err := p.Parse(tc.line)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Parse err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse err = %v, want nil", err)
			}
			if ev.Source != SourceLinuxAuth {
				t.Errorf("Source = %q, want %q", ev.Source, SourceLinuxAuth)
			}
			if ev.SourceIP != tc.wantIP {
				t.Errorf("SourceIP = %q, want %q", ev.SourceIP, tc.wantIP)
			}
			if ev.AuthUser != tc.wantUser {
				t.Errorf("AuthUser = %q, want %q", ev.AuthUser, tc.wantUser)
			}
			if tc.wantFrag != "" {
				if !contains(ev.AuthAction, tc.wantFrag) {
					t.Errorf("AuthAction = %q, want contains %q", ev.AuthAction, tc.wantFrag)
				}
			}
			if ev.Timestamp.Month() != tc.wantMonth {
				t.Errorf("Timestamp month = %v, want %v", ev.Timestamp.Month(), tc.wantMonth)
			}
			if ev.RawLine == "" {
				t.Errorf("RawLine empty, want original line")
			}
		})
	}
}

// contains 简单子串包含，避免引入 strings 仅用于断言。
func contains(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
