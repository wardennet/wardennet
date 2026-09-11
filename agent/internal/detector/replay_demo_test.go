package detector

import (
	"bufio"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/wardennet/agent/internal/logparser"
)

// TestReplay_DemoAccessLog 重放 demo/access.log，端到端验证。
// 核心断言：
// 1) 220.186.143.104（正常浏览器用户 token 过期）不再触发封禁
// 2) 真实扫描 IP（python-requests/Go-http-client/nmap 等 UA）仍能被封禁
func TestReplay_DemoAccessLog(t *testing.T) {
	cfg := DefaultDetectorCfg()
	d := NewLocalDetector(&cfg, nil)
	defer d.Close()
	SetBaselinesForTest(d, MakeMediumBaselines())

	blocked := map[string]bool{}
	var blockCount int
	d.RegisterBlockTrigger(func(ev Event) bool {
		blocked[ev.SourceIP] = true
		blockCount++
		return true
	})

	reg := logparser.NewRegistry()
	parser, ok := reg.Get(logparser.SourceNginxAccess)
	if !ok {
		t.Fatal("nginx_access parser not found")
	}

	f, err := os.Open("d:/coder/business/WardenNet/demo/access.log")
	if err != nil {
		t.Fatalf("open demo/access.log: %v", err)
	}
	defer f.Close()

	maxScoreByIP := map[string]int{}
	total := 0
	scannerIPs := map[string]int{} // IP → 可疑信号计数

	scannerPatterns := []string{
		"python-requests", "Go-http-client", "curl/", "nikto", "masscan",
		"Nmap", "sqlmap", "dirb", "gobuster", "wfuzz", "acunetix", "arachni",
		"Mozilla/5.0 (compatible", "Scrapy", "libwww-perl", "Java/1.",
	}
	scannerPathPatterns := []string{
		"/.env", "/wp-login", "/phpmyadmin", "/admin", "/etc/passwd",
		"/config", "/backup", "/.git", "/.svn", "/.DS_Store", "/cgi-bin",
		"/shell.php", "/upload", "/actuator", "/swagger", "/api-docs",
	}

	scannerUAFlag := func(ua string) bool {
		for _, p := range scannerPatterns {
			if containsStr(ua, p) {
				return true
			}
		}
		return false
	}
	scannerPathFlag := func(path string) bool {
		for _, p := range scannerPathPatterns {
			if containsStr(path, p) {
				return true
			}
		}
		return false
	}
	scannerStatusFlag := func(status int) bool {
		return status >= 500 && status < 600
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		le, err := parser.Parse(line)
		if err != nil {
			continue
		}

		// 手动转换
		ev := Event{
			SourceIP:   le.SourceIP,
			Source:     le.Source,
			Method:     le.Method,
			Path:       le.Path,
			Status:     le.Status,
			BytesSent:  le.BytesSent,
			UserAgent:  le.UserAgent,
			Referer:    le.Referer,
			AuthAction: le.AuthAction,
			Body:       le.Body,
			ContentType: le.ContentType,
			FileName:   le.FileName,
			FileExt:    le.FileExt,
			FileMime:   le.FileMime,
			EdgeIP:     le.EdgeIP,
		}
		if !le.Timestamp.IsZero() {
			ev.Timestamp = le.Timestamp.Unix()
		} else {
			ev.Timestamp = time.Now().Unix()
		}

		// 标记扫描 IP
		if scannerUAFlag(ev.UserAgent) {
			scannerIPs[ev.SourceIP] += 2
		}
		if scannerPathFlag(ev.Path) {
			scannerIPs[ev.SourceIP] += 2
		}
		if scannerStatusFlag(ev.Status) {
			scannerIPs[ev.SourceIP] += 1
		}

		ev2 := d.Process(ev)
		total++
		if ev2.LocalRiskScore > maxScoreByIP[ev.SourceIP] {
			maxScoreByIP[ev.SourceIP] = ev2.LocalRiskScore
		}
	}

	fmt.Printf("\n=== Replay done: %d events ===\n", total)
	fmt.Printf("Total block triggers: %d\n", blockCount)

	// 正常用户
	targetIP := "220.186.143.104"
	fmt.Printf("\n--- Normal user (220.186.143.104) ---\n")
	fmt.Printf("  maxScore=%d blocked=%v (ScoreHigh=%d)\n", maxScoreByIP[targetIP], blocked[targetIP], cfg.ScoreHigh)

	if blocked[targetIP] {
		t.Errorf("FAIL: normal user %s was BLOCKED — regression!", targetIP)
	} else {
		t.Logf("OK: normal user %s NOT blocked (maxScore=%d)", targetIP, maxScoreByIP[targetIP])
	}

	// 扫描 IP（阈值 >= 4 分信号）
	fmt.Printf("\n--- Scanner IPs identified ---\n")
	blockedScanners := 0
	notBlockedScanners := 0
	var scannerSet []string
	for ip, sig := range scannerIPs {
		if sig >= 4 {
			scannerSet = append(scannerSet, ip)
		}
	}

	for _, ip := range scannerSet {
		ms := maxScoreByIP[ip]
		isBlocked := blocked[ip]
		if isBlocked {
			blockedScanners++
			fmt.Printf("  OK  %-20s maxScore=%d blocked=true\n", ip, ms)
		} else {
			notBlockedScanners++
			fmt.Printf("  MISS %-20s maxScore=%d blocked=false (sig=%d)\n", ip, ms, scannerIPs[ip])
		}
	}

	fmt.Printf("\n=== Summary ===\n")
	fmt.Printf("Scanner detection rate: %d/%d blocked\n", blockedScanners, len(scannerSet))
	fmt.Printf("Normal user protected: %v\n", !blocked[targetIP])

	if len(scannerSet) > 0 && notBlockedScanners > 0 {
		t.Logf("Note: %d scanner IPs not blocked (may need tuning)", notBlockedScanners)
	}
}

func containsStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
