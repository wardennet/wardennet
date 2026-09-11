// Package stats - collector_test.go 统计收集器单元测试。
package stats

import (
	"testing"
	"time"
)

func TestCollector_Record(t *testing.T) {
	c := NewCollector(0) // 全记录

	// 模拟记录 100 个事件
	for i := 0; i < 100; i++ {
		score := 0
		isHigh := false
		if i < 10 {
			score = 80
			isHigh = true
		} else if i < 30 {
			score = 30
		}

		status := 200
		switch {
		case i%5 == 0 && i%3 != 0:
			status = 500 // 5xx: 5,10,20,25,35,40,50,55,65,70,80,85,95,100 = 14 条
		case i%3 == 0:
			status = 404 // 4xx: 3,6,9,12,15,18,21,24,27,30,33,36,39,42,45,48,51,54,57,60,63,66,69,72,75,78,81,84,87,90,93,96,99 = 33+7=40 条
		}

		source := "nginx_access"
		if i%4 == 0 {
			source = "apache_access"
		}

		c.Record(EventRecord{
			Timestamp: time.Now().Unix(),
			SourceIP:  "192.168.1." + string(rune('0'+i%10)),
			Score:     score,
			IsHigh:    isHigh,
			Source:    source,
			Status:    status,
			Dimensions: map[string]interface{}{
				"sensitive_path":  i < 5,
				"bot_ua":          i < 15 && i >= 10,
				"empty_referer":   i < 25 && i >= 15,
				"dangerous_method": false,
				"auth_fail":       false,
			},
		})
	}

	report := c.GenerateReport()

	if report.TotalEvents != 100 {
		t.Errorf("TotalEvents = %d, want 100", report.TotalEvents)
	}
	if report.HighScoreCount != 10 {
		t.Errorf("HighScoreCount = %d, want 10", report.HighScoreCount)
	}
	if report.MediumCount != 20 {
		t.Errorf("MediumCount = %d, want 20", report.MediumCount)
	}
	if report.LowScoreCount != 70 {
		t.Errorf("LowScoreCount = %d, want 70", report.LowScoreCount)
	}
	if report.Status4xx != 34 {
		t.Errorf("Status4xx = %d, want 34", report.Status4xx)
	}
	if report.Status5xx != 13 {
		t.Errorf("Status5xx = %d, want 13", report.Status5xx)
	}
	if report.SensitivePathHits < 5 {
		t.Errorf("SensitivePathHits = %d, want >= 5", report.SensitivePathHits)
	}
	if report.TopBlocked == nil || len(report.TopBlocked) == 0 {
		t.Error("TopBlocked should not be empty")
	}
}

func TestCollector_SampleRate(t *testing.T) {
	c := NewCollector(10) // 采样率 1/10

	for i := 0; i < 100; i++ {
		c.Record(EventRecord{
			Timestamp: time.Now().Unix(),
			SourceIP:  "10.0.0." + string(rune('0'+i%10)),
			Score:     10,
			IsHigh:    false,
			Source:    "nginx_access",
			Status:    200,
		})
	}

	// 全记录仍会计入统计
	report := c.GenerateReport()
	if report.TotalEvents != 100 {
		t.Errorf("TotalEvents = %d, want 100", report.TotalEvents)
	}

	// 但 recent events 应该只有 ~10 条
	recent := c.RecentEvents(100)
	if len(recent) > 15 {
		t.Errorf("RecentEvents len = %d, expected ~10 (sampled)", len(recent))
	}
}

func TestCollector_Reset(t *testing.T) {
	c := NewCollector(0)

	for i := 0; i < 50; i++ {
		c.Record(EventRecord{
			Timestamp: time.Now().Unix(),
			SourceIP:  "10.0.0." + string(rune('0'+i)),
			Score:     50,
			IsHigh:    true,
			Source:    "nginx_access",
			Status:    404,
		})
	}

	c.Reset()

	report := c.GenerateReport()
	if report.TotalEvents != 0 {
		t.Errorf("TotalEvents after reset = %d, want 0", report.TotalEvents)
	}
	if report.HighScoreCount != 0 {
		t.Errorf("HighScoreCount after reset = %d, want 0", report.HighScoreCount)
	}
}

func TestCollector_RecentEvents(t *testing.T) {
	c := NewCollector(0)

	for i := 0; i < 50; i++ {
		c.Record(EventRecord{
			Timestamp: int64(i),
			SourceIP:  "10.0.0." + string(rune('0'+i)),
			Score:     i,
			IsHigh:    false,
			Source:    "nginx_access",
			Status:    200,
		})
	}

	// 获取最近 5 条
	recent := c.RecentEvents(5)
	if len(recent) != 5 {
		t.Errorf("RecentEvents(5) len = %d, want 5", len(recent))
	}

	// 应该是最新的事件（timestamp 最大的）
	for i := 0; i < len(recent)-1; i++ {
		if recent[i].Timestamp < recent[i+1].Timestamp {
			t.Errorf("RecentEvents not in descending order: %d < %d",
				recent[i].Timestamp, recent[i+1].Timestamp)
		}
	}
}

func TestCollector_TopBlocked(t *testing.T) {
	c := NewCollector(0)

	// 记录多个 IP 的拉黑事件
	ips := []struct {
		ip    string
		count int
	}{
		{"10.0.0.1", 10},
		{"10.0.0.2", 5},
		{"10.0.0.3", 20},
	}

	for _, ip := range ips {
		for j := 0; j < ip.count; j++ {
			c.Record(EventRecord{
				Timestamp: time.Now().Unix(),
				SourceIP:  ip.ip,
				Score:     80,
				IsHigh:    true,
				Source:    "nginx_access",
				Status:    404,
			})
		}
	}

	report := c.GenerateReport()
	if len(report.TopBlocked) != 3 {
		t.Errorf("TopBlocked len = %d, want 3", len(report.TopBlocked))
	}

	// 应该按 BlockCount 降序排列
	if report.TopBlocked[0].IP != "10.0.0.3" {
		t.Errorf("TopBlocked[0].IP = %s, want 10.0.0.3 (highest count)",
			report.TopBlocked[0].IP)
	}
}
