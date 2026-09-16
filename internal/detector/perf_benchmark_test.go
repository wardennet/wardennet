package detector

import (
	"strconv"
	"testing"
	"time"
)

func BenchmarkRecord_QPS(b *testing.B) {
	cfg := DefaultDetectorCfg()
	d := NewLocalDetector(&cfg, nil)
	defer d.Close()
	w := d.window

	now := time.Now().Unix()
	ip := "10.0.0.1"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ts := now + int64(i%30)
		ev := &Event{
			SourceIP:  ip,
			Method:    "GET",
			Path:      "/api/users/" + strconv.Itoa(i%500) + "/detail",
			Status:    200,
			UserAgent: "Mozilla/5.0 Chrome/120",
			Timestamp: ts,
		}
		w.Record(ev)
	}
}

func BenchmarkProcess(b *testing.B) {
	cfg := DefaultDetectorCfg()
	d := NewLocalDetector(&cfg, nil)
	defer d.Close()

	now := time.Now().Unix()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ev := Event{
			SourceIP:  "10.0.0.1",
			Method:    "GET",
			Path:      "/api/v1/item/" + strconv.Itoa(i%100),
			Status:    200,
			UserAgent: "Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36",
			Referer:   "https://example.com/list",
			Timestamp: now + int64(i%30),
		}
		d.Process(ev)
	}
}
