package portscan

import (
	"testing"
	"time"
)

func TestPortWindowTracker_DefaultConfig(t *testing.T) {
	cfg := DefaultPortScanConfig()
	tracker := NewPortWindowTracker(cfg.Windows)
	defer tracker.Close()

	if tracker.IPCount() != 0 {
		t.Fatalf("expected 0 IPs, got %d", tracker.IPCount())
	}
}

func TestPortWindowTracker_BelowThreshold(t *testing.T) {
	cfg := DefaultPortScanConfig()
	tracker := NewPortWindowTracker(cfg.Windows)
	defer tracker.Close()

	now := time.Now().Unix()
	ip := "192.168.1.100"

	// Hit 4 distinct ports within 5s → should NOT breach the 5-port threshold
	for port := 1; port <= 4; port++ {
		tracker.RecordAt(ip, port, now)
	}

	counts := tracker.CountAt(ip, now)
	if counts[0] != 4 {
		t.Errorf("window 0 (5s): expected 4 distinct ports, got %d", counts[0])
	}
	// All should be below their respective thresholds
	if counts[0] <= cfg.Windows[0].MaxPorts &&
		counts[1] <= cfg.Windows[1].MaxPorts &&
		counts[2] <= cfg.Windows[2].MaxPorts {
		// OK — all below threshold
	} else {
		t.Errorf("counts %v exceeded thresholds", counts)
	}
}

func TestPortWindowTracker_Trigger5s(t *testing.T) {
	cfg := DefaultPortScanConfig()
	tracker := NewPortWindowTracker(cfg.Windows)
	defer tracker.Close()

	now := time.Now().Unix()
	ip := "10.0.0.50"

	// 6 distinct ports in 5 seconds → breaches first window (MaxPorts=5)
	for port := 10; port <= 15; port++ {
		tracker.RecordAt(ip, port, now)
	}

	counts := tracker.CountAt(ip, now)
	if counts[0] != 6 {
		t.Fatalf("expected 6 distinct ports, got %d", counts[0])
	}
	if counts[0] <= cfg.Windows[0].MaxPorts {
		t.Errorf("window 0 should be breached: %d <= %d", counts[0], cfg.Windows[0].MaxPorts)
	}
}

func TestPortWindowTracker_Trigger30s(t *testing.T) {
	cfg := DefaultPortScanConfig()
	tracker := NewPortWindowTracker(cfg.Windows)
	defer tracker.Close()

	base := time.Now().Unix()
	ip := "10.0.0.60"

	// Hit 15 distinct ports spread across 30s, then one more → breaches second window (MaxPorts=15)
	for port := 100; port <= 114; port++ {
		tracker.RecordAt(ip, port, base)
	}
	// Add one more at t=+10s (still within 30s window) → 16 total
	tracker.RecordAt(ip, 115, base+10)

	counts := tracker.CountAt(ip, base+10)
	if counts[1] != 16 {
		t.Fatalf("window 1: expected 16 distinct ports, got %d", counts[1])
	}
	if counts[1] <= cfg.Windows[1].MaxPorts {
		t.Errorf("window 1 should be breached: %d <= %d", counts[1], cfg.Windows[1].MaxPorts)
	}
}

func TestPortWindowTracker_Expiry(t *testing.T) {
	cfg := DefaultPortScanConfig()
	tracker := NewPortWindowTracker(cfg.Windows)
	defer tracker.Close()

	base := time.Now().Unix()
	ip := "10.0.0.70"

	// 6 ports at t=0 → breaches 5s window
	for port := 200; port <= 205; port++ {
		tracker.RecordAt(ip, port, base)
	}

	// After 6 seconds (window expired), count should drop
	countsAfter := tracker.CountAt(ip, base+6)
	if countsAfter[0] != 0 {
		t.Errorf("after window expiry, window 0 should be 0, got %d", countsAfter[0])
	}
	// But 30s window should still see them
	if countsAfter[1] != 6 {
		t.Errorf("window 1 should still have 6, got %d", countsAfter[1])
	}
}

func TestPortWindowTracker_Dedup(t *testing.T) {
	cfg := DefaultPortScanConfig()
	tracker := NewPortWindowTracker(cfg.Windows)
	defer tracker.Close()

	now := time.Now().Unix()
	ip := "10.0.0.80"

	// Hit same port 100 times → still only 1 distinct
	for i := 0; i < 100; i++ {
		tracker.RecordAt(ip, 443, now)
	}
	counts := tracker.CountAt(ip, now)
	if counts[0] != 1 {
		t.Errorf("expected 1 distinct (dedup), got %d", counts[0])
	}
}

func TestNoopDetector(t *testing.T) {
	cfg := DefaultPortScanConfig()
	// cfg.Enabled = false → should return noopDetector
	d, err := NewPortScanDetector(cfg, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	high, score := d.Process("1.2.3.4", 22)
	if high {
		t.Error("noopDetector should never return high=true")
	}
	if score != 0 {
		t.Errorf("noopDetector score should be 0, got %d", score)
	}
	d.Close()
}

func TestPortScanDetector_ProcessDirect(t *testing.T) {
	cfg := DefaultPortScanConfig()
	cfg.Enabled = true
	cfg.Source = "disabled" // won't create source, but we test Process() directly

	// Manually create a detector with source disabled
	tracker := NewPortWindowTracker(cfg.Windows)
	defer tracker.Close()

	d := &portScanDetector{
		cfg:     cfg,
		tracker: tracker,
		stop:    make(chan struct{}),
	}
	defer d.Close()

	ip := "10.10.10.10"
	// 6 distinct ports → triggers 5s window
	for port := 3000; port <= 3005; port++ {
		high, score := d.Process(ip, port)
		if port < 3005 {
			if high {
				t.Errorf("port %d should not trigger yet", port)
			}
		} else {
			if !high {
				t.Error("6th port should trigger high=true")
			}
			if score != cfg.Weight {
				t.Errorf("expected score %d, got %d", cfg.Weight, score)
			}
		}
	}
}

func TestPortScanDetector_SinglePortNormal(t *testing.T) {
	cfg := DefaultPortScanConfig()
	cfg.Enabled = true
	cfg.Source = "disabled"
	tracker := NewPortWindowTracker(cfg.Windows)
	defer tracker.Close()

	d := &portScanDetector{
		cfg:     cfg,
		tracker: tracker,
		stop:    make(chan struct{}),
	}
	defer d.Close()

	ip := "192.168.1.1"
	// Single IP hitting only port 80, 100 times → should NOT trigger
	for i := 0; i < 100; i++ {
		high, _ := d.Process(ip, 80)
		if high {
			t.Error("normal traffic on single port should not trigger")
		}
	}
}
