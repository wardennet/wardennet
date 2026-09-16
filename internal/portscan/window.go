package portscan

import (
	"sync"
	"time"
)

// portBucket tracks distinct ports hit within a single second.
type portBucket struct {
	second int64
	ports  map[int]struct{}
}

// portWindow is a circular buffer of buckets for one window size.
// Tracks the cardinality (distinct count) of ports accessed within [now - windowSec, now].
type portWindow struct {
	windowSec int
	buckets   []portBucket
}

func newPortWindow(windowSec int) *portWindow {
	if windowSec <= 0 {
		windowSec = 1
	}
	return &portWindow{
		windowSec: windowSec,
		buckets:   make([]portBucket, windowSec),
	}
}

// record adds a port hit at the given timestamp second.
func (w *portWindow) record(nowSec int64, port int) {
	pos := int(nowSec % int64(w.windowSec))
	b := &w.buckets[pos]
	if b.second != nowSec {
		b.second = nowSec
		b.ports = map[int]struct{}{}
	}
	b.ports[port] = struct{}{}
}

// sum returns the number of distinct ports in this window.
func (w *portWindow) sum(nowSec int64) int {
	cutoff := nowSec - int64(w.windowSec)
	seen := make(map[int]struct{})
	for i := 0; i < w.windowSec; i++ {
		b := &w.buckets[i]
		if b.second <= cutoff {
			continue
		}
		for p := range b.ports {
			seen[p] = struct{}{}
		}
	}
	return len(seen)
}

// portEntry holds per-IP window state.
type portEntry struct {
	mu     sync.Mutex
	last   int64
	window [3]*portWindow
}

// PortWindowTracker multi-IP × three-window port cardinality tracker.
// Thread-safe; evict goroutine cleans up idle IPs.
type PortWindowTracker struct {
	cfg    [3]PortWindow
	mu     sync.RWMutex
	ips    map[string]*portEntry
	stop   chan struct{}
	once   sync.Once
}

// NewPortWindowTracker creates a tracker with given three-window config.
func NewPortWindowTracker(cfg [3]PortWindow) *PortWindowTracker {
	for i := 0; i < 3; i++ {
		if cfg[i].Size <= 0 {
			cfg[i].Size = 1
		}
	}
	t := &PortWindowTracker{
		cfg:  cfg,
		ips:  make(map[string]*portEntry),
		stop: make(chan struct{}),
	}
	go t.evictLoop(60 * time.Second)
	return t
}

func (t *PortWindowTracker) evictLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-t.stop:
			return
		case <-ticker.C:
			t.Evict(5 * 60)
		}
	}
}

// Close stops the evict goroutine.
func (t *PortWindowTracker) Close() {
	t.once.Do(func() { close(t.stop) })
}

func (t *PortWindowTracker) getOrCreateEntry(ip string, nowSec int64) *portEntry {
	t.mu.RLock()
	e, ok := t.ips[ip]
	t.mu.RUnlock()
	if ok {
		return e
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if e2, ok2 := t.ips[ip]; ok2 {
		return e2
	}
	e = &portEntry{last: nowSec}
	for i := 0; i < 3; i++ {
		e.window[i] = newPortWindow(t.cfg[i].Size)
	}
	t.ips[ip] = e
	return e
}

// Record logs a single port hit from srcIP at current time.
func (t *PortWindowTracker) Record(srcIP string, dstPort int) {
	if srcIP == "" || dstPort <= 0 {
		return
	}
	nowSec := time.Now().Unix()
	e := t.getOrCreateEntry(srcIP, nowSec)
	e.mu.Lock()
	e.last = nowSec
	for i := 0; i < 3; i++ {
		e.window[i].record(nowSec, dstPort)
	}
	e.mu.Unlock()
}

// RecordAt logs a port hit at a specific timestamp (used for replay/testing).
func (t *PortWindowTracker) RecordAt(srcIP string, dstPort int, ts int64) {
	if srcIP == "" || dstPort <= 0 || ts <= 0 {
		return
	}
	e := t.getOrCreateEntry(srcIP, ts)
	e.mu.Lock()
	e.last = ts
	for i := 0; i < 3; i++ {
		e.window[i].record(ts, dstPort)
	}
	e.mu.Unlock()
}

// Count returns distinct port counts across the three windows for srcIP.
// IP not tracked → all zeros.
func (t *PortWindowTracker) Count(srcIP string) [3]int {
	var out [3]int
	if srcIP == "" {
		return out
	}
	t.mu.RLock()
	e, ok := t.ips[srcIP]
	t.mu.RUnlock()
	if !ok {
		return out
	}
	nowSec := time.Now().Unix()
	e.mu.Lock()
	for i := 0; i < 3; i++ {
		out[i] = e.window[i].sum(nowSec)
	}
	e.mu.Unlock()
	return out
}

// CountAt returns distinct port counts at a specific timestamp (testing).
func (t *PortWindowTracker) CountAt(srcIP string, ts int64) [3]int {
	var out [3]int
	if srcIP == "" {
		return out
	}
	t.mu.RLock()
	e, ok := t.ips[srcIP]
	t.mu.RUnlock()
	if !ok {
		return out
	}
	e.mu.Lock()
	for i := 0; i < 3; i++ {
		out[i] = e.window[i].sum(ts)
	}
	e.mu.Unlock()
	return out
}

// Evict removes IPs idle for idleSeconds or longer. Returns count evicted.
func (t *PortWindowTracker) Evict(idleSeconds int) int {
	cutoff := time.Now().Unix() - int64(idleSeconds)
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for ip, e := range t.ips {
		e.mu.Lock()
		idle := e.last <= cutoff
		e.mu.Unlock()
		if idle {
			delete(t.ips, ip)
			n++
		}
	}
	return n
}

// IPCount returns number of IPs currently tracked.
func (t *PortWindowTracker) IPCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.ips)
}
