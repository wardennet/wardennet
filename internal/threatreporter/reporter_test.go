package threatreporter

import (
	"sync"
	"testing"
	"time"

	"github.com/wardennet/agent/internal/detector"
	"github.com/wardennet/agent/internal/plugin"
)

// mockPlugin 捕获 ReportFull 调用（V2 完整上报接口）。
type mockPlugin struct {
	mu           sync.Mutex
	fullBatches  [][]detector.Event // 每次 ReportFull 收到的完整 detector.Event 快照
	callCh       chan struct{}
}

func newMockPlugin() *mockPlugin {
	return &mockPlugin{callCh: make(chan struct{}, 32)}
}

func (m *mockPlugin) Init(agentID, version string) error                    { return nil }
func (m *mockPlugin) Shutdown() error                                        { return nil }
func (m *mockPlugin) Auth(ctx plugin.AuthContext) (plugin.AuthResult, error)  { return plugin.AuthResult{OK: true}, nil }
func (m *mockPlugin) Heartbeat() (bool, error)                               { return false, nil }
func (m *mockPlugin) Diff(req plugin.DiffRequest) (plugin.DiffResult, error)  { return plugin.DiffResult{OK: true}, nil }
func (m *mockPlugin) FetchFullGlobalSnapshot() (plugin.GlobalSnapshot, error)  { return plugin.GlobalSnapshot{}, nil }
func (m *mockPlugin) FetchTenantSnapshot() (plugin.TenantSnapshot, error)      { return plugin.TenantSnapshot{}, nil }
func (m *mockPlugin) HandleCommand(cmd plugin.RemoteCommand) (plugin.CommandResult, error) {
	return plugin.CommandResult{ID: cmd.ID, Ok: true}, nil
}
func (m *mockPlugin) FetchPendingCommands() ([]plugin.RemoteCommand, error) { return nil, nil }
func (m *mockPlugin) FetchFeatures(tenantID string, currentVersion int64) (*plugin.FeatureResult, error) {
	return &plugin.FeatureResult{Version: currentVersion}, nil
}

func (m *mockPlugin) ReportFull(events interface{}) error {
	batch, ok := events.([]detector.Event)
	if !ok {
		return nil
	}
	m.mu.Lock()
	snap := make([]detector.Event, len(batch))
	copy(snap, batch)
	m.fullBatches = append(m.fullBatches, snap)
	m.mu.Unlock()
	select {
	case m.callCh <- struct{}{}:
	default:
	}
	return nil
}

func (m *mockPlugin) totalEvents() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, b := range m.fullBatches {
		n += len(b)
	}
	return n
}

func (m *mockPlugin) firstBatch() []detector.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.fullBatches) == 0 {
		return nil
	}
	return m.fullBatches[0]
}

func (m *mockPlugin) waitReport(timeout time.Duration) bool {
	select {
	case <-m.callCh:
		return true
	case <-time.After(timeout):
		return false
	}
}

func TestReporter_BufferFlush(t *testing.T) {
	mock := newMockPlugin()
	cfg := Config{BufferSize: 3, FlushInterval: 10 * time.Second}
	r := New(mock, "test-agent", cfg)
	r.Start()
	defer r.Stop()

	for i := 0; i < 3; i++ {
		r.Add(detector.Event{
			SourceIP:       "1.2.3.4",
			LocalRiskScore: 50,
			ClientIPFrom:   "cf_connecting_ip",
			Path:           "/admin",
			Source:         "nginx_access",
			Timestamp:      time.Now().Unix(),
		})
	}

	if !mock.waitReport(2 * time.Second) {
		t.Fatal("expected ReportFull to be called within 2s")
	}
	if mock.totalEvents() != 3 {
		t.Errorf("expected 3 events reported, got %d", mock.totalEvents())
	}
}

func TestReporter_TimerFlush(t *testing.T) {
	mock := newMockPlugin()
	cfg := Config{BufferSize: 100, FlushInterval: 100 * time.Millisecond}
	r := New(mock, "test-agent", cfg)
	r.Start()
	defer r.Stop()

	for i := 0; i < 2; i++ {
		r.Add(detector.Event{
			SourceIP:       "5.6.7.8",
			LocalRiskScore: 30,
			Path:           "/login",
		})
	}

	if !mock.waitReport(2 * time.Second) {
		t.Fatal("expected ReportFull to be called by timer within 2s")
	}
	if mock.totalEvents() != 2 {
		t.Errorf("expected 2 events reported, got %d", mock.totalEvents())
	}
}

func TestReporter_NoopPlugin_NoBlock(t *testing.T) {
	r := New(nil, "agent-test", DefaultConfig())
	r.Start()
	r.Add(detector.Event{SourceIP: "1.2.3.4", LocalRiskScore: 50})
	r.Add(detector.Event{SourceIP: "1.2.3.4", LocalRiskScore: 50})
	time.Sleep(100 * time.Millisecond)
	r.Stop()

	stats := r.Stats()
	if stats.BufferLen != 0 {
		t.Errorf("expected buffer empty after Stop flush, got %d", stats.BufferLen)
	}
}

func TestReporter_Concurrency(t *testing.T) {
	mock := newMockPlugin()
	cfg := Config{BufferSize: 10, FlushInterval: 100 * time.Millisecond}
	r := New(mock, "test-agent", cfg)
	r.Start()
	defer r.Stop()

	var wg sync.WaitGroup
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				r.Add(detector.Event{
					SourceIP:       "10.0.0.1",
					LocalRiskScore: 20,
					Path:           "/api",
				})
			}
		}()
	}
	wg.Wait()

	time.Sleep(300 * time.Millisecond)
	r.Stop()

	total := mock.totalEvents()
	if total != 50 {
		t.Errorf("expected 50 total events, got %d", total)
	}
}

func TestReporter_StopFlushesRemaining(t *testing.T) {
	mock := newMockPlugin()
	cfg := Config{BufferSize: 1000, FlushInterval: 10 * time.Second}
	r := New(mock, "test-agent", cfg)
	r.Start()

	for i := 0; i < 5; i++ {
		r.Add(detector.Event{SourceIP: "1.1.1.1", LocalRiskScore: 10})
	}

	r.Stop()

	if mock.totalEvents() != 5 {
		t.Errorf("expected Stop to flush 5 remaining events, got %d", mock.totalEvents())
	}
}

// TestReporter_FullEventPassedToPlugin 验证 threatreporter 传完整 detector.Event
// 给闭源插件——闭源插件内部自行做防投毒 + 评分 + 裁剪。
func TestReporter_FullEventPassedToPlugin(t *testing.T) {
	mock := newMockPlugin()
	cfg := Config{BufferSize: 1, FlushInterval: 10 * time.Second}
	r := New(mock, "agent-cf-001", cfg)
	r.Start()
	defer r.Stop()

	r.Add(detector.Event{
		SourceIP:       "222.132.94.196",
		EdgeIP:         "104.16.132.229",
		ClientIPFrom:   "cf_connecting_ip",
		Path:           "/admin/api/v1/users",
		Method:         "POST",
		Status:         200,
		UserAgent:      "Mozilla/5.0...",
		Referer:        "https://admin.example.com/",
		LocalRiskScore: 50,
		Source:         "nginx_access",
		Timestamp:      1700000000,
	})

	if !mock.waitReport(2 * time.Second) {
		t.Fatal("expected ReportFull called")
	}

	batch := mock.firstBatch()
	if batch == nil || len(batch) != 1 {
		t.Fatalf("expected 1 full event, got batch=%v", batch)
	}

	// V2: threatreporter 不裁剪，完整 detector.Event 应该全字段保留
	// 裁剪责任在闭源插件 ReportFull() 内部
	ev := batch[0]
	if ev.SourceIP != "222.132.94.196" {
		t.Errorf("SourceIP lost: %q", ev.SourceIP)
	}
	if ev.EdgeIP != "104.16.132.229" {
		t.Errorf("EdgeIP lost (完整事件应保留给闭源插件做防投毒): %q", ev.EdgeIP)
	}
	if ev.Path != "/admin/api/v1/users" {
		t.Errorf("Path lost (完整事件应保留给闭源插件做行为一致性画像): %q", ev.Path)
	}
	if ev.Method != "POST" {
		t.Errorf("Method lost: %q", ev.Method)
	}
	if ev.UserAgent != "Mozilla/5.0..." {
		t.Errorf("UserAgent lost: %q", ev.UserAgent)
	}
	if ev.Referer != "https://admin.example.com/" {
		t.Errorf("Referer lost: %q", ev.Referer)
	}
	if ev.LocalRiskScore != 50 {
		t.Errorf("LocalRiskScore lost: %d", ev.LocalRiskScore)
	}
	if ev.Source != "nginx_access" {
		t.Errorf("Source lost: %q", ev.Source)
	}
}

func strContains(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	if len(s) < len(sub) {
		return false
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}