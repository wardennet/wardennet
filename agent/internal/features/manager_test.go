// Package features - manager_test.go 特征管理器单元测试。
package features

import (
	"sync"
	"testing"
	"time"
)

// mockFetcher 模拟云端拉取器。
type mockFetcher struct {
	mu        sync.Mutex
	resp      *SyncResponse
	err       error
	callCount int
}

func (m *mockFetcher) FetchFeatures(tenantID string, currentVersion int64) (*SyncResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callCount++
	if m.err != nil {
		return nil, m.err
	}
	if m.resp != nil && m.resp.Status == "not_modified" {
		// 版本匹配时返回 not_modified
		if currentVersion >= m.resp.Version {
			return &SyncResponse{Status: "not_modified", Version: currentVersion}, nil
		}
	}
	return m.resp, nil
}

func newTestManager(fetcher FeatureFetcher) *FeatureManager {
	return NewFeatureManager(fetcher, "test-tenant")
}

func TestNewFeatureManager_Defaults(t *testing.T) {
	m := newTestManager(nil)
	defer m.Stop()

	paths := m.GetSensitivePaths()
	if len(paths) == 0 {
		t.Fatal("default sensitive paths should not be empty")
	}

	uas := m.GetBotUserAgents()
	if len(uas) == 0 {
		t.Fatal("default bot UAs should not be empty")
	}

	methods := m.GetDangerousMethods()
	if len(methods) == 0 {
		t.Fatal("default dangerous methods should not be empty")
	}

	if m.GetVersion() != 0 {
		t.Errorf("initial version=%d, want 0", m.GetVersion())
	}
}

func TestFeatureManager_SyncFromCloud(t *testing.T) {
	resp := &SyncResponse{
		Status:  "updated",
		Version: 10,
		Features: map[string][]string{
			"sensitive_path":  []string{"/cloud-path", "/admin"},
			"bot_ua":          []string{"cloud-scanner", "sqlmap"},
			"static_resource": []string{".wasm"},
			"dangerous_method": []string{"DELETE", "PURGE"},
		},
		Count: 6,
	}
	fetcher := &mockFetcher{resp: resp}

	m := newTestManager(fetcher)
	defer m.Stop()

	updated, err := m.SyncFromCloud()
	if err != nil {
		t.Fatalf("sync error: %v", err)
	}
	if !updated {
		t.Errorf("updated=%v, want true", updated)
	}

	// 验证版本号
	if m.GetVersion() != 10 {
		t.Errorf("version=%d, want 10", m.GetVersion())
	}

	// 验证特征值（云端 + 本地合并）
	paths := m.GetSensitivePaths()
	if len(paths) == 0 {
		t.Fatal("cloud sensitive paths should be loaded")
	}
	found := false
	for _, p := range paths {
		if p == "/cloud-path" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("cloud path /cloud-path not found in %v", paths)
	}
}

func TestFeatureManager_NotModified(t *testing.T) {
	resp := &SyncResponse{
		Status: "not_modified",
		Version: 5,
	}
	fetcher := &mockFetcher{resp: resp}

	m := newTestManager(fetcher)
	defer m.Stop()

	// 先设置版本为 5
	m.mu.Lock()
	m.version = 5
	m.mu.Unlock()

	updated, err := m.SyncFromCloud()
	if err != nil {
		t.Fatalf("sync error: %v", err)
	}
	if updated {
		t.Errorf("updated=%v, want false for not_modified", updated)
	}
}

func TestFeatureManager_SyncFailure(t *testing.T) {
	resp := &SyncResponse{
		Status:  "updated",
		Version: 10,
		Features: map[string][]string{"sensitive_path": []string{"/new"}},
	}
	fetcher := &mockFetcher{resp: resp}

	m := newTestManager(fetcher)
	defer m.Stop()

	// 首次同步成功
	_, err := m.SyncFromCloud()
	if err != nil {
		t.Fatalf("first sync error: %v", err)
	}

	// 记录当前敏感路径
	paths := m.GetSensitivePaths()
	foundNew := false
	for _, p := range paths {
		if p == "/new" {
			foundNew = true
			break
		}
	}
	if !foundNew {
		t.Fatal("should have /new after first sync")
	}

	// 设置拉取器失败
	fetcher.mu.Lock()
	fetcher.err = &mockError{"network timeout"}
	fetcher.mu.Unlock()

	// 再次同步应失败但保持缓存
	updated, err := m.SyncFromCloud()
	if err == nil {
		t.Errorf("expected error on failed sync")
	}
	if updated {
		t.Errorf("updated should be false on failure")
	}

	// 缓存仍然有效
	paths2 := m.GetSensitivePaths()
	foundNew2 := false
	for _, p := range paths2 {
		if p == "/new" {
			foundNew2 = true
			break
		}
	}
	if !foundNew2 {
		t.Errorf("cache should be preserved after failed sync")
	}
}

func TestFeatureManager_UpperLimits(t *testing.T) {
	// 生成 600 个敏感路径
	paths := make([]string, 600)
	for i := range paths {
		paths[i] = "/path/" + string(rune('a'+i%26)) + "_" + itoa(i)
	}

	// 生成 250 个 Bot UA
	uas := make([]string, 250)
	for i := range uas {
		uas[i] = "scanner_" + itoa(i)
	}

	resp := &SyncResponse{
		Status: "updated",
		Version: 1,
		Features: map[string][]string{
			"sensitive_path": paths,
			"bot_ua":         uas,
		},
		Count: 850,
	}
	fetcher := &mockFetcher{resp: resp}

	m := newTestManager(fetcher)
	defer m.Stop()

	_, err := m.SyncFromCloud()
	if err != nil {
		t.Fatalf("sync error: %v", err)
	}

	// 敏感路径上限 500
	gotPaths := m.GetSensitivePaths()
	if len(gotPaths) > 500 {
		t.Errorf("sensitive paths count=%d, should be <= 500", len(gotPaths))
	}

	// Bot UA 上限 200
	gotUAs := m.GetBotUserAgents()
	if len(gotUAs) > 200 {
		t.Errorf("bot UA count=%d, should be <= 200", len(gotUAs))
	}
}

func TestFeatureManager_GetAll(t *testing.T) {
	m := newTestManager(nil)
	defer m.Stop()

	all := m.GetAll()
	categories := []string{"sensitive_path", "bot_ua", "static_resource", "dangerous_method"}
	for _, cat := range categories {
		if _, ok := all[cat]; !ok {
			t.Errorf("category %s missing from GetAll", cat)
		}
	}
}

func TestFeatureManager_ConcurrentAccess(t *testing.T) {
	resp := &SyncResponse{
		Status:  "updated",
		Version: 1,
		Features: map[string][]string{"sensitive_path": []string{"/concurrent-test"}},
	}
	fetcher := &mockFetcher{resp: resp}
	m := newTestManager(fetcher)
	defer m.Stop()

	// 先同步一次
	_, _ = m.SyncFromCloud()

	done := make(chan bool, 20)
	for i := 0; i < 10; i++ {
		go func() {
			p := m.GetSensitivePaths()
			if len(p) == 0 {
				t.Errorf("concurrent read got empty paths")
			}
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	// 并发写
	for i := 0; i < 5; i++ {
		go func() {
			m.SyncFromCloud()
			done <- true
		}()
	}
	for i := 0; i < 5; i++ {
		<-done
	}
}

func TestFeatureManager_PeriodicSync(t *testing.T) {
	resp := &SyncResponse{
		Status:  "updated",
		Version: 5,
		Features: map[string][]string{"sensitive_path": []string{"/periodic-test"}},
	}
	fetcher := &mockFetcher{resp: resp}

	m := newTestManager(fetcher)
	m.SetSyncInterval(50 * time.Millisecond)
	defer m.Stop()

	// 启动定期同步（后台 goroutine）
	go m.StartPeriodicSync()

	// 等待同步完成
	time.Sleep(200 * time.Millisecond)

	// 验证已同步
	if m.GetVersion() < 1 {
		t.Errorf("version=%d, should be >= 1 after periodic sync", m.GetVersion())
	}

	paths := m.GetSensitivePaths()
	found := false
	for _, p := range paths {
		if p == "/periodic-test" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("/periodic-test not found after periodic sync, got %v", paths)
	}
}

// TestFeatureManager_SortAndDedupe 验证云端特征的排序与去重。
func TestFeatureManager_SortAndDedupe(t *testing.T) {
	resp := &SyncResponse{
		Status: "updated",
		Version: 1,
		Features: map[string][]string{
			"sensitive_path": []string{"/z-path", "/a-path", "/m-path", "/a-path"},
		},
	}
	fetcher := &mockFetcher{resp: resp}

	m := newTestManager(fetcher)
	defer m.Stop()

	_, err := m.SyncFromCloud()
	if err != nil {
		t.Fatalf("sync error: %v", err)
	}

	paths := m.GetSensitivePaths()
	// 应被排序且去重
	for i := 1; i < len(paths); i++ {
		if paths[i] < paths[i-1] {
			t.Errorf("paths not sorted: %v", paths)
			break
		}
	}
	// /a-path 应只出现一次
	count := 0
	for _, p := range paths {
		if p == "/a-path" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("/a-path appears %d times, should be 1", count)
	}
}

// ---- helpers ----

type mockError struct{ msg string }

func (e *mockError) Error() string { return e.msg }

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	result := make([]byte, 0, 8)
	for i > 0 {
		result = append([]byte{byte('0' + i%10)}, result...)
		i /= 10
	}
	return string(result)
}