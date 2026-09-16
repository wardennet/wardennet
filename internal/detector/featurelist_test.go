package detector

import (
	"reflect"
	"sort"
	"testing"
)

// TestResolveFeatureList_Basic 验证基本三段式合并。
// Builtin + Local + 去重 → 正确结果。
func TestResolveFeatureList_Basic(t *testing.T) {
	t.Parallel()

	builtin := []string{"a", "b", "c"}
	local := FeatureListConfig{
		Local: []string{"c", "d"}, // c 与 builtin 重复，d 新增
	}

	result := ResolveFeatureList(builtin, local, nil)

	// 去重后应为 [a, b, c, d]
	expected := []string{"a", "b", "c", "d"}
	if !reflect.DeepEqual(result.Items, expected) {
		t.Errorf("Items = %v, want %v", result.Items, expected)
	}
}

// TestResolveFeatureList_Excludes 验证排除项功能。
// excludes 中的条目应从最终结果中移除。
func TestResolveFeatureList_Excludes(t *testing.T) {
	t.Parallel()

	builtin := []string{"a", "b", "c", "dangerous"}
	local := FeatureListConfig{
		Excludes: []string{"dangerous"}, // 排除 dangerous
	}

	result := ResolveFeatureList(builtin, local, nil)

	expected := []string{"a", "b", "c"}
	if !reflect.DeepEqual(result.Items, expected) {
		t.Errorf("Items = %v, want %v", result.Items, expected)
	}

	// 验证 Excluded 记录
	if _, ok := result.Excluded["dangerous"]; !ok {
		t.Error("dangerous should be in Excluded map")
	}
}

// TestResolveFeatureList_Cloud 验证云端数据源合并。
func TestResolveFeatureList_Cloud(t *testing.T) {
	t.Parallel()

	builtin := []string{"a", "b"}
	local := FeatureListConfig{
		Local: []string{"c"},
	}
	cloud := []string{"d", "e"}

	result := ResolveFeatureList(builtin, local, cloud)

	expected := []string{"a", "b", "c", "d", "e"}
	if !reflect.DeepEqual(result.Items, expected) {
		t.Errorf("Items = %v, want %v", result.Items, expected)
	}

	// 验证来源标记
	if result.Sources["a"] != "builtin" {
		t.Errorf("source of a = %q, want 'builtin'", result.Sources["a"])
	}
	if result.Sources["c"] != "local" {
		t.Errorf("source of c = %q, want 'local'", result.Sources["c"])
	}
	if result.Sources["d"] != "cloud" {
		t.Errorf("source of d = %q, want 'cloud'", result.Sources["d"])
	}
}

// TestResolveFeatureList_DisableBuiltin 验证禁用内置默认值。
func TestResolveFeatureList_DisableBuiltin(t *testing.T) {
	t.Parallel()

	builtin := []string{"a", "b", "c"}
	local := FeatureListConfig{
		Local:          []string{"d", "e"},
		DisableBuiltin: true,
	}

	result := ResolveFeatureList(builtin, local, nil)

	expected := []string{"d", "e"}
	if !reflect.DeepEqual(result.Items, expected) {
		t.Errorf("Items = %v, want %v", result.Items, expected)
	}
}

// TestResolveFeatureList_DisableCloud 验证禁用云端拉取。
func TestResolveFeatureList_DisableCloud(t *testing.T) {
	t.Parallel()

	builtin := []string{"a"}
	local := FeatureListConfig{
		DisableCloud: true,
	}
	cloud := []string{"b"}

	result := ResolveFeatureList(builtin, local, cloud)

	// 云端被禁用，b 不应出现
	expected := []string{"a"}
	if !reflect.DeepEqual(result.Items, expected) {
		t.Errorf("Items = %v, want %v", result.Items, expected)
	}
}

// TestResolveFeatureList_ExcludeOverridesLocal 验证排除项可以排除本地新增的条目。
func TestResolveFeatureList_ExcludeOverridesLocal(t *testing.T) {
	t.Parallel()

	builtin := []string{"a"}
	local := FeatureListConfig{
		Local:    []string{"b"},
		Excludes: []string{"b"}, // 排除本地新增的 b
	}

	result := ResolveFeatureList(builtin, local, nil)

	// b 被排除
	expected := []string{"a"}
	if !reflect.DeepEqual(result.Items, expected) {
		t.Errorf("Items = %v, want %v", result.Items, expected)
	}
}

// TestResolveFeatureList_Dedup 验证去重逻辑。
// Builtin + Cloud + Local 中重复的条目只出现一次。
func TestResolveFeatureList_Dedup(t *testing.T) {
	t.Parallel()

	builtin := []string{"x"}
	local := FeatureListConfig{
		Local: []string{"x", "y"},
	}
	cloud := []string{"x", "z"}

	result := ResolveFeatureList(builtin, local, cloud)

	expected := []string{"x", "y", "z"}
	if !reflect.DeepEqual(result.Items, expected) {
		t.Errorf("Items = %v, want %v", result.Items, expected)
	}

	// x 应该有多个来源标记
	if result.Sources["x"] != "builtin+cloud+local" {
		t.Errorf("source of x = %q, want 'builtin+cloud+local'", result.Sources["x"])
	}
}

// TestResolveFeatureList_Empty 验证空输入的边界情况。
func TestResolveFeatureList_Empty(t *testing.T) {
	t.Parallel()

	result := ResolveFeatureList(nil, FeatureListConfig{}, nil)
	if len(result.Items) != 0 {
		t.Errorf("Items should be empty, got %v", result.Items)
	}
}

// TestResolveFeatureList_ExcludeNonExistent 验证排除不存在的条目不报错。
func TestResolveFeatureList_ExcludeNonExistent(t *testing.T) {
	t.Parallel()

	builtin := []string{"a"}
	local := FeatureListConfig{
		Excludes: []string{"nonexistent"},
	}

	result := ResolveFeatureList(builtin, local, nil)

	// 排除不存在的条目应无影响
	expected := []string{"a"}
	if !reflect.DeepEqual(result.Items, expected) {
		t.Errorf("Items = %v, want %v", result.Items, expected)
	}
}

// TestResolveFeatureList_Ordering 验证结果排序。
func TestResolveFeatureList_Ordering(t *testing.T) {
	t.Parallel()

	builtin := []string{"z", "a"}
	local := FeatureListConfig{
		Local: []string{"m", "b"},
	}

	result := ResolveFeatureList(builtin, local, nil)

	// 结果应按字母排序
	expected := []string{"a", "b", "m", "z"}
	if !reflect.DeepEqual(result.Items, expected) {
		t.Errorf("Items = %v, want %v (should be sorted)", result.Items, expected)
	}

	// 再次排序验证幂等
	sort.Strings(result.Items)
	if !reflect.DeepEqual(result.Items, expected) {
		t.Error("result should already be sorted")
	}
}

// TestDefaultKnownHTTPClients 验证默认值不为空且可复制。
func TestDefaultKnownHTTPClients(t *testing.T) {
	t.Parallel()
	defaults := DefaultKnownHTTPClients()
	if len(defaults) == 0 {
		t.Error("DefaultKnownHTTPClients() should return non-empty list")
	}
	// 验证返回的是副本而非引用
	defaults[0] = "modified"
	defaults2 := DefaultKnownHTTPClients()
	if defaults2[0] == "modified" {
		t.Error("DefaultKnownHTTPClients() should return a copy, not a reference")
	}
}

// TestDefaultDangerousPatterns 验证默认危险模式不为空。
func TestDefaultDangerousPatterns(t *testing.T) {
	t.Parallel()
	defaults := DefaultDangerousPatterns()
	if len(defaults) == 0 {
		t.Error("DefaultDangerousPatterns() should return non-empty list")
	}
}

// TestResolveAllFeatures 验证一次性合并所有三类特征列表。
func TestResolveAllFeatures(t *testing.T) {
	t.Parallel()

	cfgs := FeatureConfigs{
		KnownHTTPClients: FeatureListConfig{
			Local:    []string{"custom-client"},
			Excludes: []string{"okhttp"},
		},
		SensitivePaths: FeatureListConfig{
			Local: []string{"custom-sensitive"},
		},
		DangerousPatterns: FeatureListConfig{
			Local: []string{"custom-pattern"},
		},
	}

	result := ResolveAllFeatures(
		cfgs,
		DefaultKnownHTTPClients(),
		DefaultSensitivePaths(),
		DefaultDangerousPatterns(),
		NoopFeatureFetcher{},
		"test-tenant",
	)

	// KnownHTTPClients 应包含 custom-client 但排除 okhttp
	foundCustom := false
	for _, item := range result.KnownHTTPClients.Items {
		if item == "custom-client" {
			foundCustom = true
		}
		if item == "okhttp" {
			t.Error("okhttp should be excluded from KnownHTTPClients")
		}
	}
	if !foundCustom {
		t.Error("custom-client should be in KnownHTTPClients")
	}

	// SensitivePaths 应包含 custom-sensitive
	foundCustomSensitive := false
	for _, item := range result.SensitivePaths.Items {
		if item == "custom-sensitive" {
			foundCustomSensitive = true
		}
	}
	if !foundCustomSensitive {
		t.Error("custom-sensitive should be in SensitivePaths")
	}

	// DangerousPatterns 应包含 custom-pattern
	foundCustomPattern := false
	for _, item := range result.DangerousPatterns.Items {
		if item == "custom-pattern" {
			foundCustomPattern = true
		}
	}
	if !foundCustomPattern {
		t.Error("custom-pattern should be in DangerousPatterns")
	}
}

// TestNoopFeatureFetcher 验证空实现返回 nil, nil。
func TestNoopFeatureFetcher(t *testing.T) {
	t.Parallel()
	fetcher := NoopFeatureFetcher{}
	result, err := fetcher.FetchLatest("tenant-1", 0)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}
