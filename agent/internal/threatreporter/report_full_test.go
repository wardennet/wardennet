package threatreporter

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestFeatureStatSerialization 验证 FinalThreatPayload / FeatureStat 的 JSON 序列化行为。
//
// 注意：FinalThreatPayload 和 FeatureStat 是闭源插件内部定义的局部类型，
// 开源端（本仓库）只通过 plugin.Plugin.ReportFull 接口调用闭源插件，
// 闭源插件内部完成：防投毒 + 商业评分 + 聚合去重 + 合规裁剪 → FinalThreatPayload。
// 本测试重新声明同样的结构体，确保开源端 + 闭源端的序列化契约一致。
func TestFeatureStatSerialization(t *testing.T) {
	// 与闭源插件 ReportFull 内部完全一致的结构体
	type FeatureStat struct {
		Dim       string `json:"dim"`
		Value     string `json:"value"`
		HitCount  int    `json:"hit_count"`
		HighCount int    `json:"high_count"`
		LowCount  int    `json:"low_count"`
	}
	type FinalThreatPayload struct {
		AgentID      string        `json:"agent_id"`
		AttackerIP   string        `json:"attacker_ip"`
		Score        int           `json:"score"`
		Timestamp    int64         `json:"timestamp"`
		FeatureStats []FeatureStat `json:"feature_stats,omitempty"`
	}

	// 测试 1: nil FeatureStats 时 omitempty → 不含 feature_stats 字段
	fp1 := FinalThreatPayload{AgentID: "a1", AttackerIP: "1.2.3.4", Score: 80, Timestamp: 1700000000}
	b1, _ := json.Marshal(fp1)
	s1 := string(b1)
	if strings.Contains(s1, "feature_stats") {
		t.Errorf("Case 1 FAIL: nil FeatureStats 应该被 omitempty 省略, got: %s", s1)
	}

	// 测试 2: 有 FeatureStats 时正常序列化
	fp2 := FinalThreatPayload{
		AgentID: "a1", AttackerIP: "1.2.3.4", Score: 80, Timestamp: 1700000000,
		FeatureStats: []FeatureStat{
			{Dim: "sensitive_path", Value: "/.env", HitCount: 10, HighCount: 8, LowCount: 2},
		},
	}
	b2, _ := json.Marshal(fp2)
	s2 := string(b2)
	if !strings.Contains(s2, "feature_stats") {
		t.Errorf("Case 2 FAIL: 有 FeatureStats 应该被序列化, got: %s", s2)
	}

	// 测试 3: FeatureStat 字段不命中 FORBIDDEN_FIELDS（云端 EvidenceService.FORBIDDEN_FIELDS 子集）
	forbidden := map[string]bool{
		"path": true, "uri": true, "method": true, "status": true,
		"user_agent": true, "ua": true, "referer": true,
	}
	for _, fs := range fp2.FeatureStats {
		for _, key := range []string{fs.Dim, fs.Value} {
			if forbidden[strings.ToLower(key)] {
				t.Errorf("Case 3 FAIL: FeatureStat 命中 FORBIDDEN_FIELDS: %s", key)
			}
		}
	}

	// 测试 4: 反序列化正常
	var fp3 FinalThreatPayload
	if err := json.Unmarshal(b2, &fp3); err != nil {
		t.Errorf("Case 4 FAIL: 反序列化失败: %v", err)
	}
	if len(fp3.FeatureStats) != 1 {
		t.Errorf("Case 4 FAIL: FeatureStats count = %d, want 1", len(fp3.FeatureStats))
	}
	if fp3.FeatureStats[0].Dim != "sensitive_path" || fp3.FeatureStats[0].Value != "/.env" {
		t.Errorf("Case 4 FAIL: 反序列化字段不匹配, got dim=%q value=%q",
			fp3.FeatureStats[0].Dim, fp3.FeatureStats[0].Value)
	}
}

// TestFeatureStatEmptyValueValidation 验证空值 FeatureStat 的 JSON 表现。
// 云端 EvidenceService._consume_feature_stats 会跳过 dim 或 value 为空的项。
func TestFeatureStatEmptyValueValidation(t *testing.T) {
	type FeatureStat struct {
		Dim       string `json:"dim"`
		Value     string `json:"value"`
		HitCount  int    `json:"hit_count"`
		HighCount int    `json:"high_count"`
		LowCount  int    `json:"low_count"`
	}
	type FinalThreatPayload struct {
		FeatureStats []FeatureStat `json:"feature_stats,omitempty"`
	}

	// 空 dim 序列化
	fp := FinalThreatPayload{
		FeatureStats: []FeatureStat{{Dim: "", Value: "/.env", HitCount: 5, HighCount: 3, LowCount: 2}},
	}
	b, err := json.Marshal(fp)
	if err != nil {
		t.Fatalf("Marshal 失败: %v", err)
	}
	// 云端应跳过 dim=="" 的 feature_stat — 这是由云端 _consume_feature_stats 保障的，
	// 序列化本身没问题（验证开源端结构体正确）
	t.Logf("empty dim serialized OK: %s", string(b))
}
