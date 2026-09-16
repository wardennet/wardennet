package cloudsync

import (
	"testing"

	"github.com/wardennet/agent/internal/plugin"
)

// TestCloudConfidenceMultiplier 直接测试 VoteCount → 置信度系数的分层逻辑
func TestCloudConfidenceMultiplier(t *testing.T) {
	tests := []struct {
		vote int
		want float64
	}{
		{50, 1.00},
		{20, 1.00},
		{19, 0.90},
		{10, 0.90},
		{9, 0.75},
		{5, 0.75},
		{4, 0.60},
		{3, 0.60},
		{2, cloudConfDefaultMultiplier},
		{1, 0.40},
		{0, cloudConfDefaultMultiplier},
		{-1, cloudConfDefaultMultiplier},
	}
	for _, tc := range tests {
		got := cloudConfidenceMultiplier(tc.vote)
		if got != tc.want {
			t.Errorf("cloudConfidenceMultiplier(vote=%d) = %.2f, want %.2f",
				tc.vote, got, tc.want)
		}
	}
}

// TestConsensusFastPath_Triggers 联防快速通道核心正向测试
// global 池 + VoteCount ≥ 20 + Score ≥ 90 → 直接 Block，FastPath=true
func TestConsensusFastPath_Triggers(t *testing.T) {
	tests := []struct {
		name      string
		ts        plugin.ThreatScore
		local     LocalScoreResult
		fastPath  bool
		wantBlock bool
	}{
		// === 刚好触线 ===
		{"global_vote20_score90",
			plugin.ThreatScore{IP: "1", Score: 90, VoteCount: CONSENSUS_MIN_VOTES, Source: "global"},
			LocalScoreResult{Freq: 50, Detector: 50}, true, true},

		// === 最典型联防场景：扫描器还没扫到我 ===
		{"global_vote50_score100_never_seen",
			plugin.ThreatScore{IP: "2", Score: 100, VoteCount: 50, Source: "global"},
			LocalScoreResult{Freq: 50, Detector: 50}, true, true},

		// === 阈值以下 ===
		{"global_vote19_score100",  // VoteCount 差 1 不够
			plugin.ThreatScore{IP: "3", Score: 100, VoteCount: 19, Source: "global"},
			LocalScoreResult{Freq: 50, Detector: 50}, false, false}, // 走加权：eff=100*0.9=90*0.4+30=36+30=66 → ALERT

		{"global_vote20_score89",  // Score 差 1 不够
			plugin.ThreatScore{IP: "4", Score: 89, VoteCount: 20, Source: "global"},
			LocalScoreResult{Freq: 50, Detector: 50}, false, false}, // 走加权

		// === private 池永远不能触发快速通道 ===
		{"private_vote100_score100",
			plugin.ThreatScore{IP: "5", Score: 100, VoteCount: 100, Source: "private"},
			LocalScoreResult{Freq: 50, Detector: 50}, false, false},

		// === Source 为空 ===
		{"unknown_vote100_score100",
			plugin.ThreatScore{IP: "6", Score: 100, VoteCount: 100, Source: ""},
			LocalScoreResult{Freq: 50, Detector: 50}, false, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := Decide(tc.ts, tc.local.Freq, tc.local.Detector)

			if d.FastPath != tc.fastPath {
				t.Errorf("FastPath=%v want %v", d.FastPath, tc.fastPath)
			}
			if tc.wantBlock && d.Action != "block" {
				t.Errorf("want BLOCK, got %s (reason=%s)", d.Action, d.Reason)
			}
			if tc.fastPath {
				// FastPath 触发时 Reason 应该含 "consensus fast path"
				if d.Reason == "" {
					t.Error("FastPath=true but Reason is empty")
				}
			}
		})
	}
}

// TestConsensusFastPath_ViaShould 直接测试 shouldTriggerConsensusFastPath 的安全边界
func TestConsensusFastPath_ViaShould(t *testing.T) {
	// 正向
	if !shouldTriggerConsensusFastPath(plugin.ThreatScore{IP: "x", Score: 90, VoteCount: 20, Source: "global"}) {
		t.Error("global+vote20+score90 should trigger fast path")
	}

	// 反向：全边界
	cases := []plugin.ThreatScore{
		{IP: "a", Score: 89, VoteCount: 20, Source: "global"},  // score 差 1
		{IP: "b", Score: 90, VoteCount: 19, Source: "global"}, // vote 差 1
		{IP: "c", Score: 100, VoteCount: 20, Source: "private"}, // private 池
		{IP: "d", Score: 100, VoteCount: 20, Source: ""},       // source 空
		{IP: "e", Score: 100, VoteCount: 1, Source: "global"},  // 单租户
	}
	for _, tc := range cases {
		if shouldTriggerConsensusFastPath(tc) {
			t.Errorf("should NOT trigger fast path for %+v", tc)
		}
	}
}

// TestDecide_VoteCountImpact 验证默认加权路径下 VoteCount 正确影响评分
// 注意：所有 VoteCount ≥ 20 + Score ≥ 90 的 case 会直接走快速通道 BLOCK
// 所以这里测试的是**快速通道不会误触发**的边界场景
func TestDecide_VoteCountImpact(t *testing.T) {
	local50_50 := LocalScoreResult{Freq: 50, Detector: 50}

	tests := []struct {
		name       string
		ts         plugin.ThreatScore
		local      LocalScoreResult
		wantFinal  float64
		wantAction string
	}{
		// === vote=19 + score=100 → multiplier=0.9（走加权，不是快速通道）===
		{"global_vote19_score100_defaults",
			plugin.ThreatScore{IP: "1.1.1.1", Score: 100, VoteCount: 19, Source: "global"},
			local50_50, 66, "alert"}, // eff=90 → 90*0.4+15+15=66

		// === vote=50 + score=89（score 差 1 不够触发快速通道）===
		{"global_vote50_score89_defaults",
			plugin.ThreatScore{IP: "2.2.2.2", Score: 89, VoteCount: 50, Source: "global"},
			local50_50, 65.6, "alert"}, // eff=89 → 89*0.4+30=65.6

		// === 中等共识 vote=10 ===
		{"global_vote10_score100_defaults",
			plugin.ThreatScore{IP: "4.4.4.4", Score: 100, VoteCount: 10, Source: "global"},
			local50_50, 66, "alert"}, // eff=90 → 同上

		// === 单租户上报 VoteCount=1 → multiplier=0.40 ===
		// 核心安全测试：单租户误报 cloud=100 应该被 Agent 否决
		{"global_vote1_score100_defaults",
			plugin.ThreatScore{IP: "7.7.7.7", Score: 100, VoteCount: 1, Source: "global"},
			local50_50, 46, "ignore"}, // eff=40 → 16+30=46 → IGNORE ✅

		// === private 池：VoteCount 被忽略，固定 multiplier=0.7 ===
		{"private_vote100_score100_defaults",
			plugin.ThreatScore{IP: "8.8.8.8", Score: 100, VoteCount: 100, Source: "private"},
			local50_50, 58, "alert"}, // eff=70 → 28+30=58

		// === vote=20 + score=100 + 本地强信号（先快速通道触发，不受本地影响）===
		{"global_vote20_score100_strong_local",
			plugin.ThreatScore{IP: "2.2.2.2", Score: 100, VoteCount: 20, Source: "global"},
			LocalScoreResult{Freq: 80, Detector: 80}, 80, "block"}, // FastPath 触发，FinalScore=80 硬标记

		// === 两端都低 ===
		{"both_low",
			plugin.ThreatScore{IP: "10.10.10.10", Score: 20, VoteCount: 5, Source: "global"},
			local50_50, 36, "ignore"}, // eff=20*0.75=15 → 15*0.4+30=36 < 50 → IGNORE
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := Decide(tc.ts, tc.local.Freq, tc.local.Detector)

			if d.FinalScore < tc.wantFinal-0.5 || d.FinalScore > tc.wantFinal+0.5 {
				t.Errorf("final=%.1f want %.1f (effCloud=%.0f, conf=%.2f)",
					d.FinalScore, tc.wantFinal, d.EffectiveCloud, d.CloudConfidence)
			}
			if d.Action != tc.wantAction {
				t.Errorf("action=%q want %q (cloud=%.0f vote=%d local=%.0f/%.0f)",
					d.Action, tc.wantAction, tc.ts.Score, tc.ts.VoteCount,
					tc.local.Freq, tc.local.Detector)
			}
		})
	}
}

// TestDecide_CloudVetoBySingleTenant 核心安全测试：
// 单租户 VoteCount=1 上报 cloud=100 但本地没见过 → IGNORE
// 防止单租户误报/投毒扩散
func TestDecide_CloudVetoBySingleTenant(t *testing.T) {
	d := Decide(
		plugin.ThreatScore{IP: "x.x.x.x", Score: 100, VoteCount: 1, Source: "global"},
		50, 50,
	)
	if d.Action == "block" {
		t.Fatalf("FAIL: single-tenant cloud=100 should NOT block — Agent vetoes! got BLOCK")
	}
	if d.FinalScore > 50 {
		t.Errorf("single-tenant cloud=100 final_score should be ~46, got %.1f", d.FinalScore)
	}
	t.Logf("PASS: single-tenant cloud=100 vote=1 → conf=%.2f effCloud=%.0f final=%.1f %s (Agent correctly vetoes!)",
		d.CloudConfidence, d.EffectiveCloud, d.FinalScore, d.Action)
}

// TestDecide_ConsensusCanIndependentBlock 联防的核心价值验证：
// 20+ 租户共识 + score=90 → **直接 Block**，不管本地有没有见过
// 这才是联防首发阻断该有的样子
func TestDecide_ConsensusCanIndependentBlock(t *testing.T) {
	d := Decide(
		plugin.ThreatScore{IP: "x.x.x.x", Score: 100, VoteCount: CONSENSUS_MIN_VOTES, Source: "global"},
		50, 50, // 本地完全没见过！
	)
	if d.Action != "block" {
		t.Fatalf("FAIL: cloud=100+vote=20 should BLOCK via consensus fast path! got %s (final=%.1f)",
			d.Action, d.FinalScore)
	}
	if !d.FastPath {
		t.Error("expected FastPath=true")
	}
	t.Logf("PASS: cloud=100 vote=20 local=50/50 → FAST_PATH BLOCK (consensus triggers)")
}

// TestDecide_DecisionFields 验证 Decision 结构体各字段正确赋值
func TestDecide_DecisionFields(t *testing.T) {
	d := Decide(
		plugin.ThreatScore{IP: "a.b.c.d", Score: 75, VoteCount: 12, Source: "global"},
		40, 60,
	)

	if d.IP != "a.b.c.d" {
		t.Errorf("IP = %q, want %q", d.IP, "a.b.c.d")
	}
	if d.CloudScore != 75 {
		t.Errorf("CloudScore = %v, want 75", d.CloudScore)
	}
	if d.VoteCount != 12 {
		t.Errorf("VoteCount = %v, want 12", d.VoteCount)
	}
	if d.CloudConfidence != 0.90 {
		t.Errorf("CloudConfidence = %v, want 0.90 (vote=12 >=10)", d.CloudConfidence)
	}
	wantEff := 75 * 0.90 // 67.5
	if d.EffectiveCloud < wantEff-0.5 || d.EffectiveCloud > wantEff+0.5 {
		t.Errorf("EffectiveCloud = %.1f, want ~%.1f", d.EffectiveCloud, wantEff)
	}
	if d.LocalFreqScore != 40 {
		t.Errorf("LocalFreqScore = %v, want 40", d.LocalFreqScore)
	}
	if d.DetectorScore != 60 {
		t.Errorf("DetectorScore = %v, want 60", d.DetectorScore)
	}
	// final = 67.5*0.4 + 40*0.3 + 60*0.3 = 27 + 12 + 18 = 57
	if d.FinalScore < 56.5 || d.FinalScore > 57.5 {
		t.Errorf("FinalScore = %.1f, want ~57", d.FinalScore)
	}
}

// TestDecideAll_Batch 批量决策分类
func TestDecideAll_Batch(t *testing.T) {
	scores := []plugin.ThreatScore{
		{IP: "1.1.1.1", Score: 100},                             // VoteCount=0 → conf=0.7 → eff=70 → 28+30=58 → alert
		{IP: "2.2.2.2", Score: 50},                              // eff=35 → 14+30=44 → ignore
		{IP: "3.3.3.3", Score: 100, VoteCount: 20, Source: "global"}, // 快速通道 BLOCK
	}
	blocks, alerts := DecideAll(scores, nil)

	if len(blocks) != 1 {
		t.Errorf("expected 1 block (fast path), got %d", len(blocks))
	}
	if len(alerts) != 1 {
		t.Errorf("expected 1 alert, got %d", len(alerts))
	}
}

// TestDecideAll_WithLocalScoreFn 自定义本地评分回调
func TestDecideAll_WithLocalScoreFn(t *testing.T) {
	scores := []plugin.ThreatScore{
		{IP: "1.1.1.1", Score: 100, VoteCount: 50, Source: "global"}, // FastPath BLOCK
		{IP: "2.2.2.2", Score: 100, VoteCount: 50, Source: "global"}, // FastPath BLOCK
		// 只有 Score=89（不够快速通道门槛）+ vote=50（≥20 但 score 不够）
		{IP: "3.3.3.3", Score: 89, VoteCount: 50, Source: "global"}, // 走加权
	}

	localFn := func(ip string) LocalScoreResult {
		switch ip {
		case "3.3.3.3":
			return LocalScoreResult{Freq: 50, Detector: 50} // eff=89 → 89*0.4+30=65.6 → ALERT
		default:
			return LocalScoreResult{Freq: 50, Detector: 50} // 默认
		}
	}

	blocks, alerts := DecideAll(scores, localFn)

	if len(blocks) != 2 {
		t.Errorf("expected 2 blocks (fast path), got %d", len(blocks))
	}
	if len(alerts) != 1 {
		t.Errorf("expected 1 alert, got %d", len(alerts))
	}
}

// TestClamp0100 边界值保护
func TestClamp0100(t *testing.T) {
	cases := map[float64]float64{
		-10: 0,
		0:   0,
		50:  50,
		100: 100,
		150: 100,
	}
	for in, want := range cases {
		got := clamp0100(in)
		if got != want {
			t.Errorf("clamp(%.0f) = %.0f, want %.0f", in, got, want)
		}
	}
}
