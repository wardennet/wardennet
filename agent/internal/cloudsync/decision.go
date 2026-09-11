// Package cloudsync — 本地威胁决策引擎。
//
// 核心变更（V2 安全防御层）：
// 云端只下发威胁评分 threat_scoring（0-100）+ VoteCount（独立投票租户数），
// **不**直接下发拉黑指令。Agent 结合云端评分的**置信度**和本地 Detector 评分综合决策，
// 最终决策权在 Agent，杜绝云端被投毒导致大规模误杀真实用户。
//
// ┌── 两层决策架构 ──────────────────────────────────────────────────┐
// │ 层 1: 默认加权（普通场景）                                       │
// │                                                                 │
// │   effective_cloud = cloud_score × cloud_confidence(VoteCount)   │
// │   composite = effective_cloud × W_cloud                         │
// │            + local_freq_score × W_local                         │
// │            + detector_score × W_detector                       │
// │                                                                 │
// │   权重默认 0.4 / 0.3 / 0.3，可云端热更（含安全校验）。          │
// │   VoteCount 分层提升/降低云端分在公式里的有效占比。             │
// │                                                                 │
// │ 层 2: 集群共识快速通道（联防首发阻断核心价值）                 │
// │                                                                 │
// │   当且仅当同时满足以下所有条件时，**跳过硬加权直接 Block**：      │
// │     - Source == "global"（仅全局池，private 池不触发）           │
// │     - VoteCount >= CONSENSUS_MIN_VOTES（硬编码，不可热更）       │
// │     - Score    >= CONSENSUS_MIN_SCORE （硬编码，不可热更）       │
// │     - 本地白名单未命中（Manager.ApplyCloud 负责过滤）            │
// │                                                                 │
// │   设计意图：当 20+ 独立租户都把同一个 IP 打成 90+ 高危分时，     │
// │   这已不是"单云端指令"，而是"跨租户共识"——等同于 B 自己也      │
// │   观察到了威胁（云端替 B 提前发现）。直接 Block 实现联防首发     │
// │   阻断，不让扫描器在 B 的 Web 服务上游造成伤害。                │
// │                                                                 │
// │   安全：两个阈值硬编码在源码中，**不可热更**——防止云端把阈值     │
// │   降到 VoteCount=1 然后开始投毒扩散。private 池永远不能触发     │
// │   快速通道，因为它的 VoteCount 不是跨租户共识。                │
// └─────────────────────────────────────────────────────────────────┘
//
// VoteCount 分层（仅 Source=global 时生效；private 池 VoteCount 语义不同，固定 0.7）：
//
//	  vote ≥ 20  → multiplier = 1.00  // 20+ 租户共识 → 完整信任 + 可能触发快速通道
//	  vote ≥ 10  → multiplier = 0.90  // 强共识
//	  vote ≥ 5   → multiplier = 0.75  // 中等共识
//	  vote ≥ 3   → multiplier = 0.60  // 弱共识
//	  vote = 1   → multiplier = 0.40  // 单租户上报 → 高度怀疑，防止误报扩散
//	  其他/未知  → multiplier = 0.70  // 保守默认
//
// 决策阈值（硬编码，不可变）：
//   ≥ 80 → 拉黑（写 ipset blacklist）
//   ≥ 50 → 告警（仅记录日志，不拉黑）
//   < 50 → 忽略（评分过低，不做任何操作）

package cloudsync

import (
	"sync"

	"github.com/wardennet/agent/internal/plugin"
)

// 决策阈值 & 联防快速通道门槛 —— 全部硬编码，**不可热更**。
// 安全设计：
//   权重可以云端热更（含 sum ∈ [0.5, 1.5] 安全校验），
//   但阈值和联防门槛写死在源码里——一旦云端能改这些，
//   就等于给云端开了"绕过 Agent 决策、直接大规模封禁"的后门。
const (
	decisionBlockThreshold = 80.0 // ≥ 此值 → 拉黑
	decisionAlertThreshold = 50.0 // ≥ 此值 → 告警（不拉黑）

	// cloudConfDefaultMultiplier VoteCount 未知时的保守置信度系数
	cloudConfDefaultMultiplier = 0.70

	// CONSENSUS_MIN_VOTES 触发联防快速通道的最低独立租户数
	// 20 个独立租户 = 20 个完全不同的业务场景
	// 投毒需要同时黑掉 20 个付费租户的 Agent → 成本极高
	CONSENSUS_MIN_VOTES = 20

	// CONSENSUS_MIN_SCORE 触发联防快速通道的最低云端原始评分
	// 90 分确保这个 IP 在全局池里是"极高威胁"，不是边缘分
	CONSENSUS_MIN_SCORE = 90.0
)

// 默认权重（三项之和 = 1.0）
var defaultWeights = plugin.DecisionWeightsConfig{
	Cloud:    0.4,
	Local:    0.3,
	Detector: 0.3,
}

// 当前生效的权重（可被云端热更）。
// 用 sync.RWMutex 保护——决策是高频读、权重热更是低频写。
var (
	weightsMu      sync.RWMutex
	currentWeights = defaultWeights
)

// SetDecisionWeights 热更决策引擎权重。
// 安全校验：三项之和必须在 [0.5, 1.5] 范围内，否则返回 false 不应用。
// 云端紧急时刻可调用此方法把 cloud 权重提到 0.9（"核按钮"）。
// 注意：只能改权重，不能改决策阈值和联防门槛（那两个是常量，硬编码）。
func SetDecisionWeights(w *plugin.DecisionWeightsConfig) bool {
	if w == nil {
		return false
	}
	if w.Cloud <= 0 || w.Local <= 0 || w.Detector <= 0 {
		return false
	}
	sum := w.Cloud + w.Local + w.Detector
	if sum < 0.5 || sum > 1.5 {
		return false
	}
	weightsMu.Lock()
	currentWeights = *w
	weightsMu.Unlock()
	return true
}

// ResetDecisionWeights 重置为默认值。
func ResetDecisionWeights() {
	weightsMu.Lock()
	currentWeights = defaultWeights
	weightsMu.Unlock()
}

func getWeights() plugin.DecisionWeightsConfig {
	weightsMu.RLock()
	w := currentWeights
	weightsMu.RUnlock()
	return w
}

// cloudConfidenceMultiplier 根据 VoteCount 计算云端信誉置信度系数。
// VoteCount 越高（越多租户独立报告同一 IP），云端 score 越可信。
// 仅 Source=global（全局池）时用 VoteCount；private 池返回保守默认值。
//
// 这个函数把云端的"信誉强度"翻译成"Agent 应该多相信这个 score"。
// 关键安全设计：单租户上报 VoteCount=1 时 multiplier=0.40——
// 防止单租户误报/投毒通过全局池扩散成误杀。
func cloudConfidenceMultiplier(voteCount int) float64 {
	switch {
	case voteCount >= CONSENSUS_MIN_VOTES:
		return 1.00
	case voteCount >= 10:
		return 0.90
	case voteCount >= 5:
		return 0.75
	case voteCount >= 3:
		return 0.60
	case voteCount == 1:
		return 0.40
	default:
		return cloudConfDefaultMultiplier
	}
}

// shouldTriggerConsensusFastPath 判断是否应该走联防快速通道。
// 只有 Source="global" + VoteCount ≥ CONSENSUS_MIN_VOTES + Score ≥ CONSENSUS_MIN_SCORE
// 三个条件同时满足时才返回 true。所有条件硬编码，不可热更。
//
// 为什么 private 池永远不能触发？因为 private 池的 VoteCount 是
// "该租户自己上报这个 IP 的次数"，不是跨租户共识——
// 一个租户自己反复上报某个 IP 50 次，投毒成本为零。
func shouldTriggerConsensusFastPath(ts plugin.ThreatScore) bool {
	if ts.Source != "global" {
		return false
	}
	if ts.VoteCount < CONSENSUS_MIN_VOTES {
		return false
	}
	if ts.Score < CONSENSUS_MIN_SCORE {
		return false
	}
	return true
}

// Decision 单次决策结果。
type Decision struct {
	IP              string
	CloudScore      float64 // 原始云端威胁评分（0-100）
	VoteCount       int     // 参与打分的独立租户数（global 池有值）
	CloudConfidence float64 // 云端信誉置信度系数（由 VoteCount 推导）
	EffectiveCloud  float64 // 置信度加权后的有效云端分 = CloudScore × CloudConfidence
	LocalFreqScore  float64 // 本地频率偏离评分（0-100）
	DetectorScore   float64 // Detector 综合检测评分（0-100）
	FinalScore      float64 // 综合评分（或快速通道触发时等于 decisionBlockThreshold）
	FastPath        bool    // true = 走了集群共识快速通道（跳过硬加权直接 Block）
	Action          string  // block / alert / ignore
	Reason          string  // 简短说明（FastPath=true 时会标注 "consensus fast path"）
}

// LocalScoreResult 本地评分回调返回值——两个独立信号源。
// 默认值语义：Freq=50 / Detector=50 表示"无本地检测信号"。
type LocalScoreResult struct {
	Freq     float64 // 本地频率/流量偏离评分
	Detector float64 // Detector 综合检测评分
}

// Decide 对单条威胁评分做综合决策。
//
// 决策流程：
//  1. 如果满足联防快速通道条件（global + VoteCount≥20 + Score≥90）→ 直接 Block
//  2. 否则走默认加权公式 → 根据 final 分到 block/alert/ignore
//
// 本地未见过 IP 时传 50/50（中性占位，让云端分数自己说话）。
// 云端 Score 先过 cloudConfidenceMultiplier(VoteCount) 得到有效分再参与加权。
func Decide(ts plugin.ThreatScore, localFreq float64, detector float64) Decision {
	cloudRaw := clamp0100(ts.Score)
	freq := clamp0100(localFreq)
	det := clamp0100(detector)

	// VoteCount 仅对 global 池有意义——private 池 VoteCount 不是跨租户共识信号。
	var confMult float64
	if ts.Source == "global" && ts.VoteCount > 0 {
		confMult = cloudConfidenceMultiplier(ts.VoteCount)
	} else {
		confMult = cloudConfDefaultMultiplier
	}
	effectiveCloud := clamp0100(cloudRaw * confMult)

	// === 层 2: 集群共识快速通道（联防首发阻断核心）===
	if shouldTriggerConsensusFastPath(ts) {
		return Decision{
			IP:              ts.IP,
			CloudScore:      cloudRaw,
			VoteCount:       ts.VoteCount,
			CloudConfidence: confMult,
			EffectiveCloud:  effectiveCloud,
			LocalFreqScore:  freq,
			DetectorScore:    det,
			FinalScore:      decisionBlockThreshold, // 标记为 BLOCK 门槛
			FastPath:        true,
			Action:          "block",
			Reason:          "consensus fast path: " +
				ts.Source + " vote=" + itoa(ts.VoteCount) +
				" score=" + itoa(int(cloudRaw)),
		}
	}

	// === 层 1: 默认加权 ===
	w := getWeights()
	final := effectiveCloud*w.Cloud + freq*w.Local + det*w.Detector
	final = clamp0100(final)

	action := "ignore"
	reason := ""
	switch {
	case final >= decisionBlockThreshold:
		action = "block"
		reason = "composite score exceeds block threshold"
	case final >= decisionAlertThreshold:
		action = "alert"
		reason = "composite score exceeds alert threshold"
	default:
		action = "ignore"
		reason = "composite score below alert threshold"
	}

	return Decision{
		IP:              ts.IP,
		CloudScore:      cloudRaw,
		VoteCount:       ts.VoteCount,
		CloudConfidence: confMult,
		EffectiveCloud:  effectiveCloud,
		LocalFreqScore:  freq,
		DetectorScore:    det,
		FinalScore:      final,
		FastPath:        false,
		Action:          action,
		Reason:          reason,
	}
}

// DecideAll 批量决策，返回需拉黑和需告警的分类结果。
// 参数 scoreFn 为每个 IP 获取本地评分的回调；nil 时 Freq/Detector 全部用 50（无本地信号）。
func DecideAll(scores []plugin.ThreatScore, scoreFn func(ip string) LocalScoreResult) (blocks []Decision, alerts []Decision) {
	for _, ts := range scores {
		var freq, det float64 = 50, 50 // 无本地信号默认中等
		if scoreFn != nil {
			r := scoreFn(ts.IP)
			freq, det = r.Freq, r.Detector
		}
		d := Decide(ts, freq, det)
		switch d.Action {
		case "block":
			blocks = append(blocks, d)
		case "alert":
			alerts = append(alerts, d)
		}
	}
	return
}

// itoa 小型整数转字符串（仅用于 Decide.Reason 字段，避免引入 strconv 依赖）。
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	buf := [20]byte{}
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// clamp0100 将值限制在 [0, 100] 范围。
func clamp0100(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}
