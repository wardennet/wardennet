// Package detector - detail.go 提供评分详情回调接口，用于日志记录与统计分析。
// 设计原则：detector 包保持零外部依赖，通过回调将评分详情传出。
package detector

import "fmt"

// ScoreDetail 记录单次打分的各维度详情。
// 供上层日志/统计模块消费，不直接耦合。
type ScoreDetail struct {
	WindowIndex          int   // 0=10s, 1=30s, 2=60s
	WindowSec            int   // 窗口大小（秒）
	EffectiveSensitivity int   // 实际生效的敏感度（1=high, 2=medium, 3=low）
	TotalScore           int   // 本窗口贡献分数

	// 基线置信度（0~1）。低置信度时 QPS 偏离分会打折防止误杀。
	BaselineConfidence float64
	// QPS 分因基线置信度不足被打折（baselineConfidence < 0.3）
	QPSConfidenceMitigated bool
	// QPS 分因纯尖峰无攻击特征被打折（有 DangerousPattern/BotUA/DangerousMethod/FileUpload 之一则不触发）
	// 注意：HeadMethod 不阻止此打折（HEAD 是低权重、非致命的）
	QPSPureSpikeMitigated bool

	// 偏差倍数（相对基线 P95 的偏离倍数，1.0 表示刚好等于 P95）
	QPSDeviation           float64
	Status4xxDeviation     float64
	Status5xxDeviation     float64
	Status404Deviation     float64
	AuthFailDeviation      float64
	SensitivePathDeviation float64
	BotUADeviation         float64
	EmptyRefererDeviation  float64
	HeadMethodDeviation    float64 // HEAD 请求比率偏离基线倍数

	// 各维度得分明细（>0 表示该维度命中并贡献了分数）
	QPSScore                 int
	Status4xxScore           int
	Status5xxScore           int
	AuthFailScore            int
	Status404Score           int
	// v1.4 新增：status anomaly 聚合分数 = Status4xx + Status404 + AuthFail + Status5xx
	// 对应 activeRelDims 里合并后的 1 个 status 维度。
	// 保留各子维度字段用于诊断日志；聚合字段供下游快速消费。
	StatusAnomalyScore       int
	SensitivePathScore       int
	DangerousPatternScore    int
	PathTraversalScore       int // v1.3 新增：路径遍历攻击意图分数
	BotUAScore               int
	EmptyRefererScore        int
	EmptyRefererMitigated    bool  // 空 Referer 是否因无佐证信号而降级（true=已降级 80%）
	EmptyRefererSynergy404   bool  // 空 Referer × 404 协同置信度触发（true=硬上限已放宽至 score_high/2）
	EmptyReferer404Ratio     int   // 空 Referer 触发时的 404 比率（%），用于日志分析
	DangerousMethodScore     int
	HeadMethodScore          int // HEAD 请求低权重分（非致命）
	RealUserBonus            int
	FileUploadScore          int

	// legitimateUserContext 降权标记（"合法用户访问坏掉的后端"场景）
	LegitimateUserContext bool // 本窗口是否判定为 legitimateUserContext
	Status4xxLegMitigated bool // 4xx 分数因 legitimateUserContext 降权 60%
	Status404LegMitigated bool // 404 比率分数因 legitimateUserContext 降权 60%

	// concentrated4xx 降权（"合法 HTTP 客户端调单一坏端点"场景）
	Concentrated4xxMitigated bool
	Distinct4xxPaths         int64

	// 活跃度保护（Activity Guard）标记
	// 活跃扫描器 QPS 不可能低于 0.3（60s 至少 18 个请求）。
	// 低于此阈值时，所有相对基线偏离都是噪音——清零相对维度，
	// 绝对攻击特征打折 50%，总分封顶 ScoreMedium（告警不封禁）。
	InactivityMitigated bool

	// 多维度协同评分标记
	ActiveRelDims  int  // 活跃相对维度数（>0 的相对维度个数）
	SingleDimCapped bool // 单维度封顶生效（只有 1 个相对维度且无绝对特征 → 封顶 ScoreMedium）

	// 原始计数
	TotalReq               int64
	Count4xx               int64
	Count401               int64
	Count5xx               int64
	Count404               int64
	AuthFail               int64
	SensitivePathHit       int64
	DangerousPatternHit    int64
	PathTraversalHit       int64 // v1.3 新增：路径遍历攻击意图命中（clean 前捕获）
	BotUAHit               int64
	EmptyRefererHit        int64
	DangerousMethod        int64
	HeadMethod             int64 // HEAD 请求次数（非致命、低权重）
	StaticResHit           int64
	FileUploadBlockedCount int64
	NormalBrowserHit       int64

	// v1.3 新增：蜜罐路径命中标记（短路路径专用）。
	// 当 Process() 里 IsHoneypotPath 返回 true 时，ScoreDetail.HoneypotHit=true，
	// 用于 DetailLogger 日志输出，让运维能区分"正常评分链路封禁"vs"蜜罐绝对封禁"。
	HoneypotHit bool
}

// DetailLogger 接收评分详情的回调接口。
// blocked 表示多事件确认机制最终判定是否触发封禁（report-only 模式下恒为 false）。
type DetailLogger interface {
	LogDetail(ev Event, details [3]ScoreDetail, finalScore int, isHigh bool, blocked bool)
}

// NopDetailLogger 默认空实现，不记录任何详情。
type NopDetailLogger struct{}

// LogDetail 空实现。
func (NopDetailLogger) LogDetail(_ Event, _ [3]ScoreDetail, _ int, _ bool, _ bool) {}

// ScoreDetailString 将 ScoreDetail 格式化为可读字符串（用于日志）。
func ScoreDetailString(d ScoreDetail) string {
	refTag := ""
	if d.EmptyRefererMitigated {
		refTag = "(mitigated)"
	}
	if d.EmptyRefererSynergy404 {
		refTag = fmt.Sprintf("(404sync=%d%%)", d.EmptyReferer404Ratio)
		if d.EmptyRefererMitigated {
			refTag = "(mitigated,404sync)"
		}
	}
	dangerStr := ""
	if d.DangerousPatternScore > 0 {
		dangerStr = fmt.Sprintf(" danger=%d", d.DangerousPatternScore)
	}
	legTag := ""
	if d.LegitimateUserContext {
		legTag = "(legmit"
		if d.Status4xxLegMitigated {
			legTag += " 4xx"
		}
		if d.Status404LegMitigated {
			legTag += " 404"
		}
		legTag += ")"
	}
	if d.Concentrated4xxMitigated {
		legTag += fmt.Sprintf("(4xxpath=%d)", d.Distinct4xxPaths)
	}
	capTag := ""
	if d.SingleDimCapped {
		capTag = fmt.Sprintf("(1dim-capped,dims=%d)", d.ActiveRelDims)
	} else if d.ActiveRelDims > 0 {
		capTag = fmt.Sprintf("(dims=%d)", d.ActiveRelDims)
	}
	if d.InactivityMitigated {
		capTag += "(inactmit)"
	}

	return fmt.Sprintf(
		"win=%ds sens=%d score=%d%s%s [qps=%.1fx:%d 4xx=%.1fx:%d 5xx=%.1fx:%d fail=%.1fx:%d 404=%.1fx:%d sens=%.1fx:%d%s ua=%.1fx:%d ref=%.1fx:%d%s method=%d head=%d upload=%d bonus=%d] cnt[req=%d 4xx=%d 401=%d 5xx=%d 404=%d fail=%d sens=%d%s ua=%d ref=%d method=%d head=%d static=%d brow=%d 4xxpaths=%d]",
		d.WindowSec, d.EffectiveSensitivity, d.TotalScore, legTag, capTag,
		d.QPSDeviation, d.QPSScore, d.Status4xxDeviation, d.Status4xxScore,
		d.Status5xxDeviation, d.Status5xxScore, d.AuthFailDeviation, d.AuthFailScore,
		d.Status404Deviation, d.Status404Score, d.SensitivePathDeviation, d.SensitivePathScore,
		dangerStr, d.BotUADeviation, d.BotUAScore,
		d.EmptyRefererDeviation, d.EmptyRefererScore, refTag,
		d.DangerousMethodScore, d.HeadMethodScore, d.FileUploadScore, d.RealUserBonus,
		d.TotalReq, d.Count4xx, d.Count401, d.Count5xx, d.Count404, d.AuthFail,
		d.SensitivePathHit, dangerStr, d.BotUAHit, d.EmptyRefererHit, d.DangerousMethod, d.HeadMethod, d.StaticResHit,
		d.NormalBrowserHit, d.Distinct4xxPaths,
	)
}
