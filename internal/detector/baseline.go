// Package detector - baseline.go 实现 WardenNet Agent 的基线自学习评分引擎。
// 基线引擎持续观察所有活跃 IP 的流量特征分布（QPS、4xx 比率、Bot UA 比率等），
// 计算 P50/P95/P99 分位数作为"正常范围"，让评分引擎基于"偏离基线程度"而非固定阈值进行评分。
// 支持指数衰减追踪长期趋势、冷启动默认值保守策略、攻击者污染防护（极端值不纳入统计）、
// 基线置信度（confidence）保护：低置信度时评分引擎自动打折避免误杀。
package detector

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

// 硬保底阈值：基线 QPS P95 永远不低于 MIN_BASELINE_QPS。
// 即使 Preload 期间恰好是凌晨低峰，正常用户的 2-5 req/s 也能被正确识别。
// 攻击流量想触发封禁，实际 QPS 必须 >= MIN_BASELINE_QPS × sensitivity_threshold。
//
// 示例：MIN_BASELINE_QPS=1.0, sensitivity=medium(threshold=5)
//   正常用户 3 req/s → 偏离 3x < 5x → 不触发
//   攻击流量 8 req/s → 偏离 8x > 5x → 触发
//   硬保底保证了基线不会因为低峰被压到 0.1 req/s 导致正常 3 req/s 误判为 30x 偏离
const (
	// QPS 硬保底（req/s）：即使 Preload 期间恰好是凌晨低峰，正常用户的 2-5 req/s 也能被正确识别。
	// 攻击流量想触发封禁，实际 QPS 必须 >= MIN_BASELINE_QPS × sensitivity_threshold。
	//   正常用户 3 req/s → 偏离 3x < 5x → 不触发
	//   攻击流量 8 req/s → 偏离 8x > 5x → 触发
	MIN_BASELINE_QPS = 1.0

	// 比率型维度硬保底（Rate4xx / RateBotUA / RateSensPath 等）。
	// Preload 用凌晨低峰数据时，很多 rate 维度的 P95 会是极小正数（非零），
	// deviation 计算 currentRate / p.P95 时会爆炸到 1e200 量级。
	// 0.001 = 0.1%：任何正常网站哪怕在深夜，也应该有 >= 0.1% 的 4xx / BotUA / 空 Referer。
	// 低于此值说明 Preload 数据太安静，不可信，需要提到一个合理的"地板值"。
	MIN_BASELINE_RATE_P95 = 0.001

	// deviation 上限：任何偏离倍数超过此值都 cap 掉。
	// 数学上 deviation = current / baseline，baseline 接近 0 时会得到天文数字。
	// 但评分引擎的 deviationToScore 已经用 excess*10 cap 到 100，再高没有实际意义。
	// 设 1000 足够大（1000x 偏离 → score = (1000 - threshold) * 10 ≈ 100，早已封顶），
	// 同时能挡掉 float64 溢出和天文数字污染日志。
	MAX_DEVIATION = 1000.0

	CONFIDENCE_MIN_FOR_SCORE = 0.3 // 低于此置信度时 QPS 评分打 3 折
	CONFIDENCE_MIN_FOR_BLOCK = 0.1 // 低于此置信度时永不封禁（只记录评分）
	QUICK_DECAY_FACTOR      = 0.5  // 前 30 分钟快速收敛用的衰减系数
	NORMAL_DECAY_FACTOR     = 0.8  // 稳定后的正常衰减系数
	WARMUP_DURATION         = 30 * time.Minute // 基线预热期：此期间用快速衰减

	// ---------- 基线抗投毒：硬阈值预筛 ----------
	// Update() 收集样本前先过滤"明显可疑"的 IP：
	//   - 4xx/404 比率过高 → 扫描器特征（正常用户的 404 rate 极少 > 20%）
	//   - BotUA 比率过高 → 自动化工具特征
	//   - DangerousPattern 命中 ≥ minSamples 次 → 明确的攻击意图
	// 这些阈值故意设得很宽松，宁肯多过滤几个也不让攻击者污染基线。
	// 正常业务站点如果真的有某个 IP 的 404 rate > 80%（比如 CDN 预热 404 批量探测），
	// 那它本身也是异常行为，不参与基线学习是合理的。
	PRESCAN_MAX_RATE_4xx          = 0.80 // 4xx rate 超过此值直接排除
	PRESCAN_MAX_RATE_404          = 0.80 // 404 rate 超过此值直接排除
	PRESCAN_MAX_RATE_BOT_UA       = 0.90 // BotUA rate 超过此值直接排除
	PRESCAN_MIN_DANGEROUS_HITS    = 3    // DangerousPattern 命中 ≥ 此值直接排除
	PRESCAN_MIN_TRAVERSAL_HITS    = 3    // 路径穿越命中 ≥ 此值直接排除
)

// Percentile 分位数结果：描述某个流量特征维度的分布情况。
// P50 中位数，P95 大多数正常 IP 的上限，P99 极端正常值。
type Percentile struct {
	P50 float64 // 中位数
	P95 float64 // 95 分位（大多数正常 IP 在这个值以下）
	P99 float64 // 99 分位（极端正常值，超过则高度可疑）
	N   int     // 样本数
}

// BaselineDimensions 所有基线维度的集合。
// 计数型维度（QPS/ReqInterval）与窗口大小成正比。
// 比率型维度（4xx 比率等）窗口无关，计算为 count / totalReq。
type BaselineDimensions struct {
	// 计数型维度（与窗口大小成正比）
	QPS         Percentile // 请求速率分布（所有活跃 IP 的 qps = TotalReq / windowSec）
	ReqInterval Percentile // 请求间隔分布（可选，当前填默认零值）

	// 比率型维度（窗口无关，计算为 count / totalReq）
	Rate4xx      Percentile // 4xx 比率分布
	Rate5xx      Percentile // 5xx 比率分布
	Rate404      Percentile // 404 比率分布
	RateAuthFail Percentile // 认证失败比率分布
	RateSensPath Percentile // 敏感路径访问比率分布
	RateBotUA    Percentile // Bot UA 比率分布
	RateEmptyRef Percentile // 空 Referer 比率分布
	RateHeadMethod Percentile // HEAD 请求比率分布（动态适应站点特性：FineReport/CDN 站点 HEAD 天生多）
}

// Baseline 基线自学习引擎。
// 线程安全：mu 保护 dims / lastUpdated / sampleCount / confidence 的读写。
// 调用者定期传入 map[string]WindowCounters 更新基线，
// Scorer 通过 Get() 读取当前基线进行"偏离度评分"。
//
// confidence 说明基线的可信程度，取值 0~1：
//   - PreloadFromLogFile 计算：健康桶数 / 总桶数（0=Preload 全用低峰数据，1=全用高峰数据）
//   - 运行时自动提升：每小时根据最近观测数据重新计算
//   - Scorer 在置信度 < CONFIDENCE_MIN_FOR_SCORE 时自动对 QPS 偏离分打折
//   - Scorer 在置信度 < CONFIDENCE_MIN_FOR_BLOCK 时永不封禁
type Baseline struct {
	mu          sync.RWMutex
	dims        BaselineDimensions // 当前基线
	lastUpdated time.Time          // 最后一次更新时间
	windowSec   int                // 窗口大小（秒），用于 QPS 计算
	decayFactor float64            // 指数衰减系数（默认 0.8），newP = oldP*decay + currP*(1-decay)
	minSamples  int                // 最小样本数（默认 5），样本不足的 IP 不参与统计
	startAt     time.Time          // 该 Baseline 创建时间（用于冷启动 IsReady 判断）
	sampleCount int                // 最近一次 Update 的样本数
	confidence  float64            // 基线置信度（0~1），越高越可信
}

// NewBaseline 创建基线引擎。
// windowSec 用于 QPS 计算（TotalReq / windowSec）。
func NewBaseline(windowSec int) *Baseline {
	if windowSec <= 0 {
		windowSec = 1
	}
	return &Baseline{
		windowSec:   windowSec,
		decayFactor: NORMAL_DECAY_FACTOR,
		minSamples:  5,
		startAt:     time.Now(),
		confidence:  0.5, // 初始中等置信度，Preload 后会被覆盖
	}
}

// Update 根据所有活跃 IP 的计数器更新基线。
// 内部执行：过滤低样本 IP → 收集各维度样本 → 攻击者污染防护（极端值剔除）
// → 计算分位数 → 硬保底（QPS P95 >= MIN_BASELINE_QPS）→ 动态衰减融合历史 → 更新当前基线。
//
// 动态衰减：前 WARMUP_DURATION 用 QUICK_DECAY_FACTOR(0.5) 快速追平真实流量，
// 稳定后用 NORMAL_DECAY_FACTOR(0.8) 平滑跟踪趋势。
func (b *Baseline) Update(counters map[string]WindowCounters) {
	if len(counters) == 0 {
		return
	}

	var (
		qpsVals    []float64
		rate4xx    []float64
		rate5xx    []float64
		rate404    []float64
		rateAuth   []float64
		rateSens   []float64
		rateBotUA  []float64
		rateEmpty  []float64
		rateHead   []float64
	)

	for _, c := range counters {
		// 过滤 TotalReq < minSamples 的 IP
		if c.TotalReq < int64(b.minSamples) {
			continue
		}

		// G1 硬阈值预筛：明显可疑的 IP 直接 skip，不参与基线学习（防攻击者污染）
		if isLikelyAttacker(c) {
			continue
		}

		n := int64(b.windowSec)
		if n <= 0 {
			n = 1
		}
		qpsVals = append(qpsVals, float64(c.TotalReq)/float64(n))

		// 比率型维度
		rate4xx = append(rate4xx, ratio(c.Count4xx, c.TotalReq))
		rate5xx = append(rate5xx, ratio(c.Count5xx, c.TotalReq))
		rate404 = append(rate404, ratio(c.Count404, c.TotalReq))
		rateAuth = append(rateAuth, ratio(c.AuthFail, c.TotalReq))
		rateSens = append(rateSens, ratio(c.SensitivePathHit, c.TotalReq))
		rateBotUA = append(rateBotUA, ratio(c.BotUAHit, c.TotalReq))
		rateEmpty = append(rateEmpty, ratio(c.EmptyRefererHit, c.TotalReq))
		rateHead = append(rateHead, ratio(c.HeadMethod, c.TotalReq))
	}

	// G2 双重极端值剔除管线：
	//   Step 1: removeOutliersMAD — MAD 对极端值鲁棒，能砍掉"P99 本身就是极端值"的场景（如集群扫描）
	//   Step 2: trimExtremes P99×10 — 第二道保险，砍掉 MAD 没覆盖到的超天文值
	// G1 硬阈值预筛已经在上游过滤掉了明显的攻击者 IP，这里处理的是剩余的"边缘可疑值"
	qpsVals = removeOutliersMAD(qpsVals, 5)
	rate4xx = removeOutliersMAD(rate4xx, 5)
	rate5xx = removeOutliersMAD(rate5xx, 5)
	rate404 = removeOutliersMAD(rate404, 5)
	rateAuth = removeOutliersMAD(rateAuth, 5)
	rateSens = removeOutliersMAD(rateSens, 5)
	rateBotUA = removeOutliersMAD(rateBotUA, 5)
	rateEmpty = removeOutliersMAD(rateEmpty, 5)
	rateHead = removeOutliersMAD(rateHead, 5)

	qpsVals = trimExtremes(qpsVals, 10)
	rate4xx = trimExtremes(rate4xx, 10)
	rate5xx = trimExtremes(rate5xx, 10)
	rate404 = trimExtremes(rate404, 10)
	rateAuth = trimExtremes(rateAuth, 10)
	rateSens = trimExtremes(rateSens, 10)
	rateBotUA = trimExtremes(rateBotUA, 10)
	rateEmpty = trimExtremes(rateEmpty, 10)
	rateHead = trimExtremes(rateHead, 10)

	b.mu.Lock()
	defer b.mu.Unlock()

	// 为 MIN 兜底取一个合理参考值：优先用旧 baseline 的 P95（已知稳定），
	// 旧 baseline 也没数据就用 MIN_BASELINE_QPS 硬编码 fallback
	refDims := b.dims
	if refDims.QPS.N == 0 || refDims.QPS.P95 <= 0 {
		refDims = BaselineDimensions{QPS: Percentile{P95: MIN_BASELINE_QPS, P50: MIN_BASELINE_QPS * 0.3}}
	}
	dynMin := computeMinQPS(refDims)

	sampleCnt := len(qpsVals) + len(rate4xx) + len(rate5xx) + len(rate404) +
		len(rateAuth) + len(rateSens) + len(rateBotUA) + len(rateEmpty) + len(rateHead)

	curr := BaselineDimensions{
		QPS:          computePercentiles(qpsVals),
		Rate4xx:      computePercentiles(rate4xx),
		Rate5xx:      computePercentiles(rate5xx),
		Rate404:      computePercentiles(rate404),
		RateAuthFail: computePercentiles(rateAuth),
		RateSensPath: computePercentiles(rateSens),
		RateBotUA:    computePercentiles(rateBotUA),
		RateEmptyRef: computePercentiles(rateEmpty),
		RateHeadMethod: computePercentiles(rateHead),
	}

	// 硬保底（动态）：QPS P95 永远不低于 dynMin
	if curr.QPS.P95 < dynMin {
		if curr.QPS.P95 > 0 {
			curr.QPS.P95 = dynMin
			if curr.QPS.P99 < dynMin*2 {
				curr.QPS.P99 = dynMin * 2
			}
			if curr.QPS.P50 < dynMin*0.3 {
				curr.QPS.P50 = dynMin * 0.3
			}
		} else {
			curr.QPS.P95 = dynMin
			curr.QPS.P99 = dynMin * 2
			curr.QPS.P50 = dynMin * 0.3
		}
	}

	// 硬保底：比率型维度 P95 永远不低于 MIN_BASELINE_RATE_P95
	// 凌晨低峰 Preload 时 rate 维度 P95 可能是 1e-17 这样的极小正数，
	// deviation 计算时会爆炸。和 QPS 地板同理。
	curr.Rate4xx = floorRatePercentile(curr.Rate4xx)
	curr.Rate5xx = floorRatePercentile(curr.Rate5xx)
	curr.Rate404 = floorRatePercentile(curr.Rate404)
	curr.RateAuthFail = floorRatePercentile(curr.RateAuthFail)
	curr.RateSensPath = floorRatePercentile(curr.RateSensPath)
	curr.RateBotUA = floorRatePercentile(curr.RateBotUA)
	curr.RateEmptyRef = floorRatePercentile(curr.RateEmptyRef)
	curr.RateHeadMethod = floorRatePercentile(curr.RateHeadMethod)

	if b.dims.QPS.N > 0 {
		// 动态衰减：预热期用快速收敛，稳定后用正常衰减
		decay := b.decayFactor
		if time.Since(b.startAt) < WARMUP_DURATION {
			decay = QUICK_DECAY_FACTOR
		}
		b.dims = decayDims(b.dims, curr, decay)
		// 硬保底也应用到衰减结果上（用衰减后自身的 P95 来算 MIN，更准确）
		decayedMin := computeMinQPS(b.dims)
		if b.dims.QPS.P95 < decayedMin {
			b.dims.QPS.P95 = decayedMin
		}
		// 比率型维度衰减后也重新应用地板，防止旧 baseline 很小 + 新 baseline 很小 → 衰减后掉下去
		b.dims.Rate4xx = floorRatePercentile(b.dims.Rate4xx)
		b.dims.Rate5xx = floorRatePercentile(b.dims.Rate5xx)
		b.dims.Rate404 = floorRatePercentile(b.dims.Rate404)
		b.dims.RateAuthFail = floorRatePercentile(b.dims.RateAuthFail)
		b.dims.RateSensPath = floorRatePercentile(b.dims.RateSensPath)
		b.dims.RateBotUA = floorRatePercentile(b.dims.RateBotUA)
		b.dims.RateEmptyRef = floorRatePercentile(b.dims.RateEmptyRef)
		b.dims.RateHeadMethod = floorRatePercentile(b.dims.RateHeadMethod)
	} else {
		b.dims = curr
	}
	b.lastUpdated = time.Now()
	b.sampleCount = sampleCnt
}

// IsReady 返回基线是否已就绪。
// 冷启动时（样本不足或运行时间不够），Get() 会返回保守默认值。
func (b *Baseline) IsReady() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.sampleCount >= 100 && time.Since(b.startAt) >= 5*time.Minute
}

// ForceReady 强制将基线标记为就绪。
// 用于启动时预扫描历史日志建立基线的场景：样本已灌入并 Update 完成，
// 但 startAt 还是创建时间（可能只有几秒）。
// 此方法将 startAt 回拨 10 分钟，让 IsReady() 立即返回 true。
func (b *Baseline) ForceReady() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.startAt = time.Now().Add(-10 * time.Minute)
	if b.sampleCount < 100 {
		b.sampleCount = 100
	}
}

// SetConfidence 设置基线置信度（0~1）。Preload 计算完成后调用。
func (b *Baseline) SetConfidence(c float64) {
	if c < 0 {
		c = 0
	}
	if c > 1 {
		c = 1
	}
	b.mu.Lock()
	b.confidence = c
	b.mu.Unlock()
}

// Confidence 返回当前基线置信度（0~1）。
func (b *Baseline) Confidence() float64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.confidence
}

// IsConfident 返回基线置信度是否 >= min。
// 评分引擎用此判断是否该对 QPS 偏离分打折。
func (b *Baseline) IsConfident(min float64) bool {
	return b.Confidence() >= min
}

// Get 返回当前基线维度的副本（不含 confidence）。
// 冷启动时（!IsReady()）返回保守默认值，不会误报。
// 推荐用 GetWithConfidence 同时拿到置信度。
func (b *Baseline) Get() *BaselineDimensions {
	d, _ := b.GetWithConfidence()
	return d
}

// GetWithConfidence 返回当前基线维度副本 + 置信度。
// 冷启动时返回保守默认值 + confidence=0（表示无可信基线）。
func (b *Baseline) GetWithConfidence() (*BaselineDimensions, float64) {
	b.mu.RLock()
	ready := b.sampleCount >= 100 && time.Since(b.startAt) >= 5*time.Minute
	d := b.dims
	conf := b.confidence
	b.mu.RUnlock()

	if !ready {
		def := defaultBaselineDims()
		return &def, 0
	}
	return &d, conf
}

// LogBaselineStats 返回当前基线统计字符串（调用方决定怎么输出）。
func (b *Baseline) LogBaselineStats(tag string) string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return fmt.Sprintf("[baseline] %s: QPS P50=%.2f P95=%.2f P99=%.2f N=%d conf=%.2f samples=%d",
		tag, b.dims.QPS.P50, b.dims.QPS.P95, b.dims.QPS.P99,
		b.dims.QPS.N, b.confidence, b.sampleCount)
}

// ---------- 包级辅助函数 ----------

// floorRatePercentile 将比率型维度的 P95 / P99 / P50 夹到地板值以上。
// 凌晨低峰 Preload 时，很多 rate 维度的样本全是 0 或只有极个别非零样本，
// computePercentiles 会产出 P95=1e-17 这样的极小正数。
// deviation 用 P95 做除数时会爆炸到 1e200，污染评分引擎和日志。
// 统一用 MIN_BASELINE_RATE_P95 做地板，保证基线永远"有意义"。
func floorRatePercentile(p Percentile) Percentile {
	if p.N == 0 {
		return p
	}
	floor := MIN_BASELINE_RATE_P95
	if p.P95 < floor {
		p.P95 = floor
	}
	if p.P99 < floor*3 {
		p.P99 = floor * 3
	}
	if p.P50 < floor*0.3 {
		p.P50 = floor * 0.3
	}
	return p
}

// defaultBaselineDims 返回冷启动保守默认值。
// 所有 P95 都设为非常宽松的值，避免误报。
// N=0 表示是默认值（非真实统计）。
func defaultBaselineDims() BaselineDimensions {
	def := Percentile{N: 0}
	return BaselineDimensions{
		QPS:         Percentile{P95: 1000, P99: 2000, N: 0},
		ReqInterval: def,
		Rate4xx:     Percentile{P95: 1.0, P99: 1.0, N: 0},
		Rate5xx:     Percentile{P95: 1.0, P99: 1.0, N: 0},
		Rate404:     Percentile{P95: 1.0, P99: 1.0, N: 0},
		RateAuthFail: Percentile{P95: 1.0, P99: 1.0, N: 0},
		RateSensPath: Percentile{P95: 1.0, P99: 1.0, N: 0},
		RateBotUA:   Percentile{P95: 1.0, P99: 1.0, N: 0},
		RateEmptyRef: Percentile{P95: 1.0, P99: 1.0, N: 0},
		RateHeadMethod: Percentile{P95: 1.0, P99: 1.0, N: 0},
	}
}

// computePercentiles 计算分位数。
// 空切片返回零值 Percentile；过滤 NaN/Inf。
// 使用简单索引而非线性插值。
func computePercentiles(values []float64) Percentile {
	if len(values) == 0 {
		return Percentile{}
	}

	// 过滤 NaN/Inf
	filtered := make([]float64, 0, len(values))
	for _, v := range values {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			continue
		}
		if v < 0 {
			v = 0
		}
		filtered = append(filtered, v)
	}
	n := len(filtered)
	if n == 0 {
		return Percentile{}
	}

	sort.Float64s(filtered)

	p50 := filtered[n/2]
	p95 := filtered[int(0.95*float64(n))]
	p99 := filtered[int(0.99*float64(n))]

	return Percentile{P50: p50, P95: p95, P99: p99, N: n}
}

// isLikelyAttacker 硬阈值预筛：判断一个 IP 的窗口计数器是否明显"像攻击者"。
// 满足任一条件即返回 true（不参与基线学习）：
//   1. Rate4xx > 0.80（80%+ 的请求是 4xx → 扫描器特征）
//   2. Rate404 > 0.80（80%+ 的请求是 404 → 枚举探测特征）
//   3. RateBotUA > 0.90（90%+ 是 Bot UA → 自动化工具）
//   4. DangerousPattern 命中 ≥ 3 次（明确的攻击意图）
//   5. AttackPathHit 命中 ≥ 3 次（路径穿越等）
//
// 这些阈值故意设得很宽松（0.80/0.90），保证正常业务几乎不会被误伤：
//   - 正常用户的 4xx rate 通常 < 20%（绝大多数是偶尔的 404）
//   - CDN 爬虫/搜索引擎的 BotUA rate 很高但 404 rate 不会到 80%
//   - 真正的扫描器（如 libredtail、nmap）会同时满足 4xx=100% + BotUA=100%
func isLikelyAttacker(c WindowCounters) bool {
	if c.TotalReq <= 0 {
		return false
	}
	r4xx := ratio(c.Count4xx, c.TotalReq)
	if r4xx > PRESCAN_MAX_RATE_4xx {
		return true
	}
	r404 := ratio(c.Count404, c.TotalReq)
	if r404 > PRESCAN_MAX_RATE_404 {
		return true
	}
	rBot := ratio(c.BotUAHit, c.TotalReq)
	if rBot > PRESCAN_MAX_RATE_BOT_UA {
		return true
	}
	if c.DangerousPatternHit >= PRESCAN_MIN_DANGEROUS_HITS {
		return true
	}
	if c.PathTraversalHit >= PRESCAN_MIN_TRAVERSAL_HITS {
		return true
	}
	return false
}

// trimExtremes 剔除偏离临时 P99 超过 factor 倍的极端值（攻击者污染防护）。
// 先计算临时 P99，再过滤。样本数不足 5 时原样返回。
// 局限：只能砍 P99 × factor 以外的值，砍不掉 P99 本身（如果 P99 就是极端值）。
// 更彻底的极端值剔除见 removeOutliersMAD。
func trimExtremes(values []float64, factor float64) []float64 {
	if len(values) < 5 {
		return values
	}
	tmp := computePercentiles(values)
	if tmp.P99 <= 0 {
		return values
	}
	threshold := tmp.P99 * factor
	out := make([]float64, 0, len(values))
	for _, v := range values {
		if v <= threshold {
			out = append(out, v)
		}
	}
	return out
}

// removeOutliersMAD 用 MAD（Median Absolute Deviation）方法剔除极端值。
// MAD = median(|x_i - median|)
// 阈值 = median + k × MAD；超过此值的 x_i 视为极端值并删除。
//
// 相比 trimExtremes 的优势：
//   - MAD 本身对极端值鲁棒（不像 P99 会被极端值拉高）
//   - 能砍掉 P95/P99 位置上的极端值（正是 Preload 场景下的扫描器/爬虫桶）
//   - 对正态分布 k≈3 对应 99.7% 置信；k=5 更保守，保留更多真实值
//
// k=5 是推荐值：
//   你的场景 median=1.4, MAD≈0.5 → 阈值=3.9 req/s
//   扫描器桶 70 req/s 被删，正常桶 3 req/s 保留
func removeOutliersMAD(values []float64, k float64) []float64 {
	if len(values) < 5 {
		return values
	}

	// 1. 算 median
	sorted := make([]float64, len(values))
	copy(sorted, values)
	sort.Float64s(sorted)
	median := sorted[len(sorted)/2]

	// 2. 算 MAD = median(|x - median|)
	absDev := make([]float64, len(values))
	for i, v := range values {
		diff := v - median
		if diff < 0 {
			diff = -diff
		}
		absDev[i] = diff
	}
	sort.Float64s(absDev)
	mad := absDev[len(absDev)/2]

	// MAD 为 0 说明数据几乎全相同（比如所有桶都是 1 req/s），无法用 MAD 检测
	if mad <= 0 {
		return values
	}

	// 3. 删掉超过 median + k*MAD 的值
	threshold := median + k*mad
	out := make([]float64, 0, len(values))
	for _, v := range values {
		if v <= threshold {
			out = append(out, v)
		}
	}
	return out
}

// decayDims 对两组 BaselineDimensions 做指数衰减融合。
// new = old*decay + curr*(1-decay)；decay 决定历史权重。
func decayDims(old, curr BaselineDimensions, decay float64) BaselineDimensions {
	out := BaselineDimensions{}
	out.QPS = decayPercentile(old.QPS, curr.QPS, decay)
	out.Rate4xx = decayPercentile(old.Rate4xx, curr.Rate4xx, decay)
	out.Rate5xx = decayPercentile(old.Rate5xx, curr.Rate5xx, decay)
	out.Rate404 = decayPercentile(old.Rate404, curr.Rate404, decay)
	out.RateAuthFail = decayPercentile(old.RateAuthFail, curr.RateAuthFail, decay)
	out.RateSensPath = decayPercentile(old.RateSensPath, curr.RateSensPath, decay)
	out.RateBotUA = decayPercentile(old.RateBotUA, curr.RateBotUA, decay)
	out.RateEmptyRef = decayPercentile(old.RateEmptyRef, curr.RateEmptyRef, decay)
	out.RateHeadMethod = decayPercentile(old.RateHeadMethod, curr.RateHeadMethod, decay)
	return out
}

// decayPercentile 对单个 Percentile 做指数衰减融合。
// curr.N=0 时表示该维度本轮无新数据，直接保留 old。
func decayPercentile(old, curr Percentile, decay float64) Percentile {
	if curr.N == 0 {
		return old
	}
	return Percentile{
		P50: old.P50*decay + curr.P50*(1-decay),
		P95: old.P95*decay + curr.P95*(1-decay),
		P99: old.P99*decay + curr.P99*(1-decay),
		N:   curr.N,
	}
}

// deviation 计算 value 相对基线 P95 的偏离倍数。
// p.P95 <= 0 时返回 0（避免除零）；结果 cap 到 MAX_DEVIATION 避免天文数字污染。
func deviation(value float64, p Percentile) float64 {
	if p.P95 <= 0 {
		return 0
	}
	dev := value / p.P95
	if dev > MAX_DEVIATION {
		dev = MAX_DEVIATION
	}
	return dev
}

// deviationToScore 将偏离倍数转换为 0-100 的风险分。
// threshold 是偏离多少倍才开始计分——由调用方从动态参数计算（见 computeThresholds）。
// dev < threshold → 0 分；否则 score = min((dev-threshold)*10, 100)。
func deviationToScore(dev float64, threshold float64) int {
	if dev < threshold {
		return 0
	}
	excess := dev - threshold
	score := int(math.Min(excess*10, 100))
	return score
}

// ---------- 动态自适应参数 ----------
// 所有参数由基线自身的统计特征推导，不引入外部配置。
// 当 confidence < 0.5 或 baseline 无数据时，回退到硬编码默认值（保持历史行为）。

// computeMinQPS 计算 QPS 硬保底下限：P95 × 0.1，clamp 在 [0.5, 50.0]。
// 理由：P95 的 10% 是一个"合理的最小值"——不会干扰 baseline 真实值，
// 又能防止 baseline 被压到极端小值导致 deviation 计算爆炸。
// 示例：P95=73 → MIN=7.3；P95=1.5 → MIN=0.5；P95=500 → MIN=50.0。
func computeMinQPS(dims BaselineDimensions) float64 {
	if dims.QPS.N == 0 || dims.QPS.P95 <= 0 {
		return MIN_BASELINE_QPS // fallback to original default on cold start
	}
	min := dims.QPS.P95 * 0.1
	if min < 0.5 {
		min = 0.5
	}
	if min > 50.0 {
		min = 50.0
	}
	return min
}

// computeGuardQPS 计算 activity guard 阈值：P95 × 0.02，最低 0.05。
// QPS 低于此值时，所有相对维度清零（只保留绝对攻击特征）。
// 固定 0.3 对小站点太苛刻——P95=1 的站点正常 QPS 就可能 < 0.3。
func computeGuardQPS(dims BaselineDimensions) float64 {
	if dims.QPS.N == 0 || dims.QPS.P95 <= 0 {
		return 0.3 // fallback to original default
	}
	guard := dims.QPS.P95 * 0.02
	if guard < 0.05 {
		guard = 0.05
	}
	return guard
}

// computeThresholds 计算三档 sensitivity 对应的偏离倍数 threshold 数组。
// 返回 [sens1, sens2, sens3]，含义是"偏离多少倍才开始计分"。
//
// 核心思想：threshold 应该理解站点的流量稳定性。
//   R = P95 / P50 是站点的正常波动倍率（稳定站点 R≈1.0，波动站点 R≈5~10）
//   threshold = R × slack（sensitivity 决定 slack 松紧）
//
// sensitivity=1 (high, 最紧): slack=1.2x → threshold = R×1.2, cap [1.5, 15.0]
// sensitivity=2 (medium, 默认): slack=1.5x → threshold = R×1.5, cap [2.0, 15.0]
// sensitivity=3 (low, 最松): slack=2.5x → threshold = R×2.5, cap [3.0, 15.0]
//
// confidence < 0.5 或 P50=0 时回退到硬编码 [2.0, 5.0, 10.0]。
//
// 示例（P50=62, P95=73, R=1.18）：
//   sens1=max(1.18×1.2, 1.5)=1.5, sens2=max(1.18×1.5, 2.0)=2.0, sens3=max(1.18×2.5, 3.0)=3.0
//   → 稳定站点 threshold 卡到 cap 下限，和历史行为一致
//
// 示例（P50=0.5, P95=1.5, R=3.0，小站点）：
//   sens1=max(3.0×1.2, 1.5)=3.6, sens2=max(3.0×1.5, 2.0)=4.5, sens3=max(3.0×2.5, 3.0)=7.5
//   → 波动站点 threshold 自动放大，不会把正常波动算成 deviation
func computeThresholds(dims BaselineDimensions, confidence float64) [3]float64 {
	// Fallback: confidence 太低或 baseline 无数据 → 用硬编码默认值（历史行为）
	if confidence < 0.5 || dims.QPS.N == 0 || dims.QPS.P50 <= 0 {
		return [3]float64{2.0, 5.0, 10.0}
	}

	// R = 正常波动倍率，cap 在 [1.01, 10.0] 防极端
	R := dims.QPS.P95 / math.Max(dims.QPS.P50, 0.5)
	if R < 1.01 {
		R = 1.01
	}
	if R > 10.0 {
		R = 10.0
	}

	t1 := R * 1.2
	t2 := R * 1.5
	t3 := R * 2.5

	// cap 下限（sens 越高越松，下限也越高）
	if t1 < 1.5 {
		t1 = 1.5
	}
	if t2 < 2.0 {
		t2 = 2.0
	}
	if t3 < 3.0 {
		t3 = 3.0
	}

	// cap 上限 15.0
	cap := 15.0
	if t1 > cap {
		t1 = cap
	}
	if t2 > cap {
		t2 = cap
	}
	if t3 > cap {
		t3 = cap
	}

	return [3]float64{t1, t2, t3}
}

// Thresholds 返回当前基线的三档 sensitivity threshold 数组。
// 公开供 scorer.go 调用——不需要持有锁，内部自行 RLock。
func (b *Baseline) Thresholds() [3]float64 {
	b.mu.RLock()
	d := b.dims
	conf := b.confidence
	b.mu.RUnlock()
	return computeThresholds(d, conf)
}

// MinQPS 返回当前基线的动态 QPS 硬保底下限。
// 公开供外部（如 scorer/detector preload）查询。
func (b *Baseline) MinQPS() float64 {
	b.mu.RLock()
	d := b.dims
	b.mu.RUnlock()
	return computeMinQPS(d)
}

// GuardQPS 返回当前基线的动态 activity guard 阈值。
// 公开供 scorer.go 调用——QPS 低于此值时清零所有相对维度。
func (b *Baseline) GuardQPS() float64 {
	b.mu.RLock()
	d := b.dims
	b.mu.RUnlock()
	return computeGuardQPS(d)
}

// ratio 安全计算 numerator/denominator。
// denominator<=0 或 numerator<=0 时返回 0。
func ratio(numerator, denominator int64) float64 {
	if denominator <= 0 {
		return 0
	}
	if numerator <= 0 {
		return 0
	}
	return float64(numerator) / float64(denominator)
}

// getEffectiveSensitivity 根据 IP 历史访问量返回实际敏感度。
// baseSensitivity 范围 1-3；seenCount<20 返回 1（新 IP 严格），>1000 返回 3（老 IP 宽松）。
func getEffectiveSensitivity(seenCount int, baseSensitivity int) int {
	if baseSensitivity < 1 || baseSensitivity > 3 {
		baseSensitivity = 2
	}
	if seenCount < 20 {
		return 1
	}
	if seenCount > 1000 {
		return 3
	}
	return baseSensitivity
}
