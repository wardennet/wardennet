// Package detector - consistency.go
// 5 维行为连贯性评分（Consistency Score）。
//
// 设计原则：零业务依赖、零 header 依赖、纯统计形状。
// 只依赖 access.log 必有字段的排列模式：path 序列的前缀连贯性、
// 新颖度饱和、路径集中度、状态同质性、HTTP 方法语义符合度。
//
// 用于 Scorer 之后的降权 gate：若一个 IP 在形状上明显是正常用户，
// 但 Scorer 给了高分（基线偏离），则降权到 ScoreMedium，
// 让多事件确认机制去处理。
//
// 参数化：所有阈值和权重集中在 ConsistencyThresholds 结构，
// 由 DetectorCfg.Consistency 注入。程序默认值 DefaultConsistencyThresholds()
// 兜底（与 hardcoded 版本一致，不影响现有测试）。
//
// 内存: ring buffer 容量 512 条/IP，每条约 64 字节，active 500 IP ≈ 16 MB。

package detector

import (
	"math"
	"regexp"
	"strings"
)

// ---------- ConsistencyThresholds ----------

// ConsistencyThresholds 5 维评分的所有阈值、权重、工程参数。
// 可由 DetectorCfg.Consistency 覆盖；nil 字段保留 DefaultConsistencyThresholds() 值。
//
// 为什么需要参数化？
//   - 不同系统特征差异大（纯 API 站 vs 富前端 SPA），阈值需要微调
//   - 合法机器客户端边界（如内部 RPA）可由用户配置更宽松
//
// YAML 示例:
//   detector:
//     consistency:
//       min_samples: 15          # 降低样本要求
//       score_threshold: 3      # 放宽 BENIGN 判定
//       ring_capacity: 1024      # 加大历史窗口
//       path_concentrated_threshold: 0.20
//       novelty_early30_min: 0.60
type ConsistencyThresholds struct {
	// --- 工程参数 ---
	RingCapacity int `yaml:"ring_capacity"`     // 每 IP 最多保留的历史请求数，默认 512
	MinSamples   int `yaml:"min_samples"`        // 总请求数不足时评分不可靠，默认 20
	ScoreThreshold int `yaml:"score_threshold"`   // >= 此分判 BENIGN，默认 4

	// --- 前缀连贯度阈值 ---
	PrefixRunLenMin  float64 `yaml:"prefix_run_len_min"`  // avgRunLen >= 此值 → 连贯，默认 3
	PrefixDominantMin float64 `yaml:"prefix_dominant_min"` // dominant 前缀占比 >= 此值 → 连贯，默认 0.50

	// --- 新颖度饱和阈值 ---
	NoveltyEarly30Min  float64 `yaml:"novelty_early30_min"`   // 前 30% 请求覆盖路径占比 ≥ 此值，默认 0.70
	LateNoveltyRateMax float64 `yaml:"late_novelty_rate_max"` // 晚 30% 请求的新增路径率 ≤ 此值，默认 0.40

	// --- 路径集中度阈值 ---
	PathConcentratedThreshold float64 `yaml:"path_concentrated_threshold"` // Top5 覆盖比例阈值，默认 0.25

	// --- 状态同质性阈值 ---
	StatusCVMax float64 `yaml:"status_cv_max"` // 同路径状态码变异系数上限，默认 0.6

	// --- 方法语义阈值 ---
	GetRatioMin    float64 `yaml:"get_ratio_min"`     // GET 占比下限，默认 0.50
	GetRatioMax    float64 `yaml:"get_ratio_max"`     // GET 占比上限，默认 0.99
	PostRatioMin   float64 `yaml:"post_ratio_min"`    // POST 占比下限，默认 0.01
	PostRatioMax   float64 `yaml:"post_ratio_max"`    // POST 占比上限，默认 0.49
	UnusualMax     float64 `yaml:"unusual_max"`       // PUT/DELETE/PATCH 上限，默认 0.05
	PureAPIGetMax  float64 `yaml:"pure_api_get_max"`  // 纯 API GET 客户端：GET ≥ 此值 + Unusual ≤ 0.01，默认 0.80
	PureAPIPostMin float64 `yaml:"pure_api_post_min"` // 纯 API POST 客户端：POST ≥ 此值，默认 0.50

	// --- 反信号阈值 ---
	AlwaysErrorDynamicMin    int     `yaml:"always_error_dynamic_min"`    // 动态路径反复撞墙 ≥ 此次 → 反信号，默认 5
	AlwaysErrorProbeMin      int     `yaml:"always_error_probe_min"`      // 公共探测反复撞墙 ≥ 此次 → 反信号，默认 10
	SinglePathErrorBonus     int     `yaml:"single_path_error_bonus"`     // 单路径+全错额外扣分（绝对值），默认 3
	AlwaysErrorScorePenalty  int     `yaml:"always_error_score_penalty"`  // 反复撞墙扣分（绝对值），默认 5

	// --- 发散扫描反信号阈值 ---
	HighlyNovelEarlyMax  float64 `yaml:"highly_novel_early_max"`   // 早 30% 覆盖 < 此值，默认 0.50
	HighlyNovelLateMin   float64 `yaml:"highly_novel_late_min"`    // 晚 30% 新增 > 此值，默认 0.70
	HighlyNovelCoverMax  float64 `yaml:"highly_novel_cover_max"`   // Top5 覆盖 < 此值，默认 0.40
	HighlyNovelPenalty   int     `yaml:"highly_novel_penalty"`     // 发散扫描扣分（绝对值），默认 3

	// --- 评分权重 ---
	WeightPrefix    int `yaml:"weight_prefix"`     // 前缀连贯 +2
	WeightNovelty   int `yaml:"weight_novelty"`    // 新颖度饱和 +2
	WeightPathConc  int `yaml:"weight_path_conc"`  // 路径集中 +2
	WeightErrors    int `yaml:"weight_errors"`     // 状态同质 +1
	WeightMethod    int `yaml:"weight_method"`     // 方法语义 +1
}

// DefaultConsistencyThresholds 返回程序默认值。
// 与重构前 hardcoded 版本完全等价，不影响现有测试和生产行为。
func DefaultConsistencyThresholds() ConsistencyThresholds {
	return ConsistencyThresholds{
		RingCapacity:  512,
		MinSamples:    20,
		ScoreThreshold: 4,

		PrefixRunLenMin:   3,
		PrefixDominantMin: 0.50,

		NoveltyEarly30Min:  0.70,
		LateNoveltyRateMax: 0.40,

		PathConcentratedThreshold: 0.25,

		StatusCVMax: 0.6,

		GetRatioMin:    0.50,
		GetRatioMax:    0.99,
		PostRatioMin:   0.01,
		PostRatioMax:   0.49,
		UnusualMax:     0.05,
		PureAPIGetMax:  0.80,
		PureAPIPostMin: 0.50,

		AlwaysErrorDynamicMin:   5,
		AlwaysErrorProbeMin:     10,
		SinglePathErrorBonus:    3,
		AlwaysErrorScorePenalty: 5,

		HighlyNovelEarlyMax: 0.50,
		HighlyNovelLateMin:  0.70,
		HighlyNovelCoverMax: 0.40,
		HighlyNovelPenalty:  3,

		WeightPrefix:   2,
		WeightNovelty:  2,
		WeightPathConc: 2,
		WeightErrors:   1,
		WeightMethod:   1,
	}
}

// MergeConsistencyThresholds 合并用户配置和程序默认值。
// cfg 中零值字段保留 default 对应的值。
func MergeConsistencyThresholds(cfg *ConsistencyThresholds, def ConsistencyThresholds) ConsistencyThresholds {
	if cfg == nil {
		return def
	}
	out := def
	if cfg.RingCapacity > 0 {
		out.RingCapacity = cfg.RingCapacity
	}
	if cfg.MinSamples > 0 {
		out.MinSamples = cfg.MinSamples
	}
	if cfg.ScoreThreshold > 0 {
		out.ScoreThreshold = cfg.ScoreThreshold
	}
	if cfg.PrefixRunLenMin != 0 {
		out.PrefixRunLenMin = cfg.PrefixRunLenMin
	}
	if cfg.PrefixDominantMin != 0 {
		out.PrefixDominantMin = cfg.PrefixDominantMin
	}
	if cfg.NoveltyEarly30Min != 0 {
		out.NoveltyEarly30Min = cfg.NoveltyEarly30Min
	}
	if cfg.LateNoveltyRateMax != 0 {
		out.LateNoveltyRateMax = cfg.LateNoveltyRateMax
	}
	if cfg.PathConcentratedThreshold != 0 {
		out.PathConcentratedThreshold = cfg.PathConcentratedThreshold
	}
	if cfg.StatusCVMax != 0 {
		out.StatusCVMax = cfg.StatusCVMax
	}
	if cfg.GetRatioMin != 0 {
		out.GetRatioMin = cfg.GetRatioMin
	}
	if cfg.GetRatioMax != 0 {
		out.GetRatioMax = cfg.GetRatioMax
	}
	if cfg.PostRatioMin != 0 {
		out.PostRatioMin = cfg.PostRatioMin
	}
	if cfg.PostRatioMax != 0 {
		out.PostRatioMax = cfg.PostRatioMax
	}
	if cfg.UnusualMax != 0 {
		out.UnusualMax = cfg.UnusualMax
	}
	if cfg.PureAPIGetMax != 0 {
		out.PureAPIGetMax = cfg.PureAPIGetMax
	}
	if cfg.PureAPIPostMin != 0 {
		out.PureAPIPostMin = cfg.PureAPIPostMin
	}
	if cfg.AlwaysErrorDynamicMin > 0 {
		out.AlwaysErrorDynamicMin = cfg.AlwaysErrorDynamicMin
	}
	if cfg.AlwaysErrorProbeMin > 0 {
		out.AlwaysErrorProbeMin = cfg.AlwaysErrorProbeMin
	}
	if cfg.SinglePathErrorBonus > 0 {
		out.SinglePathErrorBonus = cfg.SinglePathErrorBonus
	}
	if cfg.AlwaysErrorScorePenalty > 0 {
		out.AlwaysErrorScorePenalty = cfg.AlwaysErrorScorePenalty
	}
	if cfg.HighlyNovelEarlyMax != 0 {
		out.HighlyNovelEarlyMax = cfg.HighlyNovelEarlyMax
	}
	if cfg.HighlyNovelLateMin != 0 {
		out.HighlyNovelLateMin = cfg.HighlyNovelLateMin
	}
	if cfg.HighlyNovelCoverMax != 0 {
		out.HighlyNovelCoverMax = cfg.HighlyNovelCoverMax
	}
	if cfg.HighlyNovelPenalty > 0 {
		out.HighlyNovelPenalty = cfg.HighlyNovelPenalty
	}
	if cfg.WeightPrefix != 0 {
		out.WeightPrefix = cfg.WeightPrefix
	}
	if cfg.WeightNovelty != 0 {
		out.WeightNovelty = cfg.WeightNovelty
	}
	if cfg.WeightPathConc != 0 {
		out.WeightPathConc = cfg.WeightPathConc
	}
	if cfg.WeightErrors != 0 {
		out.WeightErrors = cfg.WeightErrors
	}
	if cfg.WeightMethod != 0 {
		out.WeightMethod = cfg.WeightMethod
	}
	return out
}

// ---------- 常量（ring 默认容量仍保留，但会被 Thresholds.RingCapacity 覆盖） ----------

// pathRecord 单条请求记录，用于 Consistency 评分。
// 存 bare path（去 query）+ method + status，足够算 5 维。
type pathRecord struct {
	path   string // bare path, e.g. "/tdsc/api/list"
	method byte   // 'G','P','U','D','H','O'
	status int16  // 200, 404, 403, 500, ...
}

// pathRing per-IP 历史请求 ring buffer。
// 容量可配置，写满覆盖最旧的。
type pathRing struct {
	buf      []pathRecord
	head     int  // 下一个写入位置
	full     bool // buf 是否满过
	total    int  // 累计写入次数
	capacity int  // buf 长度
}

func newPathRing(capacity int) *pathRing {
	if capacity <= 0 {
		capacity = DefaultConsistencyThresholds().RingCapacity
	}
	return &pathRing{
		buf:      make([]pathRecord, capacity),
		capacity: capacity,
	}
}

func (r *pathRing) append(path string, method string, status int) {
	var methodByte byte = 'G' // 默认 GET
	switch strings.ToUpper(method) {
	case "GET":
		methodByte = 'G'
	case "POST":
		methodByte = 'P'
	case "PUT":
		methodByte = 'U'
	case "DELETE":
		methodByte = 'D'
	case "PATCH":
		methodByte = 'O'
	case "HEAD":
		methodByte = 'H'
	default:
		methodByte = 'X'
	}
	r.buf[r.head] = pathRecord{path: path, method: methodByte, status: int16(status)}
	r.head = (r.head + 1) % r.capacity
	r.total++
	if r.head == 0 {
		r.full = true
	}
}

// all 返回 ring buffer 中所有有效记录，按时间序（旧→新）。
func (r *pathRing) all() []pathRecord {
	n := r.capacity
	if !r.full {
		n = r.head
	}
	out := make([]pathRecord, 0, n)
	if r.full {
		// 旧数据: head..end，新数据: 0..head-1
		out = append(out, r.buf[r.head:]...)
		out = append(out, r.buf[:r.head]...)
	} else {
		out = append(out, r.buf[:r.head]...)
	}
	return out
}

// --- Consistency 评分 ---

var (
	staticExtRe    = regexp.MustCompile(`(?i)\.(css|js|mjs|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|otf|map|woff)$`)
	commonProbeRe  = regexp.MustCompile(`(?i)^/(favicon\.ico|robots\.txt|sitemap\.xml|crossdomain\.xml|\.well-known/.*)$`)
)

// ConsistencyScoreResult 评分结果。
// Score: 原始分（含反信号）。
// IsBenign: Score >= 4。
// Details: 各维度是否命中，用于日志诊断。
type ConsistencyScoreResult struct {
	Score            int
	IsBenign         bool
	HasSamples       bool // total >= 20
	Total            int
	UniquePaths      int

	PrefixCoherent    bool
	NoveltyConverged  bool
	PathConcentrated  bool
	ErrorsStable      bool
	MethodNatural     bool
	AlwaysSameError   bool

	AvgRunLen       float64
	SegDominant     float64
	NoveltyEarly30  float64
	LateNoveltyRate float64
	Top5Cover       float64
	AvgStatusCV     float64
	GetRatio        float64
	PostRatio       float64
	UnusualRatio    float64
}

// firstSegment 提取路径第一段（如 "/api/v1/users" → "/api"）。
func firstSegmentConsistency(path string) string {
	// 去除 query
	if i := strings.Index(path, "?"); i >= 0 {
		path = path[:i]
	}
	// 去除尾随 /
	path = strings.TrimRight(path, "/")
	if path == "" || path == "/" {
		return "/"
	}
	parts := strings.Split(path, "/")
	for _, p := range parts {
		if p != "" {
			return "/" + p
		}
	}
	return "/"
}

func cvInt(arr []int) float64 {
	if len(arr) < 2 {
		return 0
	}
	var s float64
	for _, v := range arr {
		s += float64(v)
	}
	m := s / float64(len(arr))
	if m == 0 {
		return 0
	}
	var varS float64
	for _, v := range arr {
		d := float64(v) - m
		varS += d * d
	}
	return math.Sqrt(varS/float64(len(arr)-1)) / m
}

// Score 对 ring buffer 中的数据计算 Consistency 分数。
// 总请求数不足 consistencyMinSamples 时返回 HasSamples=false，调用方应跳过。
// Score 接收 ConsistencyThresholds 参数进行评分。
// 所有阈值、权重、工程参数都从 t 读取，支持运行时配置覆盖。
func (r *pathRing) Score(t ConsistencyThresholds) ConsistencyScoreResult {
	recs := r.all()
	total := len(recs)
	res := ConsistencyScoreResult{Total: total}
	if total < t.MinSamples {
		res.HasSamples = false
		return res
	}
	res.HasSamples = true

	// --- 统计数据 ---
	segAt := make([]string, total)
	pathCount := map[string]int{}
	pathStatuses := map[string][]int{}
	methodCount := map[byte]int{}
	for i, rec := range recs {
		segAt[i] = firstSegmentConsistency(rec.path)
		pathCount[rec.path]++
		pathStatuses[rec.path] = append(pathStatuses[rec.path], int(rec.status))
		methodCount[rec.method]++
	}
	res.UniquePaths = len(pathCount)

	// --- ① 前缀连贯度 ---
	runLen := 1
	var runs []int
	for i := 1; i < len(segAt); i++ {
		if segAt[i] == segAt[i-1] {
			runLen++
		} else {
			runs = append(runs, runLen)
			runLen = 1
		}
	}
	runs = append(runs, runLen)
	var sum int
	for _, rn := range runs {
		sum += rn
	}
	avgRunLen := float64(sum) / float64(len(runs))
	res.AvgRunLen = math.Round(avgRunLen*100) / 100.0
	// dominant 前缀占比
	segCnt := map[string]int{}
	for _, seg := range segAt {
		segCnt[seg]++
	}
	maxN := 0
	for _, n := range segCnt {
		if n > maxN {
			maxN = n
		}
	}
	dominant := float64(maxN) / float64(total)
	res.SegDominant = math.Round(dominant*1000) / 1000.0
	res.PrefixCoherent = avgRunLen >= t.PrefixRunLenMin || dominant >= t.PrefixDominantMin

	// --- ② 新颖度饱和 ---
	req30 := total / 3
	if req30 < 1 {
		req30 = 1
	}
	// 早 30% 发现的路径集合
	earlySet := map[string]bool{}
	for i := 0; i < req30; i++ {
		earlySet[recs[i].path] = true
	}
	res.NoveltyEarly30 = float64(len(earlySet)) / float64(len(pathCount))
	// 晚 30% 中，有多少是 earlySet 里没有的
	lateNew := 0
	for i := total - req30; i < total; i++ {
		if !earlySet[recs[i].path] {
			lateNew++
		}
	}
	res.LateNoveltyRate = float64(lateNew) / float64(req30)
	res.NoveltyConverged = res.NoveltyEarly30 >= t.NoveltyEarly30Min && res.LateNoveltyRate <= t.LateNoveltyRateMax

	// --- ③ 路径集中度 ---
	top5Paths := topKStrings(pathCount, 5)
	var top5Sum int
	for _, p := range top5Paths {
		top5Sum += pathCount[p]
	}
	res.Top5Cover = float64(top5Sum) / float64(total)
	res.PathConcentrated = res.Top5Cover >= t.PathConcentratedThreshold

	// --- ④ 状态同质性 ---
	var pCVs []float64
	for _, sts := range pathStatuses {
		if len(sts) < 3 {
			continue
		}
		// 分组计数
		cnt := map[int]int{}
		for _, s := range sts {
			cnt[s]++
		}
		vals := make([]int, 0, len(cnt))
		for _, n := range cnt {
			vals = append(vals, n)
		}
		pCVs = append(pCVs, cvInt(vals))
	}
	if len(pCVs) > 0 {
		var s float64
		for _, c := range pCVs {
			s += c
		}
		res.AvgStatusCV = math.Round((s/float64(len(pCVs)))*1000) / 1000.0
	}
	res.ErrorsStable = res.AvgStatusCV < t.StatusCVMax

	// --- ⑤ 方法语义 ---
	getN := methodCount['G']
	postN := methodCount['P']
	putN := methodCount['U']
	delN := methodCount['D']
	patchN := methodCount['O']
	res.GetRatio = float64(getN) / float64(total)
	res.PostRatio = float64(postN) / float64(total)
	res.UnusualRatio = float64(putN+delN+patchN) / float64(total)
	methodNatural := false
	if res.GetRatio >= t.GetRatioMin && res.GetRatio <= t.GetRatioMax &&
		res.PostRatio >= t.PostRatioMin && res.PostRatio <= t.PostRatioMax &&
		res.UnusualRatio < t.UnusualMax {
		methodNatural = true
	}
	if res.GetRatio >= t.PureAPIGetMax && res.UnusualRatio < 0.01 {
		methodNatural = true
	}
	if res.PostRatio >= t.PureAPIPostMin && res.GetRatio > 0.01 && res.UnusualRatio < t.UnusualMax {
		methodNatural = true
	}
	res.MethodNatural = methodNatural

	// --- 反信号 ---
	// 反信号 1: 动态路径反复撞墙 ≥ threshold 次且全错；公共探测路径阈值更高
	topPathsAll := topKStrings(pathCount, 5)
	alwaysSameError := false
	for _, p := range topPathsAll {
		cnt := pathCount[p]
		bare := p
		if i := strings.Index(bare, "?"); i >= 0 {
			bare = bare[:i]
		}
		var threshold int
		switch {
		case commonProbeRe.MatchString(bare):
			threshold = t.AlwaysErrorProbeMin
		case staticExtRe.MatchString(bare):
			continue // 静态资源永远跳过
		default:
			threshold = t.AlwaysErrorDynamicMin
		}
		if cnt < threshold {
			continue
		}
		sts := pathStatuses[p]
		allBad := true
		for _, s := range sts {
			if s < 400 {
				allBad = false
				break
			}
		}
		if allBad {
			alwaysSameError = true
			break
		}
	}
	res.AlwaysSameError = alwaysSameError

	// 反信号 2: 新颖度高度发散 = 扫描器特征
	// 合法 API 客户端的路径也可能 batch 写入导致 noveltyEarly30 低，
	// 但它们的 Top5 覆盖极高。发散 + 低覆盖 = 每条路径只扫一两次的扫描器
	highlyNovel := res.NoveltyEarly30 < t.HighlyNovelEarlyMax &&
		res.LateNoveltyRate > t.HighlyNovelLateMin &&
		res.Top5Cover < t.HighlyNovelCoverMax

	// --- 加权汇总 ---
	score := 0
	if res.PrefixCoherent {
		score += t.WeightPrefix
	}
	if res.NoveltyConverged {
		score += t.WeightNovelty
	}
	if res.PathConcentrated {
		score += t.WeightPathConc
	}
	if res.ErrorsStable {
		score += t.WeightErrors
	}
	if res.MethodNatural {
		score += t.WeightMethod
	}
	if alwaysSameError {
		score -= t.AlwaysErrorScorePenalty
	}
	if len(pathCount) < 3 && alwaysSameError {
		score -= t.SinglePathErrorBonus
	}
	// 新颖度高度发散 → 额外扣分（捕获每条路径只扫一次的发散型扫描器）
	if highlyNovel {
		score -= t.HighlyNovelPenalty
	}

	res.Score = score
	res.IsBenign = score >= t.ScoreThreshold
	return res
}

// topKStrings 返回 map 中 value 最大的 K 个 key。
func topKStrings(m map[string]int, k int) []string {
	type kv struct {
		key string
		val int
	}
	list := make([]kv, 0, len(m))
	for kk, vv := range m {
		list = append(list, kv{kk, vv})
	}
	// 降序排序
	for i := 0; i < len(list); i++ {
		for j := i + 1; j < len(list); j++ {
			if list[j].val > list[i].val {
				list[i], list[j] = list[j], list[i]
			}
		}
	}
	if k > len(list) {
		k = len(list)
	}
	out := make([]string, k)
	for i := 0; i < k; i++ {
		out[i] = list[i].key
	}
	return out
}

// --- SlidingWindow 集成方法 ---

// AppendPathRecord 给 ipEntry 的 pathHistory 追加一条请求记录。
// 在 Record 流程中调用，和 counters 记录并行。
func (e *ipEntry) appendPathRecord(path, method string, status int) {
	if e.pathHistory == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.pathHistory.append(path, method, status)
}

// ComputeConsistency 对指定 IP 计算 Consistency 分数。
// 加 ipEntry.mu Lock 保护（ipEntry.mu 是 sync.Mutex，不能 RLock）。
// 返回的 ScoreResult 是值类型，调用方持有副本。
// 使用 SlidingWindow.thresholds（由 DetectorCfg.Consistency 注入）。
func (w *SlidingWindow) ComputeConsistency(ip string) ConsistencyScoreResult {
	w.mu.RLock()
	e, ok := w.ips[ip]
	t := w.consistencyThresholds
	w.mu.RUnlock()
	if !ok {
		return ConsistencyScoreResult{}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.pathHistory == nil {
		return ConsistencyScoreResult{}
	}
	return e.pathHistory.Score(t)
}
