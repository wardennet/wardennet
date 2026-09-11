// Package detector - scorer.go 依据三档窗口计数 + 基线偏差 + 固定权重计算 LocalRiskScore。
// 设计：
//   - 取三档窗口中最高分的那档作为最终 LocalRiskScore（任一窗口异常即敏感）；
//   - 相对特征（QPS/4xx 比率等）基于偏离基线 P95 的倍数评分；
//   - 绝对特征（危险模式/危险方法/文件上传）用固定权重评分；
//   - 分数上限 = score_high * 2，避免异常日志导致整数溢出；
//   - 支持 IP 级基线（qpsEMA + seenCount）动态调整敏感度；
//   - 空 Referer 防误杀：单独触发时降级 + 硬上限 score_high/4；
//   - legitimateUserContext + concentrated4xx 保留。
package detector

// Scorer 打分器。持有 DetectorCfg 指针和三档窗口对应的基线引擎。
// v1.2: cfg 改为 *DetectorCfg——与 LocalDetector 共享同一份配置，便于权重热更。
type Scorer struct {
	cfg       *DetectorCfg
	baselines [3]*Baseline
}

// NewScorer 基于配置指针与三档基线创建打分器。
func NewScorer(cfg *DetectorCfg, baselines [3]*Baseline) *Scorer {
	return &Scorer{cfg: cfg, baselines: baselines}
}

// ScoreResult 打分结果，包含各维度详情。
type ScoreResult struct {
	FinalScore int            // 最终分数（三档最高）
	Details    [3]ScoreDetail // 三档窗口各自的详情
}

// ScoreWithDetail 计算分数并返回各维度详情。
// ipQpsEMA 为该 IP 的历史 QPS 指数移动平均；ipSeenCount 为该 IP 被记录的次数。
// 用于 per-IP 与全局基线双轨偏差判定。
func (s *Scorer) ScoreWithDetail(counters [3]WindowCounters, ipQpsEMA float64, ipSeenCount int) ScoreResult {
	high := s.cfg.ScoreHigh
	ceiling := high * 2
	if ceiling < 0 {
		ceiling = 0
	}
	w := s.cfg.Weights
	best := 0
	var result ScoreResult

	for i := 0; i < 3; i++ {
		c := counters[i]
		bl, baselineConf := s.baselines[i].GetWithConfidence()
		winSec := s.baselines[i].windowSec

		effSens := getEffectiveSensitivity(ipSeenCount, s.cfg.Sensitivity)
		// 动态 threshold：从 baseline 自身统计特征推导，理解站点波动稳定性
		dynThresholds := s.baselines[i].Thresholds()
		dynThreshold := dynThresholds[effSens-1] // effSens ∈ {1,2,3} → index {0,1,2}
		dynGuardQPS := s.baselines[i].GuardQPS()

		detail := ScoreDetail{
			WindowIndex:            i,
			WindowSec:              winSec,
			EffectiveSensitivity:   effSens,
			BaselineConfidence:     baselineConf,
			TotalReq:               c.TotalReq,
			Count4xx:               c.Count4xx,
			Count401:               c.Count401,
			Count5xx:               c.Count5xx,
			Count404:               c.Count404,
			AuthFail:               c.AuthFail,
			SensitivePathHit:       c.SensitivePathHit,
			DangerousPatternHit:    c.DangerousPatternHit,
		PathTraversalHit:       c.PathTraversalHit,
			BotUAHit:               c.BotUAHit,
			EmptyRefererHit:        c.EmptyRefererHit,
			DangerousMethod:        c.DangerousMethod,
			HeadMethod:             c.HeadMethod,
			StaticResHit:           c.StaticResHit,
			NormalBrowserHit:       c.NormalBrowserHit,
			Distinct4xxPaths:       c.Distinct4xxPaths,
			FileUploadBlockedCount: c.FileUploadBlocked,
		}

		sc := 0

		// ---------- 相对特征：基线偏差评分 ----------

		qpsVal := float64(c.TotalReq) / float64(winSec)
		qpsDev := deviation(qpsVal, bl.QPS)
		if ipSeenCount > 20 && ipQpsEMA > 0 {
			if perIPDev := qpsVal / ipQpsEMA; perIPDev > qpsDev {
				qpsDev = perIPDev
			}
		}
		qpsScore := 0
		if c.TotalReq >= 5 {
			qpsScore = deviationToScore(qpsDev, dynThreshold)
		}
		// ---------- QPS 偏离分打折机制 ----------
		// 1. 基线置信度不足 → QPS 分打 5 折（保守策略：宁可放过不要误杀）
		if qpsScore > 0 && baselineConf < CONFIDENCE_MIN_FOR_SCORE {
			qpsScore = qpsScore * 5 / 10
			detail.QPSConfidenceMitigated = true
		}
		// 2. 纯 QPS 尖峰且无攻击特征 → QPS 分再打 3 折
		//    （有 DangerousPattern/BotUA/DangerousMethod/FileUpload 就不打折，
		//     因为真实攻击通常伴随至少一个攻击特征）
		if qpsScore > 0 && baselineConf >= CONFIDENCE_MIN_FOR_SCORE {
			hasAttackFeature := (c.DangerousPatternHit > 0 || c.BotUAHit > 0 || c.PathTraversalHit > 0 ||
				c.DangerousMethod > 0 || c.FileUploadBlocked > 0)
			if !hasAttackFeature {
				qpsScore = qpsScore * 3 / 10
				detail.QPSPureSpikeMitigated = true
			}
		}
		detail.QPSDeviation = qpsDev

		rate4xx := ratio(c.Count4xx, c.TotalReq)
		rate4xxDev := deviation(rate4xx, bl.Rate4xx)
		rate4xxScore := 0
		if c.TotalReq >= 5 {
			rate4xxScore = deviationToScore(rate4xxDev, dynThreshold)
		}
		detail.Status4xxDeviation = rate4xxDev

		rate5xx := ratio(c.Count5xx, c.TotalReq)
		rate5xxDev := deviation(rate5xx, bl.Rate5xx)
		rate5xxScore := 0
		if c.TotalReq >= 5 {
			rate5xxScore = deviationToScore(rate5xxDev, dynThreshold)
		}
		detail.Status5xxDeviation = rate5xxDev

		rate404 := ratio(c.Count404, c.TotalReq)
		rate404Dev := deviation(rate404, bl.Rate404)
		rate404Score := 0
		if c.TotalReq >= 5 {
			rate404Score = deviationToScore(rate404Dev, dynThreshold)
		}
		detail.Status404Deviation = rate404Dev

		// v0.9: 认证失败合并评分通道
		//   Count401 — HTTP 401 状态码（nginx access.log 源，session/token 过期或暴力破解）
		//   AuthFail — linux_auth 源认证失败事件（SSH/系统登录）
		// 两者语义相近（"认证相关失败"），合并成一个维度统一评分。
		// window.go 已把 401 从 Count4xx 排除，所以 Count4xx 是纯净的攻击型 4xx。
		totalAuthFail := c.Count401 + c.AuthFail
		rateAuthFail := ratio(totalAuthFail, c.TotalReq)
		rateAuthFailDev := deviation(rateAuthFail, bl.RateAuthFail)
		authFailScore := 0
		if c.TotalReq >= 5 {
			authFailScore = deviationToScore(rateAuthFailDev, dynThreshold)
		}
		detail.AuthFailDeviation = rateAuthFailDev

		rateSens := ratio(c.SensitivePathHit, c.TotalReq)
		rateSensDev := deviation(rateSens, bl.RateSensPath)
		sensScore := 0
		if c.TotalReq >= 5 {
			sensScore = deviationToScore(rateSensDev, dynThreshold)
		}
		detail.SensitivePathDeviation = rateSensDev

		rateBotUA := ratio(c.BotUAHit, c.TotalReq)
		rateBotUADev := deviation(rateBotUA, bl.RateBotUA)
		botUAScore := 0
		if c.TotalReq >= 5 {
			botUAScore = deviationToScore(rateBotUADev, dynThreshold)
		}
		detail.BotUADeviation = rateBotUADev

		rateEmptyRef := ratio(c.EmptyRefererHit, c.TotalReq)
		rateEmptyRefDev := deviation(rateEmptyRef, bl.RateEmptyRef)
		emptyRefScore := 0
		if c.TotalReq >= 5 {
			emptyRefScore = deviationToScore(rateEmptyRefDev, dynThreshold)
		}
		detail.EmptyRefererDeviation = rateEmptyRefDev

		// HEAD 请求比率：相对特征评分。
		// 走基线偏离（deviationToScore），站点基线 HEAD 天生多（FineReport/CDN）→ 自动压低分数。
		// 非致命：不进 noFatalAttack / hasAttackFeature / computeHighConfidence。
		rateHeadMethod := ratio(c.HeadMethod, c.TotalReq)
		rateHeadMethodDev := deviation(rateHeadMethod, bl.RateHeadMethod)
		headMethodScore := 0
		if c.TotalReq >= 5 {
			headMethodScore = deviationToScore(rateHeadMethodDev, dynThreshold)
		}
		detail.HeadMethodDeviation = rateHeadMethodDev

		// ---------- 绝对特征：固定权重评分 ----------

		dangerPatternScore := 0
		if c.DangerousPatternHit > 0 {
			dangerPatternScore = int(c.DangerousPatternHit) * w.DangerousPattern
			maxDanger := high / 2
			if dangerPatternScore > maxDanger {
				dangerPatternScore = maxDanger
			}
		}

		// v1.3: 路径遍历攻击意图评分
		// 独立于 DangerousPatternHit 的 clean 后 decode 匹配，
		// 这个维度是 clean 前捕获的原始穿越特征，覆盖所有编码和反斜杠穿越。
		// 使用与 DangerousPattern 相同的权重（都是强绝对攻击特征）。
		pathTraversalScore := 0
		if c.PathTraversalHit > 0 {
			pathTraversalScore = int(c.PathTraversalHit) * w.DangerousPattern
			capTraversal := high / 2
			if pathTraversalScore > capTraversal {
				pathTraversalScore = capTraversal
			}
		}

		dangerMethodScore := 0
		if c.DangerousMethod > 0 {
			dangerMethodScore = int(c.DangerousMethod) * w.DangerousMethod
			methodCap := 3 * w.DangerousMethod
			if dangerMethodScore > methodCap {
				dangerMethodScore = methodCap
			}
		}

		fileUploadScore := 0
		if c.FileUploadBlocked > 0 {
			fileUploadScore = int(c.FileUploadBlocked) * w.FileUpload
			if fileUploadScore > high {
				fileUploadScore = high
			}
		}

		// ---------- 真实用户奖励（扣分项） ----------
		// 基础：每个静态资源请求 +3 分（真实用户特征，比原来 *2 更重）
		//       每个有效 Referer +1 分（合法浏览器带 Referer）
		validReferer := c.TotalReq - c.EmptyRefererHit
		bonus := int(c.StaticResHit)*3 + int(validReferer)

		// P1-1 强化：纯浏览器 + 有静态资源 → 404 主要是浏览器自动探测 demo 路径/favicon，
		// 不应计入攻击。把 Count404 按 50% 比例额外扣 bonus。
		if c.TotalReq > 0 {
			bp := float64(c.NormalBrowserHit) / float64(c.TotalReq)
			if bp >= 0.95 && c.BotUAHit == 0 && c.StaticResHit > 0 {
				// 静态资源 404（demo.js / demo.css / favicon 等）+ 正常浏览器 = 正常行为
				// Count404 里大约 50% 是这种，直接扣 bonus
				bonus += int(float64(c.Count404) * 0.5)
			}
		}

		// ---------- legitimateUserContext ----------
		// 核心思想：如果 IP 的绝大多数请求（>= 95%）来自正常浏览器，
		// 那零星的 BotUA / SensPath / AuthFail 只是噪音（嵌入浏览器、
		// 客户端 API 请求、偶尔密码输错等），不应阻止 legit 触发。
		// 只有"致命攻击特征"（DangerousPatternHit / DangerousMethod /
		// FileUploadBlocked）必须为零——正常浏览器真的不可能触发这些。

		// 1. 致命攻击特征：正常浏览器用户不可能触发，必须为零
		noFatalAttack := (c.DangerousPatternHit == 0 &&
			c.DangerousMethod == 0 &&
			c.FileUploadBlocked == 0 &&
			c.PathTraversalHit == 0)

		// 2. 噪音容忍：根据浏览器纯净度动态调整
		noAttackFeature := false
		if noFatalAttack {
			bp := float64(c.NormalBrowserHit) / float64(c.TotalReq)
			totalAuthFail := int64(c.Count401) + c.AuthFail
			if bp >= 0.95 {
				// 浏览器占 >= 95%：容忍低比例噪音（每个维度都 < 3% 且绝对值 <= 5）
				// 2% 比例 + 绝对上限 5，防止低样本时比例波动
				noAttackFeature = (
					ratio(int64(c.BotUAHit), c.TotalReq) <= 0.03 && int(c.BotUAHit) <= 5 &&
						ratio(int64(c.SensitivePathHit), c.TotalReq) <= 0.02 && int(c.SensitivePathHit) <= 3 &&
						ratio(totalAuthFail, c.TotalReq) <= 0.02 && totalAuthFail <= 3)
			} else {
				// 浏览器占比不够高（可能是扫描器/爬虫/混合流量）：保持严格
				noAttackFeature = (c.BotUAHit == 0 && c.SensitivePathHit == 0 && totalAuthFail == 0)
			}
		}

		legitimateUserContext := false
		if c.NormalBrowserHit > 0 && c.TotalReq >= 3 && noAttackFeature {
			// legitimateUserContext 在中等偏差时触发降权，
			// 仅在极端偏差（>= threshold*5）时不触发（大概率真实攻击）。
			luThreshold := []float64{40, 100, 200}[effSens-1]
			if qpsDev < luThreshold && rate4xxDev < luThreshold && rate404Dev < luThreshold {
				legitimateUserContext = true
			}
		}
		detail.LegitimateUserContext = legitimateUserContext

		// ---------- concentrated4xx ----------
		concentrated4xx := false
		if c.Distinct4xxPaths > 0 && c.Distinct4xxPaths <= 2 &&
			c.NormalBrowserHit == 0 && c.BotUAHit == 0 {
			if rate4xxScore > 0 || rate4xxDev >= 1 {
				concentrated4xx = true
			}
		}
		detail.Concentrated4xxMitigated = concentrated4xx

		// ---------- 降权（对原始分生效） ----------
		// legitimateUserContext: 强降权（90%），因为"浏览器+无攻击特征+有效Referer"的信号远超"基线异常"
		final4xxScore := rate4xxScore
		if legitimateUserContext && final4xxScore > 0 {
			final4xxScore = final4xxScore / 10
			detail.Status4xxLegMitigated = true
		}
		if concentrated4xx && final4xxScore > 0 {
			final4xxScore = final4xxScore * 5 / 10
		}
		final404Score := rate404Score
		if legitimateUserContext && final404Score > 0 {
			final404Score = final404Score / 10
			detail.Status404LegMitigated = true
		}

		// ---------- 多维度协同评分架构 ----------
		// 核心原则：没有任何单一相对维度能独立触发封禁。
		// 必须有多个维度同时异常，或有绝对攻击特征（危险模式/文件上传） corroborate。
		//
		// v1.4 status 维度合并：
		//   把 4 个 status 相对维度（Rate4xx, Rate404, RateAuthFail, Rate5xx）
		//   合并为 1 个"status anomaly"维度。原因：
		//   - 正常用户 token 过期 → 1 个 401 + 浏览器加载不存在的 js → 1 个 404
		//     如果 401 和 404 各算一个维度 → dims=2 → 绕过 SingleDimCapped → 触发 is_high
		//     合并后 → dims=1 → SingleDimCapped 生效 → 封顶 ScoreMedium → 不触发封禁
		//   - 扫描器撞几十个不同 404 → 合并后 status anomaly 比率本身就很高，
		//     deviationToScore 给高分，再叠加 QPS/BotUA/SensPath 其他维度 → dims≥2
		//     合并不会降低攻击检测能力，只是消除了"不同类型 4xx 恰好各出现 1 次"的人为放大。

		// 1. 单维度上限：每个相对维度最多贡献 ScoreHigh × 60%
		relCap := high * 6 / 10
		if qpsScore > relCap {
			qpsScore = relCap
		}
		if final4xxScore > relCap {
			final4xxScore = relCap
		}
		if rate5xxScore > relCap {
			rate5xxScore = relCap
		}
		if authFailScore > relCap {
			authFailScore = relCap
		}
		if final404Score > relCap {
			final404Score = relCap
		}
		if sensScore > relCap {
			sensScore = relCap
		}
		if botUAScore > relCap {
			botUAScore = relCap
		}
		if headMethodScore > relCap {
			headMethodScore = relCap
		}

		// 2. 空 Referer 防误杀（保留原有逻辑，但也受 relCap 约束）
		// thr 复用动态 threshold（已经在循环开头算好了）
		thr := dynThreshold
		// v1.4: status 4 个 deviation 合并——取 max 作为 statusAnomalyDev
		// 因为 hasCorroborating 是"有没有其他维度佐证"，语义是"status 有没有异常"，
		// 不是"几个 status 子类型同时异常"。
		statusAnomalyDev := rate4xxDev
		if rate404Dev > statusAnomalyDev {
			statusAnomalyDev = rate404Dev
		}
		if rateAuthFailDev > statusAnomalyDev {
			statusAnomalyDev = rateAuthFailDev
		}
		if rate5xxDev > statusAnomalyDev {
			statusAnomalyDev = rate5xxDev
		}
		hasCorroborating := (qpsDev >= thr ||
			statusAnomalyDev >= thr ||
			rateSensDev >= thr ||
			rateBotUADev >= thr ||
			dangerPatternScore > 0 || dangerMethodScore > 0)

		emptyRefFinal := 0
		if emptyRefScore > 0 {
			var pts int
			if hasCorroborating {
				pts = emptyRefScore
				detail.EmptyRefererMitigated = false
			} else {
				pts = emptyRefScore / 5
				detail.EmptyRefererMitigated = true
			}
			maxPts := high / 4
			if c.TotalReq >= 5 && c.Count404 > 0 {
				ratio404 := int(c.Count404) * 100 / int(c.TotalReq)
				if ratio404 >= 50 {
					maxPts = high / 2
					detail.EmptyRefererSynergy404 = true
					detail.EmptyReferer404Ratio = ratio404
				}
			}
			if pts > maxPts {
				pts = maxPts
			}
			if pts > relCap {
				pts = relCap
			}
			emptyRefFinal = pts
			detail.EmptyRefererScore = pts
		}

		// 3. 统计活跃相对维度数
		activeRelDims := 0
		if qpsScore > 0 {
			activeRelDims++
		}
		// v1.4: 4 个 status 子维度合并为 1 个 status anomaly 维度
		// 正常用户 1 个 401 + 1 个 404 → 原来 dims+=2 → 绕 SingleDimCapped
		// 现在 dims+=1 → SingleDimCapped 生效 → 封顶 ScoreMedium
		statusRelDims := 0
		if final4xxScore > 0 || final404Score > 0 || authFailScore > 0 || rate5xxScore > 0 {
			statusRelDims = 1
		}
		activeRelDims += statusRelDims
		if sensScore > 0 {
			activeRelDims++
		}
		if botUAScore > 0 {
			activeRelDims++
		}
		if emptyRefFinal > 0 {
			activeRelDims++
		}
		if headMethodScore > 0 {
			activeRelDims++
		}

		// ---------- 活跃度保护（Activity Guard）----------
		// 活跃扫描器的 QPS 不可能低于 0.3（60s 至少 18 个请求）。
		// 低于此阈值时，所有相对基线偏离（4xx/404/QPS 偏离等）都是噪音——
		// 5 个请求算 60% 4xx 率没有任何统计意义。
		//
		// 动态化：guardQPS 从 baseline 推导（P95 × 0.02，最低 0.05）。
		// 小站点 guard 不会大到误伤正常流量，大站点 guard 也不会永远不触发。
		//
		// 保护策略（只压相对噪音，不动绝对攻击特征）：
		//   - 所有相对维度分数清零（它们的输入只有低样本率，全是噪音）
		//   - 绝对攻击特征（DangerousPattern/PathTraversal/DangerousMethod/FileUpload）
		//     原样保留——慢扫描器的 SQLi/XSS/路径遍历都是实打实的攻击信号
		//   - 弱攻击封顶：如果绝对特征总分也低于 ScoreMedium（即没有强攻击信号），
		//     总分封顶 ScoreMedium（仅告警不封禁）。
		//     如果绝对特征 ≥ ScoreMedium（比如多次 DangerousPattern 命中），
		//     说明虽慢但确实在搞事，允许完整 ScoreHigh 触发封禁。
		isInactive := qpsVal < dynGuardQPS
		if isInactive {
			// 相对维度全部清零（基于低样本率的偏离都是噪音）
			qpsScore = 0
			final4xxScore = 0
			rate5xxScore = 0
			authFailScore = 0
			final404Score = 0
			sensScore = 0
			botUAScore = 0
			emptyRefFinal = 0
			headMethodScore = 0
			// 注意：绝对攻击特征不动（DangerousPattern 等是真实信号）
			activeRelDims = 0
			detail.InactivityMitigated = true
		}

		// 4. 汇总相对维度分数
		relScore := qpsScore + final4xxScore + rate5xxScore + authFailScore +
			final404Score + sensScore + botUAScore + emptyRefFinal + headMethodScore

		// 5. 绝对特征分数（不受 relCap 和单维度限制）
		absScore := dangerPatternScore + dangerMethodScore + fileUploadScore + pathTraversalScore

		// 6. 单维度封顶：只有一个相对维度异常且无绝对特征 → 封顶 ScoreMedium
		//    防止 QPS 偏离或 404 偏离单独触发封禁
		relCapped := false
		if activeRelDims <= 1 && absScore == 0 {
			if relScore > s.cfg.ScoreMedium {
				relScore = s.cfg.ScoreMedium
				relCapped = true
			}
		}

		// P2-1: 组合触发提升 — BotUA + 多敏感路径是典型扫描器组合。
		// 即便基线里 BotUA 有一些噪音（比如业务侧定时 curl 探活），
		// 真实扫描器会同时触发 BotUA（Nmap/nmap scripting）和多个敏感路径（HNAP1/evox/about/ckeditor/...）。
		// 这两个组合信号比单一 BotUA 或单一 SensPath 可靠得多。
		if c.BotUAHit > 0 && c.SensitivePathHit >= 3 {
			// 强制提升 BotUA 和 SensPath 的绝对分数，各自至少 relCap 的 60%
			minSynergyScore := relCap * 60 / 100
			if botUAScore < minSynergyScore {
				botUAScore = minSynergyScore
			}
			if sensScore < minSynergyScore {
				sensScore = minSynergyScore
			}
		}

		// P1-1: legitimateUserContext 再强化 bonus — 降权已经做了（rate4xxScore/rate404Score 降 10 倍），
		// bonus 再额外翻 1.5 倍，确保"浏览器 + 静态资源 + 无攻击特征"的场景绝对不会误报。
		if legitimateUserContext && bonus > 0 {
			bonus = bonus * 15 / 10
		}

		// 7. 总分 = 相对维度（可能被封顶）+ 绝对特征 - 真实用户奖励
		sc = relScore + absScore - bonus

		// 7.1 活跃度保护弱攻击封顶：
		//    非活跃场景下，如果绝对特征分也低于 ScoreMedium（即没有强攻击信号），
		//    说明只是"低样本噪音+随机误匹配"——封顶 ScoreMedium，仅告警不封禁。
		//    但如果绝对特征 ≥ ScoreMedium（多次 DangerousPattern/PathTraversal/FileUpload），
		//    说明虽慢但确实在搞事——允许完整 ScoreHigh 触发封禁。
		if isInactive && absScore < s.cfg.ScoreMedium && sc > s.cfg.ScoreMedium {
			sc = s.cfg.ScoreMedium
		}

		// 记录各维度明细
		detail.QPSScore = qpsScore
		detail.Status4xxScore = final4xxScore
		detail.Status5xxScore = rate5xxScore
		detail.AuthFailScore = authFailScore
		detail.Status404Score = final404Score
		// v1.4: status anomaly 聚合分数（方便日志和下游消费）
		detail.StatusAnomalyScore = final4xxScore + final404Score + authFailScore + rate5xxScore
		detail.SensitivePathScore = sensScore
		detail.DangerousPatternScore = dangerPatternScore
		detail.PathTraversalScore = pathTraversalScore
		detail.BotUAScore = botUAScore
		detail.DangerousMethodScore = dangerMethodScore
		detail.HeadMethodScore = headMethodScore
		detail.FileUploadScore = fileUploadScore
		detail.RealUserBonus = -bonus
		detail.SingleDimCapped = relCapped
		detail.ActiveRelDims = activeRelDims

		detail.TotalScore = sc
		result.Details[i] = detail

		if sc > best {
			best = sc
		}
	}

	if best > ceiling {
		best = ceiling
	}
	if best < 0 {
		best = 0
	}

	// ---------- 低置信度永不封禁 ----------
	// 如果三档窗口的基线置信度全都不够，说明基线严重不可信（比如 Preload 全是凌晨低峰数据）。
	// 此时就算分数到了 ScoreHigh，也降级到 ScoreHigh-1，防止误杀。
	// 一旦有任意一档窗口的 baseline 置信度达标，就解除限制。
	if best >= s.cfg.ScoreHigh && s.cfg.ScoreHigh > 0 {
		anyConfident := false
		for j := 0; j < 3; j++ {
			if s.baselines[j].IsConfident(CONFIDENCE_MIN_FOR_BLOCK) {
				anyConfident = true
				break
			}
		}
		if !anyConfident {
			best = s.cfg.ScoreHigh - 1
		}
	}

	result.FinalScore = best
	return result
}

// Score 便捷方法，等价于 ScoreWithDetail(counters, 0, 0).FinalScore。
// 用于不需要 IP 级动态敏感度的场景（如纯窗口基线测试）。
func (s *Scorer) Score(counters [3]WindowCounters, ipQpsEMA float64, ipSeenCount int) int {
	return s.ScoreWithDetail(counters, ipQpsEMA, ipSeenCount).FinalScore
}

// IsHigh 返回分数是否达到本地拉黑候选阈值。
func (s *Scorer) IsHigh(score int) bool {
	return score >= s.cfg.ScoreHigh && s.cfg.ScoreHigh > 0
}



