package detector

import "time"

func SetBaselinesForTest(det *LocalDetector, dims [3]BaselineDimensions) {
	if det == nil || det.scorer == nil {
		return
	}
	for i := 0; i < 3; i++ {
		bl := det.scorer.baselines[i]
		if bl == nil {
			continue
		}
		bl.mu.Lock()
		bl.dims = dims[i]
		bl.sampleCount = 9999
		bl.startAt = time.Now().Add(-10 * time.Minute)
		bl.mu.Unlock()
	}
}

func MakeMediumBaselineDims(windowSec int) BaselineDimensions {
	qpsP95 := 100.0
	if windowSec > 0 {
		qpsP95 = 100.0 / float64(windowSec)
	}
	// P50 = P95 * 0.8 模拟稳定站点（demo 数据 P50/P95=62/73=0.85）。
	// 动态 threshold 公式基于 P95/P50 波动比 R = P95/P50 ≈ 1.25。
	// sens1 (新 IP) threshold ≈ 1.5, sens2 ≈ 2.0, sens3 ≈ 3.1
	return BaselineDimensions{
		QPS:          Percentile{P50: qpsP95 * 0.8, P95: qpsP95, P99: qpsP95 * 2, N: 100},
		ReqInterval:  Percentile{},
		Rate4xx:      Percentile{P50: 0.02, P95: 0.05, P99: 0.10, N: 100},
		Rate5xx:      Percentile{P50: 0.0, P95: 0.02, P99: 0.05, N: 100},
		Rate404:      Percentile{P50: 0.01, P95: 0.03, P99: 0.08, N: 100},
		RateAuthFail: Percentile{P50: 0.0, P95: 0.01, P99: 0.03, N: 100},
		RateSensPath: Percentile{P50: 0.0, P95: 0.01, P99: 0.03, N: 100},
		RateBotUA:    Percentile{P50: 0.0, P95: 0.02, P99: 0.05, N: 100},
		RateEmptyRef: Percentile{P50: 0.1, P95: 0.3, P99: 0.5, N: 100},
	}
}

func MakeMediumBaselines() [3]BaselineDimensions {
	return [3]BaselineDimensions{
		MakeMediumBaselineDims(10),
		MakeMediumBaselineDims(30),
		MakeMediumBaselineDims(60),
	}
}
