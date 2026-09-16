package detector

import (
	"regexp"
	"sync"
	"time"
)

// ResourcePattern 资源基线模式：检测同一 IP 是否在短时间内遍历了过多
// 不同的资源 ID（典型的 IDOR/BOLA 横向越权特征）。
//
// 两个正则配合工作：
//   path_regex — 先用整个路径匹配，筛选出"这个路径是我们关心的 API"
//   id_regex   — 从路径（含可选 query string）中提取资源 ID
// 两个正则都匹配成功才认为这个请求参与计数。
type ResourcePattern struct {
	PathRegex string `yaml:"path_regex"` // 匹配 API 路径（不含 query string）
	IDRegex   string `yaml:"id_regex"`   // 提取资源 ID 的正则（需有至少一个捕获组）
	WindowSec int    `yaml:"window_sec"` // 观察窗口（秒）
	MaxIDs    int    `yaml:"max_ids"`    // 允许的不同 ID 上限
	Weight    int    `yaml:"weight"`     // 命中后的风险贡献分
}

// compiledPattern 预编译的正则 + pattern 配置。
type compiledPattern struct {
	cfg       ResourcePattern
	pathRe    *regexp.Regexp
	idRe      *regexp.Regexp
	windowSec int
	maxIDs    int
	weight    int
}

// resourceWindow 单个 IP × 单个 pattern 的资源 ID 状态。
// ids map 记录 "见过哪些 ID"，不记录每个 ID 的访问次数（只需 distinct count）。
type resourceWindow struct {
	ids     map[string]int64 // id → 首次访问时间戳（用于窗口过期判断）
	window  int              // 窗口大小（秒）
	maxIDs  int              // 触发阈值
	weight  int              // 命中贡献分
}

// ResourceBaseline IDOR/BOLA 越权检测器。
// 设计为增强型可选功能：默认关闭（enabled=false），用户按需配置自己关心的 API。
// 完全配置驱动，path_regex 不匹配的路径静默跳过，id_regex 无提取也静默跳过。
//
// 零跨包依赖，纯 stdlib（regexp / sync / time）。
type ResourceBaseline struct {
	enabled  bool
	patterns []ResourcePattern
	compiled []*compiledPattern
	windows  map[string][]*resourceWindow // key: srcIP → 每个 pattern 一个窗口
	mu       sync.RWMutex
	stop     chan struct{}
	once     sync.Once
}

// NewResourceBaseline 创建 ResourceBaseline。
// enabled=false 或 patterns 为空时，Check() 永远返回 (false, 0)，零开销。
func NewResourceBaseline(enabled bool, patterns []ResourcePattern) *ResourceBaseline {
	rb := &ResourceBaseline{
		enabled:  enabled,
		patterns: patterns,
		windows:  make(map[string][]*resourceWindow),
		stop:     make(chan struct{}),
	}
	if !enabled || len(patterns) == 0 {
		return rb
	}
	// 预编译所有正则（启动时一次性完成，不放在热路径）
	rb.compiled = make([]*compiledPattern, 0, len(patterns))
	for _, p := range patterns {
		if p.PathRegex == "" || p.IDRegex == "" {
			continue
		}
		pathRe, err := regexp.Compile(p.PathRegex)
		if err != nil {
			continue // 编译失败的 pattern 静默跳过
		}
		idRe, err := regexp.Compile(p.IDRegex)
		if err != nil {
			continue
		}
		windowSec := p.WindowSec
		if windowSec <= 0 {
			windowSec = 60
		}
		maxIDs := p.MaxIDs
		if maxIDs <= 0 {
			maxIDs = 20
		}
		weight := p.Weight
		if weight < 0 {
			weight = 15
		}
		rb.compiled = append(rb.compiled, &compiledPattern{
			cfg:       p,
			pathRe:    pathRe,
			idRe:      idRe,
			windowSec: windowSec,
			maxIDs:    maxIDs,
			weight:    weight,
		})
	}

	// 启动清理 goroutine（只有有 patterns 时才需要）
	if len(rb.compiled) > 0 {
		go rb.evictLoop(30 * time.Second)
	}
	return rb
}

// Close 停止清理 goroutine。
func (rb *ResourceBaseline) Close() {
	rb.once.Do(func() { close(rb.stop) })
}

func (rb *ResourceBaseline) evictLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-rb.stop:
			return
		case <-ticker.C:
			rb.Evict()
		}
	}
}

// Evict 清理过期的资源窗口。
func (rb *ResourceBaseline) Evict() {
	now := time.Now().Unix()
	rb.mu.Lock()
	defer rb.mu.Unlock()

	for ip, windows := range rb.windows {
		allEmpty := true
		for _, w := range windows {
			cutoff := now - int64(w.window)
			for id, ts := range w.ids {
				if ts <= cutoff {
					delete(w.ids, id)
				}
			}
			if len(w.ids) > 0 {
				allEmpty = false
			}
		}
		if allEmpty {
			delete(rb.windows, ip)
		}
	}
}

// Check 检查 (srcIP, path) 是否触发了某个 pattern 的 IDOR 阈值。
// 返回 (hit, score)：
//   hit = true  → 至少一个 pattern 的 distinct IDs > MaxIDs
//   score       → 所有命中的 pattern 的 weight 之和
//
// 短路逻辑：
//   - !enabled → 返回 (false, 0)
//   - 无 compiled patterns → 返回 (false, 0)
//   - path_regex 不匹配 → 该 pattern 跳过
//   - id_regex 无提取 → 该请求不参与该 pattern 计数
func (rb *ResourceBaseline) Check(srcIP, path string) (bool, int) {
	if !rb.enabled || len(rb.compiled) == 0 {
		return false, 0
	}
	if srcIP == "" || path == "" {
		return false, 0
	}

	nowSec := time.Now().Unix()
	var totalScore int
	hit := false

	rb.mu.RLock()
	windows, exists := rb.windows[srcIP]
	rb.mu.RUnlock()

	rb.mu.Lock()
	defer rb.mu.Unlock()

	if !exists {
		windows = make([]*resourceWindow, len(rb.compiled))
		rb.windows[srcIP] = windows
	}

	for i, cp := range rb.compiled {
		// path_regex 匹配
		if !cp.pathRe.MatchString(path) {
			continue
		}
		// id_regex 提取
		match := cp.idRe.FindStringSubmatch(path)
		if len(match) < 2 {
			continue // 没有提取到资源 ID
		}
		id := match[1]

		// 获取或创建窗口
		if windows[i] == nil {
			windows[i] = &resourceWindow{
				ids:     make(map[string]int64),
				window:  cp.windowSec,
				maxIDs:  cp.maxIDs,
				weight:  cp.weight,
			}
		}
		w := windows[i]

		// 清理过期 ID
		cutoff := nowSec - int64(w.window)
		for idKey, ts := range w.ids {
			if ts <= cutoff {
				delete(w.ids, idKey)
			}
		}

		// 记录当前 ID（只记首次时间）
		if _, exists := w.ids[id]; !exists {
			w.ids[id] = nowSec
		}

		// 检查是否超阈值
		distinct := len(w.ids)
		if distinct > w.maxIDs {
			totalScore += cp.weight
			hit = true
		}
	}

	if !hit {
		return false, 0
	}
	return true, totalScore
}

// IPCount 返回当前跟踪的 IP 数（用于统计/测试）。
func (rb *ResourceBaseline) IPCount() int {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return len(rb.windows)
}
