// Package features - manager.go Agent 特征值动态管理。
//
// 职责：
//  1. 启动后从云端拉取最新特征值（敏感路径、Bot UA、危险方法）
//  2. 特征值热替换无需重启进程，detector 读取无锁竞争
//  3. 版本号比对生效（304 响应时跳过同步，减少流量）
//  4. 同步失败时正确降级：优先使用缓存 → 回退内置默认值
//  5. 特征值上限：敏感路径 ≤ 500，Bot UA ≤ 200，防止内存膨胀
package features

import (
	"log"
	"sort"
	"sync"
	"time"
)

// FeatureCategory 特征分类。
type FeatureCategory string

const (
	CategorySensitivePath FeatureCategory = "sensitive_path"
	CategoryBotUA         FeatureCategory = "bot_ua"
	CategoryStaticResource FeatureCategory = "static_resource"
	CategoryDangerousMethod FeatureCategory = "dangerous_method"
)

// FeatureItem 单个特征条目。
type FeatureItem struct {
	Key         string `json:"key"`
	Value       string `json:"value"`
	Category    string `json:"category"`
	Description string `json:"description,omitempty"`
	Enabled     bool   `json:"enabled"`
	UpdatedAt   int64  `json:"updated_at"`
}

// SyncResponse 云端同步响应。
type SyncResponse struct {
	Status   string              `json:"status"`   // updated / not_modified
	Version  int64               `json:"version"`
	Features map[string][]string `json:"features"` // 按类别分组
	Count    int                 `json:"count"`

	// v1.2 新增：云端下发的特征库权重（可选）。
	// 由 PluginFetcher 从 plugin.FeatureResult.Weights 转换而来。
	// 非零字段表示"覆盖 Agent 本地 ScoreWeights 的该维度"。
	Weights map[string]int `json:"weights,omitempty"`
}

// FeatureFetcher 云端特征拉取接口。
// 由 cloudclient 实现，离线场景使用 NoopFetcher。
type FeatureFetcher interface {
	FetchFeatures(tenantID string, currentVersion int64) (*SyncResponse, error)
}

// NoopFetcher 空实现，返回无更新。
type NoopFetcher struct{}

func (NoopFetcher) FetchFeatures(_ string, _ int64) (*SyncResponse, error) {
	return &SyncResponse{Status: "not_modified", Version: 0}, nil
}

// DefaultFetcher 默认内置特征数据（离线/降级时使用）。
var DefaultFetcher = struct {
	SensitivePaths  []string
	BotUserAgents   []string
	StaticResources []string
	DangerousMethods []string
}{
	SensitivePaths: []string{
		"/admin", "/wp-admin", "/phpmyadmin", "/.env", "/.git",
		"/config", "/backup", "/database", "/debug", "/test",
		"/actuator", "/swagger", "/api-docs", "/monitor",
	},
	BotUserAgents: []string{
		"sqlmap", "nikto", "nmap", "masscan", "dirbuster",
		"gobuster", "wfuzz", "hydra", "metasploit", "nessus",
		"acunetix", "arachni", "skipfish", "w3af", "zap",
		"curl", "wget", "python-requests", "go-http-client",
	},
	StaticResources: []string{
		".jpg", ".png", ".gif", ".css", ".js", ".ico",
		".woff", ".ttf", ".eot", ".svg", ".webp", ".jpeg",
	},
	DangerousMethods: []string{
		"DELETE", "PUT", "PATCH", "TRACE", "CONNECT",
	},
}

// FeatureManager Agent 特征值管理器。
//
// 线程安全：所有读写通过 RWMutex 保护。
// 热替换：UpdateFromCloud 原子替换特征集，detector 无锁读取。
type FeatureManager struct {
	mu sync.RWMutex

	// fetcher 云端拉取器（可为 nil）
	fetcher FeatureFetcher

	// tenantID 租户标识
	tenantID string

	// version 当前缓存的版本号
	version int64

	// 缓存的特征值（按类别分组，使用 copy-on-write 保证无锁读）
	sensitivePaths  []string
	botUserAgents   []string
	staticResources []string
	dangerousMethods []string

	// 变更时间
	lastUpdate time.Time

	// 同步间隔
	syncInterval time.Duration

	// stop channel
	stopCh chan struct{}

	// v1.2 新增：特征库权重热更回调。
	// 由 main.go 注入 detector.SetWeights 的适配函数，避免 features 包依赖 detector 包（项目硬约束）。
	// 云端 FetchFeatures 通道同步 weights 后调用。
	weightsSetter func(pattern, method, head, upload int)
}

// NewFeatureManager 创建特征管理器。
// fetcher 为 nil 时使用 NoopFetcher（仅本地默认值）。
func NewFeatureManager(fetcher FeatureFetcher, tenantID string) *FeatureManager {
	if fetcher == nil {
		fetcher = NoopFetcher{}
	}
	m := &FeatureManager{
		fetcher:     fetcher,
		tenantID:    tenantID,
		syncInterval: 30 * time.Minute,
		stopCh:      make(chan struct{}),
	}
	// 加载默认值
	m.loadDefaults()
	return m
}

// loadDefaults 加载内置默认特征值。
func (m *FeatureManager) loadDefaults() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sensitivePaths = copyStrings(DefaultFetcher.SensitivePaths)
	m.botUserAgents = copyStrings(DefaultFetcher.BotUserAgents)
	m.staticResources = copyStrings(DefaultFetcher.StaticResources)
	m.dangerousMethods = copyStrings(DefaultFetcher.DangerousMethods)
	m.version = 0
	m.lastUpdate = time.Now()
}

// GetSensitivePaths 获取当前敏感路径列表（线程安全，无锁读）。
func (m *FeatureManager) GetSensitivePaths() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sensitivePaths
}

// GetBotUserAgents 获取当前 Bot UA 列表。
func (m *FeatureManager) GetBotUserAgents() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.botUserAgents
}

// GetStaticResources 获取当前静态资源扩展名列表。
func (m *FeatureManager) GetStaticResources() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.staticResources
}

// GetDangerousMethods 获取当前危险 HTTP 方法列表。
func (m *FeatureManager) GetDangerousMethods() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.dangerousMethods
}

// GetVersion 获取当前版本号。
func (m *FeatureManager) GetVersion() int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.version
}

// GetAll 获取所有分类别的特征值。
func (m *FeatureManager) GetAll() map[string][]string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return map[string][]string{
		"sensitive_path":  m.sensitivePaths,
		"bot_ua":          m.botUserAgents,
		"static_resource": m.staticResources,
		"dangerous_method": m.dangerousMethods,
	}
}

// SyncFromCloud 从云端同步特征值。
//
// 返回：
//   - updated: 是否有新更新
//   - error: 同步失败（降级使用缓存 → 回退默认值）
func (m *FeatureManager) SyncFromCloud() (updated bool, err error) {
	if m.fetcher == nil {
		return false, nil
	}

	m.mu.RLock()
	currentVer := m.version
	m.mu.RUnlock()

	resp, err := m.fetcher.FetchFeatures(m.tenantID, currentVer)
	if err != nil {
		log.Printf("[FeatureManager] cloud sync failed: %v, using cache", err)
		// 同步失败：保持当前缓存（不降级到默认，因为缓存可能更旧但仍是最佳可用数据）
		return false, err
	}

	if resp == nil || resp.Status == "not_modified" {
		return false, nil
	}

	// 应用云端特征
	if err := m.applyCloudFeatures(resp); err != nil {
		log.Printf("[FeatureManager] apply cloud features failed: %v, keeping cache", err)
		return false, err
	}

	log.Printf("[FeatureManager] synced features: version=%d", resp.Version)
	return true, nil
}

// applyCloudFeatures 应用云端返回的特征值（带上限校验）。
func (m *FeatureManager) applyCloudFeatures(resp *SyncResponse) error {
	if resp == nil {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// 敏感路径上限 500
	if paths, ok := resp.Features["sensitive_path"]; ok {
		if len(paths) > 500 {
			paths = paths[:500]
		}
		m.sensitivePaths = sortStrings(paths)
	}

	// Bot UA 上限 200
	if uas, ok := resp.Features["bot_ua"]; ok {
		if len(uas) > 200 {
			uas = uas[:200]
		}
		m.botUserAgents = sortStrings(uas)
	}

	if resources, ok := resp.Features["static_resource"]; ok {
		m.staticResources = sortStrings(resources)
	}

	if methods, ok := resp.Features["dangerous_method"]; ok {
		m.dangerousMethods = sortStrings(methods)
	}

	// v1.2 新增：应用云端下发的特征库权重
	if resp.Weights != nil && m.weightsSetter != nil {
		pattern := resp.Weights["dangerous_pattern"]
		method := resp.Weights["dangerous_method"]
		head := resp.Weights["head_method"]
		upload := resp.Weights["file_upload"]
		// 至少有一个非零才调用 setter（避免空变更）
		if pattern+method+head+upload > 0 {
			m.weightsSetter(pattern, method, head, upload)
			log.Printf("[FeatureManager] weights applied: pattern=%d method=%d head=%d upload=%d",
				pattern, method, head, upload)
		}
	}

	m.version = resp.Version
	m.lastUpdate = time.Now()
	return nil
}

// StartPeriodicSync 启动后台定期同步。
// 阻塞直到 Stop 被调用。
func (m *FeatureManager) StartPeriodicSync() {
	// 立即执行一次同步
	_, _ = m.SyncFromCloud()

	ticker := time.NewTicker(m.syncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			updated, err := m.SyncFromCloud()
			if err != nil {
				log.Printf("[FeatureManager] periodic sync error: %v", err)
			} else if updated {
				log.Printf("[FeatureManager] periodic sync updated")
			}
		case <-m.stopCh:
			return
		}
	}
}

// Stop 停止后台同步。
func (m *FeatureManager) Stop() {
	select {
	case <-m.stopCh:
		// already closed
	default:
		close(m.stopCh)
	}
}

// SetSyncInterval 设置同步间隔（用于测试）。
func (m *FeatureManager) SetSyncInterval(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.syncInterval = d
}

// SetWeightsSetter 注入特征库权重热更回调。
// main.go 启动时注入 detector.SetWeights 适配函数，避免跨包依赖。
// setter 接受四个维度的权重值（int），分别对应 dangerous_pattern / dangerous_method / head_method / file_upload。
// nil 时跳过权重应用（默认行为）。
func (m *FeatureManager) SetWeightsSetter(setter func(pattern, method, head, upload int)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.weightsSetter = setter
}

// copyStrings 复制字符串切片（避免外部修改）。
func copyStrings(s []string) []string {
	if s == nil {
		return nil
	}
	out := make([]string, len(s))
	copy(out, s)
	return out
}

// sortStrings 排序并去重。
func sortStrings(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	// 去重
	seen := make(map[string]struct{}, len(s))
	unique := make([]string, 0, len(s))
	for _, v := range s {
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			unique = append(unique, v)
		}
	}
	sort.Strings(unique)
	return unique
}