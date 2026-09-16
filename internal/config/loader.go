// Package config - loader.go 实现 YAML 加载、热重载与文件监听。
// reload 不重启进程生效：通过原子指针替换 + 文件变更监听触发。
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

// ErrNotLoaded 表示 Loader 尚未成功加载过配置。
var ErrNotLoaded = errors.New("config not loaded yet")

// Loader 配置加载器，线程安全。Reload 通过原子指针替换实现无锁热重载。
type Loader struct {
	path string

	current atomic.Pointer[AgentConfig]
	done    chan struct{}
}

// NewLoader 创建加载器。path 为 YAML 文件绝对或相对路径。
func NewLoader(path string) *Loader {
	return &Loader{path: path, done: make(chan struct{})}
}

// Load 首次加载并校验配置。失败则 current 保持 nil，调用 Get 返回 ErrNotLoaded。
func (l *Loader) Load() error {
	cfg, err := loadFromFile(l.path)
	if err != nil {
		return err
	}
	merged := mergeWithDefaults(cfg)
	if err := merged.Validate(); err != nil {
		return fmt.Errorf("validate config: %w", err)
	}
	l.current.Store(&merged)
	return nil
}

// Get 返回当前配置的只读副本。若未加载返回 ErrNotLoaded。
// 调用方不应修改返回的指针指向的配置；如需修改请自行深拷贝。
func (l *Loader) Get() (AgentConfig, error) {
	p := l.current.Load()
	if p == nil {
		return AgentConfig{}, ErrNotLoaded
	}
	return *p, nil
}

// Reload 重新读取并校验配置文件，原子替换当前配置。
// 失败时旧配置保留不变，调用方收到 error 可继续使用旧配置。
func (l *Loader) Reload() error {
	cfg, err := loadFromFile(l.path)
	if err != nil {
		return err
	}
	merged := mergeWithDefaults(cfg)
	if err := merged.Validate(); err != nil {
		return fmt.Errorf("validate config: %w", err)
	}
	l.current.Store(&merged)
	return nil
}

// Watch 启动后台 goroutine 轮询文件 mtime，变更时自动 Reload。
// onError: reload 失败时回调（nil 忽略），不影响现有配置。
// onReloaded: reload 成功后回调，传入新配置（nil 忽略），供调用方同步更新运行时组件。
// 返回停止函数：调用一次后停止监听。
func (l *Loader) Watch(interval time.Duration, onError func(error), onReloaded func(AgentConfig)) func() {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	var lastMod time.Time
	if info, err := os.Stat(l.path); err == nil {
		lastMod = info.ModTime()
	}

	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-l.done:
				return
			case <-ticker.C:
				info, err := os.Stat(l.path)
				if err != nil {
					if onError != nil {
						onError(err)
					}
					continue
				}
				if !info.ModTime().Equal(lastMod) {
					lastMod = info.ModTime()
					if err := l.Reload(); err != nil {
						if onError != nil {
							onError(err)
						}
					} else if onReloaded != nil {
						cfg, _ := l.Get()
						onReloaded(cfg)
					}
				}
			}
		}
	}()

	return func() {
		select {
		case <-l.done:
		default:
			close(l.done)
		}
	}
}

// loadFromFile 读取并解析 YAML。文件不存在时返回空配置（允许首次启动无配置文件）。
func loadFromFile(path string) (*AgentConfig, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		if os.IsNotExist(err) {
			// 文件不存在时返回空配置，由 mergeWithDefaults 填充默认值。
			return &AgentConfig{}, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg AgentConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	return &cfg, nil
}

// mergeWithDefaults 将用户配置与默认配置合并：零值字段填默认。
// LogSources 按 key 合并：用户未声明的 key 保留默认项。
// IPSet/Detector 段的列表字段（Whitelist/KnownHTTPClients/SensitivePaths）
// 非空时完全覆盖默认；数值字段非零时覆盖默认。
func mergeWithDefaults(user *AgentConfig) AgentConfig {
	def := Default()

	// Agent section：用户非零值覆盖默认
	if user.Agent.LocalBlockTTL > 0 {
		def.Agent.LocalBlockTTL = user.Agent.LocalBlockTTL
	}
	if user.Agent.CloudBlockTTL > 0 {
		def.Agent.CloudBlockTTL = user.Agent.CloudBlockTTL
	}
	if user.Agent.CloudMaxTTL > 0 {
		def.Agent.CloudMaxTTL = user.Agent.CloudMaxTTL
	}

	// Log section
	if user.Log.Level != "" {
		def.Log.Level = user.Log.Level
	}
	if user.Log.File != "" {
		def.Log.File = user.Log.File
	}
	if user.Log.MaxSize > 0 {
		def.Log.MaxSize = user.Log.MaxSize
	}
	if user.Log.MaxBackups > 0 {
		def.Log.MaxBackups = user.Log.MaxBackups
	}
	if user.Log.MaxAge > 0 {
		def.Log.MaxAge = user.Log.MaxAge
	}
	// Compress 是 bool，零值无法区分未声明；约定：用户可显式写 compress: true 开启，
	// compress: false 关闭。yaml.v3 未声明的 bool 默认 false，因此仅当用户显式 true 时开启。
	def.Log.Compress = user.Log.Compress

	// UnixSocket
	if user.UnixSocket.Path != "" {
		def.UnixSocket.Path = user.UnixSocket.Path
	}

	// IPSet section：列表非空时覆盖默认
	if len(user.IPSet.Whitelist) > 0 {
		def.IPSet.Whitelist = user.IPSet.Whitelist
	}
	if len(user.IPSet.Blacklist) > 0 {
		def.IPSet.Blacklist = user.IPSet.Blacklist
	}

	// Detector section：数值非零时覆盖，字符串非空时覆盖，列表非空时覆盖
	def.Detector.Enabled = user.Detector.Enabled // bool 零值 false 无法区分未声明；直接用户值覆盖
	if user.Detector.Mode != "" {
		def.Detector.Mode = user.Detector.Mode
	}
	if user.Detector.ScoreHigh > 0 {
		def.Detector.ScoreHigh = user.Detector.ScoreHigh
	}
	if user.Detector.ScoreMedium > 0 {
		def.Detector.ScoreMedium = user.Detector.ScoreMedium
	}
	if user.Detector.ScoreLow > 0 {
		def.Detector.ScoreLow = user.Detector.ScoreLow
	}
	if user.Detector.Sensitivity != "" {
		def.Detector.Sensitivity = user.Detector.Sensitivity
	}
	if user.Detector.Weights.DangerousPattern > 0 {
		def.Detector.Weights.DangerousPattern = user.Detector.Weights.DangerousPattern
	}
	if user.Detector.Weights.DangerousMethod > 0 {
		def.Detector.Weights.DangerousMethod = user.Detector.Weights.DangerousMethod
	}
	if user.Detector.Weights.FileUpload > 0 {
		def.Detector.Weights.FileUpload = user.Detector.Weights.FileUpload
	}
	for i := 0; i < 3; i++ {
		if user.Detector.Windows[i].Size > 0 {
			def.Detector.Windows[i].Size = user.Detector.Windows[i].Size
		}
	}
	if len(user.Detector.SkipPaths) > 0 {
		def.Detector.SkipPaths = user.Detector.SkipPaths
	}
	// 可配置特征列表：FlexibleFeatureList 非默认值时覆盖
	if userHasFeatureListConfig(user.Detector.KnownHTTPClients) {
		def.Detector.KnownHTTPClients = user.Detector.KnownHTTPClients
	}
	if userHasFeatureListConfig(user.Detector.SensitivePaths) {
		def.Detector.SensitivePaths = user.Detector.SensitivePaths
	}
	if userHasFeatureListConfig(user.Detector.DangerousPatterns) {
		def.Detector.DangerousPatterns = user.Detector.DangerousPatterns
	}

	// Stats section
	if user.Stats.ReportInterval > 0 {
		def.Stats.ReportInterval = user.Stats.ReportInterval
	}

	// Cloud section
	if user.Cloud.Enabled {
		def.Cloud.Enabled = true
	}
	if user.Cloud.BaseURL != "" {
		def.Cloud.BaseURL = user.Cloud.BaseURL
	}
	if user.Cloud.TenantID != "" {
		def.Cloud.TenantID = user.Cloud.TenantID
	}
	if user.Cloud.AgentSecret != "" {
		def.Cloud.AgentSecret = user.Cloud.AgentSecret
	}
	if user.Cloud.PluginPath != "" {
		def.Cloud.PluginPath = user.Cloud.PluginPath
	}
	if user.Cloud.SyncInterval > 0 {
		def.Cloud.SyncInterval = user.Cloud.SyncInterval
	}
	if user.Cloud.HeartbeatInterval > 0 {
		def.Cloud.HeartbeatInterval = user.Cloud.HeartbeatInterval
	}
	if user.Cloud.CommandInterval > 0 {
		def.Cloud.CommandInterval = user.Cloud.CommandInterval
	}
	if user.Cloud.FeatureInterval > 0 {
		def.Cloud.FeatureInterval = user.Cloud.FeatureInterval
	}

	// PortScan section
	if user.PortScan.Enabled {
		def.PortScan.Enabled = true
	}
	if user.PortScan.Source != "" {
		def.PortScan.Source = user.PortScan.Source
	}
	if user.PortScan.LogPath != "" {
		def.PortScan.LogPath = user.PortScan.LogPath
	}
	if user.PortScan.LogPrefix != "" {
		def.PortScan.LogPrefix = user.PortScan.LogPrefix
	}
	if user.PortScan.BlockTTL > 0 {
		def.PortScan.BlockTTL = user.PortScan.BlockTTL
	}
	if user.PortScan.Weight > 0 {
		def.PortScan.Weight = user.PortScan.Weight
	}
	if user.PortScan.PcapIface != "" {
		def.PortScan.PcapIface = user.PortScan.PcapIface
	}
	if user.PortScan.PcapFilter != "" {
		def.PortScan.PcapFilter = user.PortScan.PcapFilter
	}
	for i := 0; i < 3; i++ {
		if user.PortScan.Windows[i].Size > 0 {
			def.PortScan.Windows[i].Size = user.PortScan.Windows[i].Size
		}
		if user.PortScan.Windows[i].MaxPorts > 0 {
			def.PortScan.Windows[i].MaxPorts = user.PortScan.Windows[i].MaxPorts
		}
	}

	// BodyScan section（子配置完整覆盖，因为是 bool 开关 + 列表）
	if user.Detector.BodyScan.Enabled {
		def.Detector.BodyScan.Enabled = true
	}
	if user.Detector.BodyScan.MaxBodySize > 0 {
		def.Detector.BodyScan.MaxBodySize = user.Detector.BodyScan.MaxBodySize
	}
	if len(user.Detector.BodyScan.ContentTypes) > 0 {
		def.Detector.BodyScan.ContentTypes = user.Detector.BodyScan.ContentTypes
	}
	if len(user.Detector.BodyScan.FileUpload.BlockedExtensions) > 0 {
		def.Detector.BodyScan.FileUpload.BlockedExtensions = user.Detector.BodyScan.FileUpload.BlockedExtensions
	}
	if len(user.Detector.BodyScan.FileUpload.BlockedMimeTypes) > 0 {
		def.Detector.BodyScan.FileUpload.BlockedMimeTypes = user.Detector.BodyScan.FileUpload.BlockedMimeTypes
	}

	// ResourceBaseline section
	if user.Detector.ResourceBaseline.Enabled {
		def.Detector.ResourceBaseline.Enabled = true
	}
	if len(user.Detector.ResourceBaseline.Patterns) > 0 {
		def.Detector.ResourceBaseline.Patterns = user.Detector.ResourceBaseline.Patterns
	}

	// LogSources 按 key 合并：默认项 + 用户覆盖
	for name, src := range user.LogSources {
		merged := def.LogSources[name]
		if src.Path != "" {
			merged.Path = src.Path
		}
		if src.Parser != "" {
			merged.Parser = src.Parser
		}
		def.LogSources[name] = merged
	}

	return def
}

// userHasFeatureListConfig 检查用户是否在 YAML 中显式配置了特征列表。
// 当 Local 非空、Excludes 非空、或 DisableBuiltin/DisableCloud 为 true 时，
// 认为用户有显式配置，应覆盖默认值。
func userHasFeatureListConfig(f FlexibleFeatureList) bool {
	return len(f.Local) > 0 || len(f.Excludes) > 0 || f.DisableBuiltin || f.DisableCloud
}
