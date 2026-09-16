// Package detector - featurelist.go 三段式特征列表引擎。
//
// 设计目标：所有可配置特征列表（合法 HTTP 客户端、敏感路径、危险攻击模式）
// 均采用统一的三段式合并架构，确保灵活性与可维护性。
//
// 三段式来源：
//  1. Builtin  — 程序内置默认值（硬编码在代码中，开箱即用）
//  2. Local    — 用户在 YAML 配置文件中指定（覆盖或追加）
//  3. Cloud    — 从云端服务动态拉取（最新威胁情报）
//
// 排除机制：
//  - 用户可在 YAML 中指定 excludes 列表，从最终结果中剔除特定模式
//  - 适用于某些业务确实需要 "..\" 或 "select " 等路径的合法场景
//
// 合并规则（幂等、确定性）：
//  1. 将 Builtin + Local + Cloud 合并去重
//  2. 从中移除 Excludes 中的所有条目
//  3. 返回有序的最终列表
//
// 优先级：Excludes > Local > Cloud > Builtin
// （高优先级的排除操作覆盖低优先级的包含操作）
package detector

import (
	"sort"
	"strings"
)

// FeatureListConfig 单个特征列表的三段式配置。
// 用于 known_http_clients / sensitive_paths / dangerous_patterns 等所有可配置列表。
type FeatureListConfig struct {
	// Local 用户在 YAML 中显式配置的条目。
	// 为空时不影响 Builtin 默认值；非空时追加到 Builtin 之后。
	Local []string `yaml:"local"`

	// Excludes 用户明确排除的条目。
	// 这些条目会从最终结果中移除，无论它来自 Builtin 还是 Cloud。
	// 场景示例：业务确实需要访问 /../path 或包含 select 的 URL。
	Excludes []string `yaml:"excludes"`

	// DisableBuiltin 设为 true 时完全禁用内置默认值。
	// 慎用：会导致没有任何默认检测能力。
	DisableBuiltin bool `yaml:"disable_builtin"`

	// DisableCloud 设为 true 时不从云端拉取。
	// 适用于离线环境或用户不信任云端数据源的场景。
	DisableCloud bool `yaml:"disable_cloud"`
}

// FeatureListResult 合并后的特征列表结果。
type FeatureListResult struct {
	// Items 最终生效的去重后列表（已排除 excludes）
	Items []string

	// Sources 记录每个条目的来源，用于调试和日志。
	// key = 条目值，value = 来源标识 ("builtin"/"local"/"cloud"/"builtin+local" 等)
	Sources map[string]string

	// Excluded 记录被排除的条目及其原始来源。
	Excluded map[string]string
}

// ResolveFeatureList 合并三段式特征列表并应用排除规则。
//
// 参数：
//   - builtin:  程序内置默认值（必填，至少传空切片）
//   - cfg:      用户在 YAML 中的配置（local/excludes/disable_builtin/disable_cloud）
//   - cloud:    从云端拉取的条目（离线或 disable_cloud 时传 nil）
//
// 返回：
//   - FeatureListResult: 合并去重排除后的最终列表
//
// 合并规则：
//  1. 按 Builtin → Cloud → Local 顺序依次加入（后加入的覆盖前者的来源标记）
//  2. Excludes 中的条目从最终结果中移除
//  3. 返回结果按字母排序，确保确定性
func ResolveFeatureList(builtin []string, cfg FeatureListConfig, cloud []string) FeatureListResult {
	result := FeatureListResult{
		Sources:  make(map[string]string),
		Excluded: make(map[string]string),
	}

	// 1. 加入 Builtin
	if !cfg.DisableBuiltin {
		for _, item := range builtin {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			result.Sources[item] = "builtin"
		}
	}

	// 2. 加入 Cloud
	if !cfg.DisableCloud && len(cloud) > 0 {
		for _, item := range cloud {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			if existing, ok := result.Sources[item]; ok {
				result.Sources[item] = existing + "+cloud"
			} else {
				result.Sources[item] = "cloud"
			}
		}
	}

	// 3. 加入 Local
	for _, item := range cfg.Local {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if existing, ok := result.Sources[item]; ok {
			result.Sources[item] = existing + "+local"
		} else {
			result.Sources[item] = "local"
		}
	}

	// 4. 应用 Excludes
	for _, excl := range cfg.Excludes {
		excl = strings.TrimSpace(excl)
		if excl == "" {
			continue
		}
		if source, ok := result.Sources[excl]; ok {
			result.Excluded[excl] = source
			delete(result.Sources, excl)
		}
	}

	// 5. 生成排序后的 Items 列表
	result.Items = make([]string, 0, len(result.Sources))
	for item := range result.Sources {
		result.Items = append(result.Items, item)
	}
	sort.Strings(result.Items)

	return result
}

// ---- 云端特征列表协议 ----

// CloudFeatureList 云端返回的特征列表数据。
// 对应云端 /api/sync/features 接口的响应格式。
type CloudFeatureList struct {
	// KnownHTTPClients 云端维护的合法 HTTP 客户端 UA 列表
	KnownHTTPClients []string `json:"known_http_clients,omitempty"`
	// SensitivePaths 云端维护的敏感路径关键词列表
	SensitivePaths []string `json:"sensitive_paths,omitempty"`
	// DangerousPatterns 云端维护的危险攻击模式列表
	DangerousPatterns []string `json:"dangerous_patterns,omitempty"`
	// Version 版本号，用于增量同步
	Version int64 `json:"version"`
	// UpdatedAt 更新时间戳（Unix 秒）
	UpdatedAt int64 `json:"updated_at"`
}

// CloudFeatureFetcher 云端特征列表拉取接口。
// 实现此接口即可从云端获取最新威胁情报。
// Agent 内置 HTTP 客户端实现此接口，离线场景使用 NoopFeatureFetcher。
type CloudFeatureFetcher interface {
	// FetchLatest 拉取最新的特征列表。
	// 返回 nil, nil 表示当前无更新（版本与本地一致）。
	FetchLatest(tenantID string, currentVersion int64) (*CloudFeatureList, error)
}

// NoopFeatureFetcher 空实现，用于离线或禁用云端的场景。
type NoopFeatureFetcher struct{}

// FetchLatest 返回 nil, nil 表示无更新。
func (NoopFeatureFetcher) FetchLatest(_ string, _ int64) (*CloudFeatureList, error) {
	return nil, nil
}

// ResolveAllFeatures 一次性合并所有三类特征列表。
// 返回的结构体包含所有已解析的特征列表结果。
type ResolvedFeatures struct {
	KnownHTTPClients  FeatureListResult
	SensitivePaths    FeatureListResult
	DangerousPatterns FeatureListResult
}

// FeatureConfigs 三类特征列表的配置集合。
type FeatureConfigs struct {
	KnownHTTPClients  FeatureListConfig
	SensitivePaths    FeatureListConfig
	DangerousPatterns FeatureListConfig
}

// ResolveAll 一次性合并所有三类特征列表。
// builtinKHTTPClients 等为内置默认值，fetcher 为云端拉取器（可为 nil）。
func ResolveAllFeatures(
	cfgs FeatureConfigs,
	builtinKHTTPClients []string,
	builtinSensitivePaths []string,
	builtinDangerousPatterns []string,
	fetcher CloudFeatureFetcher,
	tenantID string,
) ResolvedFeatures {
	var cloud *CloudFeatureList
	if fetcher != nil {
		if list, err := fetcher.FetchLatest(tenantID, 0); err == nil && list != nil {
			cloud = list
		}
	}

	var cloudKHTTPClients, cloudSensitivePaths, cloudDangerousPatterns []string
	if cloud != nil {
		cloudKHTTPClients = cloud.KnownHTTPClients
		cloudSensitivePaths = cloud.SensitivePaths
		cloudDangerousPatterns = cloud.DangerousPatterns
	}

	return ResolvedFeatures{
		KnownHTTPClients:  ResolveFeatureList(builtinKHTTPClients, cfgs.KnownHTTPClients, cloudKHTTPClients),
		SensitivePaths:    ResolveFeatureList(builtinSensitivePaths, cfgs.SensitivePaths, cloudSensitivePaths),
		DangerousPatterns: ResolveFeatureList(builtinDangerousPatterns, cfgs.DangerousPatterns, cloudDangerousPatterns),
	}
}