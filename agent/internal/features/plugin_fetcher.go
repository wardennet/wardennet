// Package features - plugin_fetcher.go 适配 plugin.Plugin.FetchFeatures → FeatureFetcher 接口。
//
// FeatureManager 只依赖 FeatureFetcher 接口。本适配器让它能复用 plugin.Plugin
// 提供的云端特征值拉取能力，而不需要自己发 HTTP（闭源插件内部实现）。
package features

import (
	"github.com/wardennet/agent/internal/plugin"
)

// PluginFetcher 把 plugin.Plugin 适配为 FeatureFetcher 接口。
// 有插件时通过插件拉取云端特征；插件返回空 Features 时 FeatureManager 使用内置默认值。
type PluginFetcher struct {
	p plugin.Plugin
}

// NewPluginFetcher 创建适配器。p 为 nil 或 NoopPlugin 时返回 NoopFetcher（零开销）。
func NewPluginFetcher(p plugin.Plugin) FeatureFetcher {
	if p == nil {
		return NoopFetcher{}
	}
	if _, noop := p.(*plugin.NoopPlugin); noop {
		return NoopFetcher{}
	}
	return &PluginFetcher{p: p}
}

// FetchFeatures 实现 FeatureFetcher 接口。
// 将 plugin.FeatureResult 转为 SyncResponse。
func (f *PluginFetcher) FetchFeatures(tenantID string, currentVersion int64) (*SyncResponse, error) {
	result, err := f.p.FetchFeatures(tenantID, currentVersion)
	if err != nil {
		return nil, err
	}

	if result == nil {
		return &SyncResponse{Status: "not_modified", Version: currentVersion}, nil
	}

	// 版本号相同 → 云端表示无更新
	if result.Version == currentVersion && len(result.Features) == 0 {
		return &SyncResponse{Status: "not_modified", Version: currentVersion}, nil
	}

	// 将 []map[string]interface{} 转为 map[string][]string
	features := make(map[string][]string)
	for _, item := range result.Features {
		cat, _ := item["category"].(string)
		val, _ := item["value"].(string)
		if cat != "" && val != "" {
			features[cat] = append(features[cat], val)
		}
		// 兼容没有 category 的扁平格式
		if cat == "" {
			key, _ := item["key"].(string)
			if key != "" {
				features[key] = append(features[key], val)
			}
		}
	}

	// v1.2 新增：转换 plugin.FeatureResult.Weights → SyncResponse.Weights
	var weights map[string]int
	if result.Weights != nil {
		weights = make(map[string]int, 4)
		if result.Weights.DangerousPattern > 0 {
			weights["dangerous_pattern"] = result.Weights.DangerousPattern
		}
		if result.Weights.DangerousMethod > 0 {
			weights["dangerous_method"] = result.Weights.DangerousMethod
		}
		if result.Weights.HeadMethod > 0 {
			weights["head_method"] = result.Weights.HeadMethod
		}
		if result.Weights.FileUpload > 0 {
			weights["file_upload"] = result.Weights.FileUpload
		}
	}

	return &SyncResponse{
		Status:   "updated",
		Version:  result.Version,
		Features: features,
		Count:    len(result.Features),
		Weights:  weights,
	}, nil
}
