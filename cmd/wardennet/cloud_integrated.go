//go:build plugin

package main

import (
	"github.com/wardennet/agent/internal/cloudplugin"
	"github.com/wardennet/agent/internal/plugin"
)

// newCloudPlugin -tags=plugin 构建时的工厂函数。
// CloudPlugin 直接编译进主程序，不需要 plugin.Open(.so)。
// pluginPath 参数被忽略（保留签名一致）。
//
// 返回的 Plugin 一定是 CloudPlugin 实例（不是 NoopPlugin），
// 但要正常工作仍需要 cloud.enabled=true + 云端配置。
func newCloudPlugin(pluginPath string) (plugin.Plugin, error) {
	return cloudplugin.NewPlugin(), nil
}

// isIntegratedCloudPlugin 标识插件是否为编译时整合。
// 用于 main.go 的日志输出，帮助运维判断部署形态。
const isIntegratedCloudPlugin = true
