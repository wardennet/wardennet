//go:build !plugin

package main

import (
	"github.com/wardennet/agent/internal/plugin"
)

// newCloudPlugin 默认构建的工厂函数。
// 通过 plugin.Open(.so) 动态加载插件，失败时返回 NoopPlugin。
// pluginPath 为空时 Loader 使用默认路径 /usr/lib/wardennet/libcloudplugin.so。
func newCloudPlugin(pluginPath string) (plugin.Plugin, error) {
	pluginLoader := plugin.NewLoader(pluginPath)
	return pluginLoader.Load()
}

// isIntegratedCloudPlugin 标识插件是否为编译时整合。
// 默认构建为 false（通过 .so 动态加载）。
const isIntegratedCloudPlugin = false
