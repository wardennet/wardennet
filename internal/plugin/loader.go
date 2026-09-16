// Package plugin - loader.go 实现插件加载与无插件降级逻辑。
//
// 加载优先级：
//  1. 显式指定的 plugin.so 路径（来自配置或 CLI --plugin 参数）
//  2. 默认路径 /usr/lib/wardennet/libcloudplugin.so
//  3. 若均加载失败 → 降级为 NoopPlugin（单机模式，所有云端能力禁用）
package plugin

import (
	stlplugin "plugin"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// DefaultPluginPath 默认插件路径。
const DefaultPluginPath = "/usr/lib/wardennet/libcloudplugin.so"

// Loader 插件加载器。
type Loader struct {
	mu      sync.Mutex
	plugin  Plugin
	path    string // 实际加载的插件路径；空表示无插件
	loaded  bool
}

// NewLoader 创建加载器。path 可为空，使用默认路径。
func NewLoader(path string) *Loader {
	if path == "" {
		path = DefaultPluginPath
	}
	return &Loader{path: path}
}

// Load 尝试加载插件。失败时降级为 NoopPlugin。
// 返回的 Plugin 永远非 nil，可直接使用。
// 同时返回 err——真实的加载错误（如果有的话），由调用方决定是否打印。
func (l *Loader) Load() (Plugin, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.loaded {
		return l.plugin, nil
	}
	p, err := l.tryLoad(l.path)
	if err != nil {
		// 降级为 NoopPlugin，但把错误返回给上层，让 main 打印出来方便排查
		l.plugin = &NoopPlugin{}
		l.loaded = true
		return l.plugin, err
	}
	l.plugin = p
	l.loaded = true
	return l.plugin, nil
}

// Path 返回实际加载的插件路径（NoopPlugin 时为空字符串）。
func (l *Loader) Path() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.path
}

// IsLoaded 是否已加载（包括 NoopPlugin）。
func (l *Loader) IsLoaded() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.loaded
}

// Plugin 返回已加载的插件（未加载时调用 Load）。
func (l *Loader) Plugin() Plugin {
	p, _ := l.Load()
	return p
}

// tryLoad 尝试从指定路径加载 .so 插件。
// 真实加载流程：plugin.Open → Lookup("NewPlugin") → 断言为 Plugin。
// 任何步骤失败都返回错误，由上层 Load 触发 NoopPlugin 降级。
func (l *Loader) tryLoad(path string) (Plugin, error) {
	if path == "" {
		return nil, fmt.Errorf("empty plugin path")
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("plugin not found: %s", path)
		}
		return nil, fmt.Errorf("stat plugin: %w", err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("plugin path is directory: %s", path)
	}
	// 检查候选路径：如果传入的是目录或不带后缀，则自动拼接默认文件名
	absPath := l.resolvePath(path)

	// 1. Open .so
	mod, err := stlplugin.Open(absPath)
	if err != nil {
		return nil, fmt.Errorf("plugin.Open(%s): %w", absPath, err)
	}

	// 2. Lookup NewPlugin 工厂函数
	sym, err := mod.Lookup("NewPlugin")
	if err != nil {
		return nil, fmt.Errorf("Lookup NewPlugin: %w", err)
	}

	// 3. 断言为 func() Plugin，调用拿到实例
	factory, ok := sym.(func() Plugin)
	if !ok {
		return nil, fmt.Errorf("NewPlugin has wrong type: %T", sym)
	}

	p := factory()
	if p == nil {
		return nil, fmt.Errorf("NewPlugin() returned nil")
	}
	return p, nil
}

// resolvePath 解析插件路径。
func (l *Loader) resolvePath(path string) string {
	// 如果已经是 .so/.dll 文件，直接返回
	ext := filepath.Ext(path)
	if ext == ".so" || ext == ".dll" {
		return path
	}
	// 否则尝试拼接默认插件名
	return filepath.Join(path, filepath.Base(DefaultPluginPath))
}
