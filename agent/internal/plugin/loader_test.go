// Package plugin - loader_test.go 验证加载器降级逻辑。
package plugin

import (
	"os"
	"path/filepath"
	"testing"
)

// fakePlugin 测试用假插件。
type fakePlugin struct {
	initCalled bool
	shutdown   bool
}

func (f *fakePlugin) Init(agentID, version string) error    { f.initCalled = true; return nil }
func (f *fakePlugin) Shutdown() error                      { f.shutdown = true; return nil }
func (f *fakePlugin) Auth(ctx AuthContext) (AuthResult, error) {
	return AuthResult{OK: true, AgentID: "fake-agent"}, nil
}
func (f *fakePlugin) ReportFull(events interface{}) error       { return nil }
func (f *fakePlugin) Diff(req DiffRequest) (DiffResult, error) {
	return DiffResult{OK: true}, nil
}
func (f *fakePlugin) HandleCommand(cmd RemoteCommand) (CommandResult, error) {
	return CommandResult{ID: cmd.ID, Ok: true}, nil
}

// TestLoader_NoPluginFallback 验证未指定/不存在插件时降级为 NoopPlugin。
func TestLoader_NoPluginFallback(t *testing.T) {
	l := NewLoader("")
	p, err := l.Load()
	if err != nil {
		t.Fatalf("Load should not error on missing plugin: %v", err)
	}
	if p == nil {
		t.Fatalf("plugin is nil")
	}
	if _, ok := p.(*NoopPlugin); !ok {
		t.Errorf("expected NoopPlugin, got %T", p)
	}
	if l.Path() != DefaultPluginPath {
		t.Errorf("default path=%q, want %q", l.Path(), DefaultPluginPath)
	}
}

// TestLoader_CustomPathFallback 自定义路径不存在时仍降级。
func TestLoader_CustomPathFallback(t *testing.T) {
	l := NewLoader("/tmp/does-not-exist.so")
	p, err := l.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := p.(*NoopPlugin); !ok {
		t.Errorf("expected NoopPlugin for missing custom path")
	}
}

// TestLoader_FileExistsButInvalid 存在但非有效插件的文件（比如普通文本）触发降级。
func TestLoader_FileExistsButInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fake.so")
	if err := os.WriteFile(path, []byte("not a real shared object"), 0o644); err != nil {
		t.Fatalf("write fake file: %v", err)
	}
	l := NewLoader(path)
	p, err := l.Load()
	if err != nil {
		t.Fatalf("Load should not error: %v", err)
	}
	if _, ok := p.(*NoopPlugin); !ok {
		t.Errorf("expected NoopPlugin for invalid file, got %T", p)
	}
}

// TestLoader_PluginInterface NoopPlugin 实现完整 Plugin 接口且方法安全。
func TestLoader_PluginInterface(t *testing.T) {
	n := &NoopPlugin{}
	if err := n.Init("agent-1", "v0.1"); err != nil {
		t.Errorf("Init: %v", err)
	}
	if err := n.Shutdown(); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
	if r, err := n.Auth(AuthContext{}); err != nil || r.OK {
		t.Errorf("Auth should fail-safe: %+v err=%v", r, err)
	}
	if err := n.ReportFull(nil); err != nil {
		t.Errorf("ReportFull: %v", err)
	}
	if d, err := n.Diff(DiffRequest{}); err != nil || !d.OK {
		t.Errorf("Diff should return ok: %+v err=%v", d, err)
	}
	if r, err := n.HandleCommand(RemoteCommand{}); err != nil || r.Ok {
		t.Errorf("HandleCommand should fail-safe: %+v err=%v", r, err)
	}
}
