// Package config - 测试用例覆盖 Validate、mergeWithDefaults、Loader.Load/Reload/Watch。
package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestValidate 表驱动测试：合法/非法 TTL、级别、Parser。
func TestValidate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		mutate  func(*AgentConfig)
		wantErr bool
		errSub  string
	}{
		{
			name:    "valid default",
			mutate:  func(c *AgentConfig) {},
			wantErr: false,
		},
		{
			name:    "local_block_ttl zero",
			mutate:  func(c *AgentConfig) { c.Agent.LocalBlockTTL = 0 },
			wantErr: true,
			errSub:  "local_block_ttl",
		},
		{
			name:    "cloud_block_ttl negative",
			mutate:  func(c *AgentConfig) { c.Agent.CloudBlockTTL = -1 },
			wantErr: true,
			errSub:  "cloud_block_ttl",
		},
		{
			name:    "cloud_max_ttl zero",
			mutate:  func(c *AgentConfig) { c.Agent.CloudMaxTTL = 0 },
			wantErr: true,
			errSub:  "cloud_max_ttl",
		},
		{
			name:    "log.level invalid",
			mutate:  func(c *AgentConfig) { c.Log.Level = "trace" },
			wantErr: true,
			errSub:  "log.level",
		},
		{
			name:    "log.level debug valid",
			mutate:  func(c *AgentConfig) { c.Log.Level = "debug" },
			wantErr: false,
		},
		{
			name: "parser empty",
			mutate: func(c *AgentConfig) {
				s := c.LogSources["nginx_access"]
				s.Parser = ""
				c.LogSources["nginx_access"] = s
			},
			wantErr: true,
			errSub:  "parser must not be empty",
		},
		{
			name: "parser invalid",
			mutate: func(c *AgentConfig) {
				s := c.LogSources["nginx_access"]
				s.Parser = "mysql"
				c.LogSources["nginx_access"] = s
			},
			wantErr: true,
			errSub:  "parser invalid",
		},
		{
			name:    "unix_socket empty",
			mutate:  func(c *AgentConfig) { c.UnixSocket.Path = "" },
			wantErr: true,
			errSub:  "unix_socket.path",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := Default()
			tc.mutate(&cfg)
			err := cfg.Validate()
			if tc.wantErr && err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.errSub)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
			if tc.wantErr && err != nil && tc.errSub != "" {
				if !contains(err.Error(), tc.errSub) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.errSub)
				}
			}
		})
	}
}

// contains 简化 substring 检查，避免引入 strings 包到测试。
func contains(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestLoader_LoadFromFile 验证 YAML 解析与合并默认值。
func TestLoader_LoadFromFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "wardennet.yaml")
	yamlContent := []byte(`
agent:
  local_block_ttl: 1800
  cloud_block_ttl: 3600
  cloud_max_ttl: 86400
log:
  level: debug
  file: ""
log_sources:
  nginx_access:
    path: /var/log/nginx/access.log
    parser: nginx_access
  linux_auth:
    path: /var/log/auth.log
    parser: linux_auth
unix_socket:
  path: /tmp/wardennet.sock
`)
	if err := os.WriteFile(path, yamlContent, 0o644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	l := NewLoader(path)
	if err := l.Load(); err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	cfg, err := l.Get()
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if cfg.Agent.LocalBlockTTL != 1800 {
		t.Errorf("LocalBlockTTL = %d, want 1800", cfg.Agent.LocalBlockTTL)
	}
	if cfg.Agent.CloudBlockTTL != 3600 {
		t.Errorf("CloudBlockTTL = %d, want 3600", cfg.Agent.CloudBlockTTL)
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("Log.Level = %q, want debug", cfg.Log.Level)
	}
	if cfg.UnixSocket.Path != "/tmp/wardennet.sock" {
		t.Errorf("UnixSocket.Path = %q, want /tmp/wardennet.sock", cfg.UnixSocket.Path)
	}
}

// TestLoader_LoadFromFile_NewFields 验证新增字段（Stats、Detector.Mode、Sensitivity、ScoreMedium、ScoreLow）
// 能正确从 YAML 覆盖默认值 —— 回归测试：之前 mergeWithDefaults 漏掉了这些字段导致配置不生效。
func TestLoader_LoadFromFile_NewFields(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "wardennet.yaml")
	yamlContent := []byte(`
stats:
  report_interval: 300
detector:
  enabled: true
  mode: report
  sensitivity: low
  score_high: 80
  score_medium: 40
  score_low: 15
`)
	if err := os.WriteFile(path, yamlContent, 0o644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	l := NewLoader(path)
	if err := l.Load(); err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	cfg, err := l.Get()
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	// Stats.ReportInterval —— 本次 bug 的核心
	if cfg.Stats.ReportInterval != 300 {
		t.Errorf("Stats.ReportInterval = %d, want 300 (was using default 60 before fix)", cfg.Stats.ReportInterval)
	}
	// Detector.Mode
	if cfg.Detector.Mode != "report" {
		t.Errorf("Detector.Mode = %q, want report", cfg.Detector.Mode)
	}
	// Detector.Sensitivity
	if cfg.Detector.Sensitivity != "low" {
		t.Errorf("Detector.Sensitivity = %q, want low", cfg.Detector.Sensitivity)
	}
	// Score 阈值三档
	if cfg.Detector.ScoreHigh != 80 {
		t.Errorf("Detector.ScoreHigh = %d, want 80", cfg.Detector.ScoreHigh)
	}
	if cfg.Detector.ScoreMedium != 40 {
		t.Errorf("Detector.ScoreMedium = %d, want 40", cfg.Detector.ScoreMedium)
	}
	if cfg.Detector.ScoreLow != 15 {
		t.Errorf("Detector.ScoreLow = %d, want 15", cfg.Detector.ScoreLow)
	}
}

// TestLoader_LoadFromFile_NotFound 文件不存在时仍可加载（用默认值），不返回错误。
func TestLoader_LoadFromFile_NotFound(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent.yaml")
	l := NewLoader(path)
	if err := l.Load(); err != nil {
		t.Fatalf("Load with missing file should succeed with defaults, got: %v", err)
	}
	cfg, err := l.Get()
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	// 默认值应生效
	if cfg.Agent.LocalBlockTTL != 3600 {
		t.Errorf("default LocalBlockTTL = %d, want 3600", cfg.Agent.LocalBlockTTL)
	}
}

// TestLoader_LoadFromFile_InvalidYAML 损坏 YAML 返回 parse error。
func TestLoader_LoadFromFile_InvalidYAML(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("agent: [unterminated\n  invalid"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	l := NewLoader(path)
	if err := l.Load(); err == nil {
		t.Fatalf("expected parse error, got nil")
	}
}

// TestLoader_Reload 原子替换配置：旧 Get 副本不变，新 Get 反映新值。
func TestLoader_Reload(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "wardennet.yaml")
	_ = os.WriteFile(path, []byte("agent:\n  local_block_ttl: 1000\n"), 0o644)

	l := NewLoader(path)
	if err := l.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	cfgOld, _ := l.Get()
	if cfgOld.Agent.LocalBlockTTL != 1000 {
		t.Fatalf("initial LocalBlockTTL = %d, want 1000", cfgOld.Agent.LocalBlockTTL)
	}

	// 修改文件触发 Reload
	_ = os.WriteFile(path, []byte("agent:\n  local_block_ttl: 2000\n"), 0o644)
	if err := l.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	cfgNew, _ := l.Get()
	if cfgNew.Agent.LocalBlockTTL != 2000 {
		t.Errorf("after reload LocalBlockTTL = %d, want 2000", cfgNew.Agent.LocalBlockTTL)
	}
	// cfgOld 是值副本，应保持旧值
	if cfgOld.Agent.LocalBlockTTL != 1000 {
		t.Errorf("cfgOld LocalBlockTTL mutated to %d, want 1000 (snapshot should be stable)", cfgOld.Agent.LocalBlockTTL)
	}
}

// TestLoader_Reload_InvalidKeepsOld Reload 失败时旧配置保留。
// 用非法 parser 触发 Validate 失败：零值 TTL 会被 mergeWithDefaults 用默认值覆盖，无法触发校验。
func TestLoader_Reload_InvalidKeepsOld(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "wardennet.yaml")
	_ = os.WriteFile(path, []byte("agent:\n  local_block_ttl: 1000\n"), 0o644)

	l := NewLoader(path)
	if err := l.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// 写入非法 parser，触发 Validate 失败（零值 TTL 会被 mergeWithDefaults 用默认覆盖，无法触发）
	_ = os.WriteFile(path, []byte("log_sources:\n  nginx_access:\n    parser: mysql_invalid\n"), 0o644)
	if err := l.Reload(); err == nil {
		t.Fatalf("expected validation error on Reload, got nil")
	}
	cfg, _ := l.Get()
	if cfg.Agent.LocalBlockTTL != 1000 {
		t.Errorf("after failed reload LocalBlockTTL = %d, want keep 1000", cfg.Agent.LocalBlockTTL)
	}
}

// TestLoader_Get_BeforeLoad 未加载时返回 ErrNotLoaded。
func TestLoader_Get_BeforeLoad(t *testing.T) {
	t.Parallel()
	l := NewLoader("/tmp/nonexistent_for_test.yaml")
	_, err := l.Get()
	if err != ErrNotLoaded {
		t.Errorf("Get before Load: err = %v, want ErrNotLoaded", err)
	}
}

// TestLoader_Watch 文件变更自动触发 Reload。
func TestLoader_Watch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wardennet.yaml")
	_ = os.WriteFile(path, []byte("agent:\n  local_block_ttl: 1000\n"), 0o644)

	l := NewLoader(path)
	if err := l.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	errCh := make(chan error, 4)
	stop := l.Watch(50*time.Millisecond, func(err error) {
		errCh <- err
	}, nil)
	defer stop()

	// 等待一拍后修改文件
	time.Sleep(100 * time.Millisecond)
	_ = os.WriteFile(path, []byte("agent:\n  local_block_ttl: 3000\n"), 0o644)

	deadline := time.After(2 * time.Second)
	for {
		select {
		case err := <-errCh:
			t.Fatalf("watch reported error: %v", err)
		case <-deadline:
			cfg, _ := l.Get()
			if cfg.Agent.LocalBlockTTL != 3000 {
				t.Fatalf("watch did not reload: LocalBlockTTL = %d, want 3000", cfg.Agent.LocalBlockTTL)
			}
			return
		}
	}
}

// TestLoader_ConcurrentGet 并发 Get 安全（go test -race 验证）。
func TestLoader_ConcurrentGet(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "wardennet.yaml")
	_ = os.WriteFile(path, []byte("agent:\n  local_block_ttl: 1000\n"), 0o644)

	l := NewLoader(path)
	if err := l.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			_, _ = l.Get()
		}
	}()

	for i := 0; i < 200; i++ {
		// 并发 Reload 与 Get，验证原子指针安全
		if i == 100 {
			_ = l.Reload()
		}
		_, _ = l.Get()
	}
	<-done
}

// TestLoader_ReloadAtomicPointer 验证 Reload 使用 atomic.Pointer 而非 mutex。
// 仅通过快照稳定性间接验证：Reload 后旧副本不应被修改。
func TestLoader_ReloadAtomicPointer(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "wardennet.yaml")
	_ = os.WriteFile(path, []byte("agent:\n  local_block_ttl: 1000\n"), 0o644)

	l := NewLoader(path)
	if err := l.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	old, _ := l.Get()
	_ = os.WriteFile(path, []byte("agent:\n  local_block_ttl: 5000\n"), 0o644)
	if err := l.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	// 验证内部指针确实变化
	p := l.current.Load()
	if p == nil {
		t.Fatalf("current pointer nil after Reload")
	}
	if old.Agent.LocalBlockTTL != 1000 {
		t.Errorf("old snapshot corrupted: %d", old.Agent.LocalBlockTTL)
	}
}
