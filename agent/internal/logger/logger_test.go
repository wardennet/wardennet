// Package logger - 表驱动测试：级别解析、stdout 输出（注入 buffer）、文件轮转、Close 幂等。
package logger

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestParseLevel 表驱动测试级别解析。
func TestParseLevel(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input   string
		want    slog.Level
		wantErr bool
	}{
		{"debug", slog.LevelDebug, false},
		{"info", slog.LevelInfo, false},
		{"warn", slog.LevelWarn, false},
		{"error", slog.LevelError, false},
		{"", slog.LevelInfo, false}, // 空字符串默认 info
		{"trace", 0, true},
		{"DEBUG", 0, true}, // 大小写敏感
		{"fatal", 0, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got, err := parseLevel(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got nil", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			lvl, ok := got.(slog.Level)
			if !ok {
				t.Fatalf("returned Leveler is not slog.Level: %T", got)
			}
			if lvl != tc.want {
				t.Errorf("level = %v, want %v", lvl, tc.want)
			}
		})
	}
}

// TestNew_StdoutOnly_FileEmpty File 为空时仅 stdout 输出，Close 不报错。
func TestNew_StdoutOnly_FileEmpty(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	cfg := LogConfig{Level: "info", File: ""}
	lg, err := NewWithStdout(cfg, &buf)
	if err != nil {
		t.Fatalf("NewWithStdout: %v", err)
	}
	defer lg.Close()
	lg.Info("test message", "key", "val")
	if !strings.Contains(buf.String(), "test message") {
		t.Errorf("stdout missing message: %q", buf.String())
	}
}

// TestNew_LevelFilter 表驱动测试级别过滤。
func TestNew_LevelFilter(t *testing.T) {
	t.Parallel()
	type tc struct {
		name     string
		level    string
		method   string
		loggable bool
	}
	cases := []tc{
		{"debug_debug", "debug", "debug", true},
		{"debug_info", "debug", "info", true},
		{"debug_warn", "debug", "warn", true},
		{"debug_error", "debug", "error", true},
		{"info_debug", "info", "debug", false},
		{"info_info", "info", "info", true},
		{"warn_info", "warn", "info", false},
		{"warn_warn", "warn", "warn", true},
		{"error_warn", "error", "warn", false},
		{"error_error", "error", "error", true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			cfg := LogConfig{Level: tc.level, File: ""}
			lg, err := NewWithStdout(cfg, &buf)
			if err != nil {
				t.Fatalf("NewWithStdout: %v", err)
			}
			defer lg.Close()
			dispatchLog(lg, tc.method, "captured msg", "k", "v")
			out := buf.String()
			if tc.loggable {
				if !strings.Contains(out, "captured msg") {
					t.Errorf("level %s/%s: expected log to contain 'captured msg', got %q", tc.level, tc.method, out)
				}
			} else {
				if strings.Contains(out, "captured msg") {
					t.Errorf("level %s/%s: log should be filtered, but got %q", tc.level, tc.method, out)
				}
			}
		})
	}
}

// dispatchLog 按方法名分发到对应 slog 级别。
func dispatchLog(lg *Logger, method, msg string, args ...any) {
	switch method {
	case "debug":
		lg.Debug(msg, args...)
	case "info":
		lg.Info(msg, args...)
	case "warn":
		lg.Warn(msg, args...)
	case "error":
		lg.Error(msg, args...)
	}
}

// TestNew_FileWriter 验证文件输出与轮转配置生效。
func TestNew_FileWriter(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "wardennet.log")
	cfg := LogConfig{
		Level:      "debug",
		File:       path,
		MaxSize:    1, // 1MB
		MaxBackups: 3,
		MaxAge:     7,
		Compress:   true,
	}
	var buf bytes.Buffer
	lg, err := NewWithStdout(cfg, &buf)
	if err != nil {
		t.Fatalf("NewWithStdout: %v", err)
	}
	lg.Info("file test message", "k", "v")
	if err := lg.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if !strings.Contains(string(data), "file test message") {
		t.Errorf("log file does not contain message; got %s", string(data))
	}
}

// TestNew_InvalidLevel 非法级别返回 error。
func TestNew_InvalidLevel(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	cfg := LogConfig{Level: "trace", File: ""}
	_, err := NewWithStdout(cfg, &buf)
	if err == nil {
		t.Fatalf("expected error for invalid level, got nil")
	}
}

// TestLogger_Close_Idempotent Close 多次调用不 panic。
func TestLogger_Close_Idempotent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "wardennet.log")
	cfg := LogConfig{Level: "info", File: path, MaxSize: 1, MaxBackups: 1, MaxAge: 1}
	var buf bytes.Buffer
	lg, err := NewWithStdout(cfg, &buf)
	if err != nil {
		t.Fatalf("NewWithStdout: %v", err)
	}
	if err := lg.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := lg.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// TestLogger_ConcurrentWrite 并发写入验证。
func TestLogger_ConcurrentWrite(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "wardennet.log")
	cfg := LogConfig{Level: "info", File: path, MaxSize: 5, MaxBackups: 2, MaxAge: 7}
	var buf bytes.Buffer
	lg, err := NewWithStdout(cfg, &buf)
	if err != nil {
		t.Fatalf("NewWithStdout: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			lg.Info("concurrent", "i", i)
		}(i)
	}
	wg.Wait()
	_ = lg.Close()
}

// TestNew_StdoutAndFile 验证 stdout + 文件双输出。
func TestNew_StdoutAndFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "wardennet.log")
	cfg := LogConfig{Level: "info", File: path, MaxSize: 1, MaxBackups: 1, MaxAge: 1}
	var buf bytes.Buffer
	lg, err := NewWithStdout(cfg, &buf)
	if err != nil {
		t.Fatalf("NewWithStdout: %v", err)
	}
	defer lg.Close()
	lg.Info("dual output", "k", "v")

	if !strings.Contains(buf.String(), "dual output") {
		t.Errorf("stdout missing message: %q", buf.String())
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "dual output") {
		t.Errorf("file missing message: %s", string(data))
	}
}

// TestNew_RotationTrigger 验证文件超过 MaxSize 时触发轮转。
func TestNew_RotationTrigger(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "wardennet.log")
	cfg := LogConfig{
		Level:      "info",
		File:       path,
		MaxSize:    1, // 1MB
		MaxBackups: 3,
		MaxAge:     7,
		Compress:   false,
	}
	var buf bytes.Buffer
	lg, err := NewWithStdout(cfg, &buf)
	if err != nil {
		t.Fatalf("NewWithStdout: %v", err)
	}
	for i := 0; i < 30000; i++ {
		lg.Info("rotation test message padding padding padding padding", "i", i)
	}
	_ = lg.Close()

	matches, err := filepath.Glob(filepath.Join(dir, "wardennet*"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(matches) < 2 {
		t.Errorf("expected rotation backup files, found %d: %v", len(matches), matches)
	}
}

// TestNew_ConcurrentReinit 验证多次 New 创建独立实例安全。
func TestNew_ConcurrentReinit(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cfg := LogConfig{
				Level: "info",
				File:  filepath.Join(dir, "log"+itoa(i)+".log"),
				MaxSize: 1, MaxBackups: 1, MaxAge: 1,
			}
			var buf bytes.Buffer
			lg, err := NewWithStdout(cfg, &buf)
			if err != nil {
				t.Errorf("New %d: %v", i, err)
				return
			}
			lg.Info("init test", "i", i)
			_ = lg.Close()
		}(i)
	}
	wg.Wait()
}

// itoa 简化整数转字符串。
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [16]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// TestNew_TimestampExists 验证日志包含时间戳。
func TestNew_TimestampExists(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	cfg := LogConfig{Level: "info", File: ""}
	lg, err := NewWithStdout(cfg, &buf)
	if err != nil {
		t.Fatalf("NewWithStdout: %v", err)
	}
	lg.Info("ts test")
	_ = lg.Close()
	s := buf.String()
	if !strings.Contains(s, "time=") {
		t.Errorf("log missing time field: %s", s)
	}
}

// TestNew_StdoutNilFallbacks NewWithStdout 传 nil 时回退到 os.Stdout。
func TestNew_StdoutNilFallbacks(t *testing.T) {
	t.Parallel()
	cfg := LogConfig{Level: "info", File: ""}
	lg, err := NewWithStdout(cfg, nil)
	if err != nil {
		t.Fatalf("NewWithStdout nil: %v", err)
	}
	defer lg.Close()
	lg.Info("nil fallback test")
}

// TestNew_DefaultNewUsesOSStdout New() 用 os.Stdout 不 panic。
func TestNew_DefaultNewUsesOSStdout(t *testing.T) {
	t.Parallel()
	cfg := LogConfig{Level: "info", File: ""}
	lg, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer lg.Close()
	lg.Info("default new smoke test")
}
