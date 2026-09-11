// Package logger 基于 log/slog 标准库与 lumberjack 文件轮转。
// 同时输出 stdout 与文件；文件为空时仅 stdout。级别 debug/info/warn/error。
//
// 本包自包含：不引入任何 agent/internal 其他包，避免跨模块解析问题。
package logger

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"

	"gopkg.in/natefinch/lumberjack.v2"
)

// LogLevel 日志级别常量（镜像 config.LogLevel）。
type LogLevel string

const (
	LevelDebug LogLevel = "debug"
	LevelInfo  LogLevel = "info"
	LevelWarn  LogLevel = "warn"
	LevelError LogLevel = "error"
)

// LogConfig 日志配置（镜像 config.LogSection，自包含定义避免跨包引用）。
type LogConfig struct {
	Level      string `yaml:"level"`
	File       string `yaml:"file"`
	MaxSize    int    `yaml:"max_size"`
	MaxBackups int    `yaml:"max_backups"`
	MaxAge     int    `yaml:"max_age"`
	Compress   bool   `yaml:"compress"`
}

// Logger 封装 slog.Logger 与文件 closer。
// 使用 slog.LevelVar 实现运行时动态调整日志级别（热重载）。
type Logger struct {
	*slog.Logger
	level  *slog.LevelVar
	closer io.Closer
	mu     sync.Mutex
}

// New 根据 LogConfig 构造 logger。File 为空时仅 stdout，无 closer。
// Level 必须是合法值（debug/info/warn/error），否则返回 error。
func New(cfg LogConfig) (*Logger, error) {
	return NewWithStdout(cfg, os.Stdout)
}

// NewWithStdout 使用自定义 stdout writer 构造 logger。生产代码用 New() 即可。
// stdout 为 nil 时回退到 os.Stdout。
// 返回的 Logger 使用 slog.LevelVar 管理日志级别，支持运行时通过 SetLevel 动态调整。
func NewWithStdout(cfg LogConfig, stdout io.Writer) (*Logger, error) {
	initialLevel, err := parseLevel(cfg.Level)
	if err != nil {
		return nil, err
	}
	if stdout == nil {
		stdout = os.Stdout
	}

	// 使用 LevelVar 包装，后续可通过 SetLevel 动态调整
	lv := &slog.LevelVar{}
	lv.Set(initialLevel.Level())

	opts := &slog.HandlerOptions{Level: lv}
	var writers []io.Writer
	var closers []io.Closer

	// stdout 永远启用，确保容器化场景可见
	writers = append(writers, stdout)

	if cfg.File != "" {
		lj := &lumberjack.Logger{
			Filename:   cfg.File,
			MaxSize:    cfg.MaxSize,
			MaxBackups: cfg.MaxBackups,
			MaxAge:     cfg.MaxAge,
			Compress:   cfg.Compress,
			LocalTime:  true,
		}
		writers = append(writers, lj)
		closers = append(closers, lj)
	}

	multi := io.MultiWriter(writers...)
	handler := slog.NewTextHandler(multi, opts)

	return &Logger{
		Logger: slog.New(handler),
		level:  lv,
		closer: &multiCloser{closers: closers},
	}, nil
}

// SetLevel 运行时动态调整日志级别。
// 支持值：debug / info / warn / error。
// 级别字符串非法时返回 error，不改变当前级别。
func (l *Logger) SetLevel(levelStr string) error {
	newLevel, err := parseLevel(levelStr)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level.Set(newLevel.Level())
	return nil
}

// CurrentLevel 返回当前日志级别字符串。
func (l *Logger) CurrentLevel() string {
	return formatLevel(l.level.Level())
}

// formatLevel 将 slog.Level 转为字符串。
func formatLevel(lv slog.Level) string {
	switch {
	case lv <= slog.LevelDebug:
		return "debug"
	case lv <= slog.LevelInfo:
		return "info"
	case lv <= slog.LevelWarn:
		return "warn"
	default:
		return "error"
	}
}

// Close 关闭所有底层 writer（stdout 不可关闭，跳过；仅文件 closer 生效）。
// 多次调用幂等。
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closer == nil {
		return nil
	}
	err := l.closer.Close()
	l.closer = nil
	return err
}

// parseLevel 将字符串级别转为 slog.Level。
func parseLevel(s string) (slog.Leveler, error) {
	switch LogLevel(s) {
	case LevelDebug:
		return slog.LevelDebug, nil
	case LevelInfo, "":
		return slog.LevelInfo, nil
	case LevelWarn:
		return slog.LevelWarn, nil
	case LevelError:
		return slog.LevelError, nil
	default:
		return nil, fmt.Errorf("invalid log level: %q (want debug/info/warn/error)", s)
	}
}

// multiCloser 聚合多个 io.Closer，Close 时依次关闭并返回 join error。
type multiCloser struct {
	closers []io.Closer
}

func (m *multiCloser) Close() error {
	var errs []error
	for _, c := range m.closers {
		if c == nil {
			continue
		}
		if err := c.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
