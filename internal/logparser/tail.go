// Package logparser - tail.go 实现日志文件持续 tail、断点续读与轮转检测。
// 设计要点：
//   - 状态 (inode, offset) 持久化到 JSON 文件，进程重启从断点续读
//   - Linux 下 syscall.Stat_t.Ino 准确识别轮转；Windows 退化为 size 变小检测
//   - 半行处理：未读到 \n 的部分回退 offset 与 fd 位置，下次 poll 续读
//   - poll 间隔可配置（默认 1s），不引入 fsnotify 外部依赖
//   - 状态持久化降频：默认 10s 写一次磁盘，减少 IO
//   - 背压控制：channel 满时非阻塞丢弃，记录丢弃数，定期告警
package logparser

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultPollInterval 默认轮询间隔。可被 Tail.poll 覆盖。
const DefaultPollInterval = 1 * time.Second

// DefaultPersistInterval 默认状态持久化间隔（降频写盘）。
const DefaultPersistInterval = 10 * time.Second

// DefaultDropLogThreshold 丢弃日志的告警阈值（每 N 条丢弃打印一次）。
const DefaultDropLogThreshold = 100

// ErrClosed 表示 Tail 已关闭，不能再 poll。
var ErrClosed = errors.New("tail closed")

// LogFn 日志回调，避免 tail 包依赖具体 logger。
// level: "debug" | "info" | "warn" | "error"
type LogFn func(level, format string, args ...interface{})

// tailState 持久化到 JSON 文件的断点状态。
type tailState struct {
	Inode   uint64    `json:"inode"`   // Linux 文件 inode；Windows 为 0
	Offset  int64     `json:"offset"`  // 已读偏移
	Updated time.Time `json:"updated"` // 上次更新时间
}

// Tail 持续 tail 单个日志文件。
type Tail struct {
	path      string
	statePath string
	parser    Parser
	poll      time.Duration

	persistInterval    time.Duration // 状态持久化间隔
	lastPersist        time.Time     // 上次持久化时间
	dropLogThreshold   int64         // 丢弃日志告警阈值
	dropCount          atomic.Int64  // 累计丢弃数
	dropNotified       atomic.Int64  // 上次告警时的丢弃数（用于去重）

	// v1.2 新增：截断/轮转检测指标
	truncatedCount atomic.Int64  // 累计检测到的截断/轮转次数
	lastTruncatedAt time.Time    // 上次检测到截断的时间

	logFn LogFn // 日志回调（nil 时静默）

	mu     sync.Mutex
	file   *os.File
	state  tailState
	closed bool
}

// NewTail 创建 tail。statePath 为断点状态 JSON 文件路径。
// parser 为 nil 时跳过解析，直接发送 RawLine 包装的 Event。
// poll <= 0 时使用 DefaultPollInterval。
func NewTail(path, statePath string, parser Parser, poll time.Duration) *Tail {
	if poll <= 0 {
		poll = DefaultPollInterval
	}
	return &Tail{
		path:             path,
		statePath:        statePath,
		parser:           parser,
		poll:             poll,
		persistInterval:  DefaultPersistInterval,
		dropLogThreshold: DefaultDropLogThreshold,
	}
}

// SetLogFn 设置日志回调函数。
func (t *Tail) SetLogFn(fn LogFn) {
	t.logFn = fn
}

// SetPersistInterval 覆盖默认持久化间隔。<=0 时恢复默认值。
func (t *Tail) SetPersistInterval(d time.Duration) {
	if d <= 0 {
		t.persistInterval = DefaultPersistInterval
		return
	}
	t.persistInterval = d
}

// DroppedCount 返回累计丢弃的事件数（channel 背压时被丢弃的行数）。
func (t *Tail) DroppedCount() int64 {
	return t.dropCount.Load()
}

// TruncatedCount 返回累计检测到的截断/轮转次数。
// 每次 inode 变化（Linux）或 size 变小（Windows fallback）都会递增。
func (t *Tail) TruncatedCount() int64 {
	return t.truncatedCount.Load()
}

// LastTruncatedAt 返回上次检测到截断/轮转的时间。零值 time.Time 表示从未发生。
func (t *Tail) LastTruncatedAt() time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastTruncatedAt
}

// Run 启动 tail 循环，直到 ctx.Done()。lines 接收解析后的 Event。
// 文件不存在时静默等待；inode 变化或 size 变小时识别为轮转，从 0 重读。
// 返回 ctx.Err() 或 ErrClosed。
//
// 每 30s 打印一次心跳日志（如果 logFn 已设置），包含当前 state.Offset / 真实 size / 丢包数，
// 用于快速定位"tail 静默不读新数据"问题。
func (t *Tail) Run(ctx context.Context, lines chan<- Event) error {
	t.mu.Lock()
	t.loadStateLocked()
	t.lastPersist = time.Now()
	t.mu.Unlock()

	defer func() {
		t.mu.Lock()
		if t.file != nil {
			_ = t.file.Close()
			t.file = nil
		}
		_ = t.saveStateLocked()
		t.mu.Unlock()
	}()

	ticker := time.NewTicker(t.poll)
	defer ticker.Stop()

	// 心跳：每 30s 打印一次 tail 状态
	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-heartbeat.C:
			t.logHeartbeat()
		case <-ticker.C:
			if err := t.pollOnce(ctx, lines); err != nil {
				if errors.Is(err, ErrClosed) {
					return err
				}
				// 单次错误不致命，继续
			}
		}
	}
}

// logHeartbeat 打印心跳日志：state.Offset / 真实 size / inode / 丢包累计。
// 用于快速定位"tail 静默不读新数据"问题 — 如果 size 一直增长但 offset 不动，
// 说明 tail 检测逻辑卡住了（Seek 修复前的 bug 就是这种表现）。
func (t *Tail) logHeartbeat() {
	if t.logFn == nil {
		return
	}

	var stat os.FileInfo
	info, err := os.Stat(t.path)
	if err == nil {
		stat = info
	}

	t.mu.Lock()
	stateCopy := t.state
	fileOpen := t.file != nil
	dropped := t.dropCount.Load()
	t.mu.Unlock()

	if stat != nil {
		size := stat.Size()
		gap := size - stateCopy.Offset
		t.logFn("debug", "tail heartbeat path=%s size=%d offset=%d gap=%d inode=%d file_open=%v dropped=%d",
			t.path, size, stateCopy.Offset, gap, stateCopy.Inode, fileOpen, dropped)
		if gap < 0 {
			t.logFn("warn", "tail heartbeat: NEGATIVE GAP (offset > size), possible truncation/rotation not detected!")
		} else if gap > 1024*1024 {
			t.logFn("warn", "tail heartbeat: LARGE GAP (%d bytes unread), consumer may be falling behind", gap)
		}
	} else {
		t.logFn("debug", "tail heartbeat path=%s stat_error=%v offset=%d file_open=%v dropped=%d",
			t.path, err, stateCopy.Offset, fileOpen, dropped)
	}
}

// Close 标记 Tail 为关闭状态，下次 poll 检测到后退出。
// 不阻塞；调用方应配合 ctx 取消让 Run 返回。
func (t *Tail) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	return nil
}

// pollOnce 执行一次文件检查与读取。
func (t *Tail) pollOnce(ctx context.Context, lines chan<- Event) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return ErrClosed
	}
	t.mu.Unlock()

	info, err := os.Stat(t.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // 文件不存在，等下次
		}
		return err
	}
	curInode := getInode(info)
	curSize := info.Size()

	t.mu.Lock()
	defer t.mu.Unlock()

	// 文件未打开：首次启动或轮转后重开
	if t.file == nil {
		return t.openAndReadLocked(ctx, lines, curInode, curSize, false)
	}

	// inode 变化（Linux）：轮转
	if t.state.Inode > 0 && curInode > 0 && curInode != t.state.Inode {
		_ = t.file.Close()
		t.file = nil
		t.state.Offset = 0
		t.state.Inode = 0
		t.lastPersist = time.Time{} // 强制轮转后立即持久化
		t.truncatedCount.Add(1)
		t.lastTruncatedAt = time.Now()
		if t.logFn != nil {
			t.logFn("warn", "tail rotation detected (inode %d → %d) truncation=true", t.state.Inode, curInode)
		}
		return t.openAndReadLocked(ctx, lines, curInode, curSize, true)
	}

	// Windows fallback：size 变小识别轮转
	if (t.state.Inode == 0 || curInode == 0) && curSize < t.state.Offset {
		_ = t.file.Close()
		t.file = nil
		t.state.Offset = 0
		t.state.Inode = 0
		t.lastPersist = time.Time{} // 强制轮转后立即持久化
		t.truncatedCount.Add(1)
		t.lastTruncatedAt = time.Now()
		if t.logFn != nil {
			t.logFn("warn", "tail truncation detected (size %d < offset %d) truncation=true", curSize, t.state.Offset)
		}
		return t.openAndReadLocked(ctx, lines, curInode, curSize, true)
	}

	// 续读新内容
	return t.readNewLocked(ctx, lines, curInode, curSize, false)
}

// openAndReadLocked 打开文件（按 state.Offset 续读）并读新内容。
// truncated 为 true 表示刚检测到截断/轮转，本次读取到的 Event 会标记 Truncated=true。
func (t *Tail) openAndReadLocked(ctx context.Context, lines chan<- Event, inode uint64, size int64, truncated bool) error {
	f, err := os.Open(t.path)
	if err != nil {
		return err
	}
	t.file = f
	t.state.Inode = inode

	// 若 offset 超过当前 size，从 0 读
	if t.state.Offset > size {
		t.state.Offset = 0
	}
	if t.state.Offset > 0 {
		if _, err := f.Seek(t.state.Offset, io.SeekStart); err != nil {
			return err
		}
	}
	return t.readNewLocked(ctx, lines, inode, size, truncated)
}

// readNewLocked 从 state.Offset 位置读取新行，发到 lines channel，更新 state。
// 半行（读到 EOF 但无 \n）会回退 offset 与 fd 位置，下次 poll 续读完整行。
// truncated 为 true 时，本轮发送的所有 Event.Truncated 置 true，用于 detector / plugin 识别数据缺失风险。
func (t *Tail) readNewLocked(ctx context.Context, lines chan<- Event, inode uint64, size int64, truncated bool) error {
	if t.file == nil {
		return nil
	}
	// 没有新内容
	if size <= t.state.Offset {
		return nil
	}

	// 关键：显式 Seek 到 state.Offset，避免 bufio.Reader 预读把 fd 位置推过
	// state.Offset 导致下次 poll 从错误位置开始读漏新行。
	if _, seekErr := t.file.Seek(t.state.Offset, io.SeekStart); seekErr != nil {
		return seekErr
	}

	reader := bufio.NewReader(t.file)
	sentCount := 0 // 本次 poll 发送的事件数
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line, err := reader.ReadString('\n')
		hasNewline := len(line) > 0 && line[len(line)-1] == '\n'

		if hasNewline {
			// 完整一行，推进 offset
			t.state.Offset += int64(len(line))
			t.state.Inode = inode
			t.state.Updated = time.Now()

			clean := line
			if len(clean) > 0 && clean[len(clean)-1] == '\n' {
				clean = clean[:len(clean)-1]
			}
			if len(clean) > 0 && clean[len(clean)-1] == '\r' {
				clean = clean[:len(clean)-1]
			}
			ev, parseErr := t.parseLine(clean)
				if parseErr == nil {
					ev.Truncated = truncated
					if t.sendEvent(ctx, lines, ev) {
						sentCount++
					}
				} else if parseErr != ErrUnparsable {
				// 非预期解析错误（ErrUnparsable 是正常的格式不匹配）
				if t.logFn != nil {
					t.logFn("warn", "log parse error: %v line=%s", parseErr, truncateStr(clean, 100))
				}
			}
			// 解析失败：跳过但仍推进 offset，避免重复
		} else if line != "" {
			// 半行（EOF 且无 \n）：回退 fd 位置到旧 offset，等下次 poll
			oldOffset := t.state.Offset
			if _, seekErr := t.file.Seek(oldOffset, io.SeekStart); seekErr == nil {
				// 成功回退，offset 不推进
				break
			}
			// 回退失败：直接推进 offset 跳过此段（最坏情况丢半行）
			t.state.Offset += int64(len(line))
			break
		}

		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			// 其他错误（如文件被删除），关闭 fd 等 inode 变化或重建
			_ = t.file.Close()
			t.file = nil
			break
		}
	}

	// 降频持久化：轮转后立即持久化，否则按间隔持久化
	if t.shouldPersist() {
		_ = t.saveStateLocked()
		t.lastPersist = time.Now()
	}

	// 如果本次有事件被丢弃，检查是否需要告警
	if dc := t.dropCount.Load(); dc > 0 {
		notified := t.dropNotified.Load()
		threshold := t.dropLogThreshold
		if dc-notified >= threshold {
			t.dropNotified.Store(dc)
			if t.logFn != nil {
				t.logFn("warn", "tail backpressure: dropped %d events (cumulative: %d) from %s",
					dc-notified, dc, t.path)
			}
		}
	}

	_ = sentCount // sentCount 用于调试，未来可扩展

	return nil
}

// sendEvent 非阻塞发送事件到 channel。
// channel 满时丢弃并计数，返回 false 表示丢弃。
func (t *Tail) sendEvent(ctx context.Context, lines chan<- Event, ev Event) bool {
	select {
	case <-ctx.Done():
		return false
	case lines <- ev:
		return true
	default:
		// channel 满，丢弃事件
		t.dropCount.Add(1)
		return false
	}
}

// shouldPersist 判断是否需要立即持久化状态。
// 条件：距上次持久化 >= persistInterval，或轮转后（lastPersist 为零值）。
func (t *Tail) shouldPersist() bool {
	if t.lastPersist.IsZero() {
		return true
	}
	return time.Since(t.lastPersist) >= t.persistInterval
}

// parseLine 调用 parser 解析；parser 为 nil 时构造 RawLine-only Event。
func (t *Tail) parseLine(line string) (Event, error) {
	if t.parser == nil {
		return Event{RawLine: line, Timestamp: time.Now()}, nil
	}
	return t.parser.Parse(line)
}

// loadStateLocked 从 statePath 加载断点状态。文件不存在或损坏时静默。
func (t *Tail) loadStateLocked() {
	data, err := os.ReadFile(t.statePath)
	if err != nil {
		return
	}
	var s tailState
	if err := json.Unmarshal(data, &s); err != nil {
		return
	}
	t.state = s
}

// saveStateLocked 持久化断点状态到 statePath。目录不存在时创建。
func (t *Tail) saveStateLocked() error {
	if t.statePath == "" {
		return nil
	}
	dir := filepath.Dir(t.statePath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	data, err := json.Marshal(t.state)
	if err != nil {
		return err
	}
	return os.WriteFile(t.statePath, data, 0o644)
}

// getInode 跨平台获取 inode。Linux/Unix 上 info.Sys() 是 *syscall.Stat_t 含 Ino 字段；
// 反射访问避免直接 import 平台特定 syscall 包。
// Windows 不提供 Ino 字段，返回 0（依赖 size 变小识别轮转）。
func getInode(info os.FileInfo) uint64 {
	sys := info.Sys()
	if sys == nil {
		return 0
	}
	v := reflect.ValueOf(sys)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	f := v.FieldByName("Ino")
	if !f.IsValid() {
		return 0
	}
	switch f.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return f.Uint()
	}
	return 0
}

// truncateStr 截断字符串到指定长度，用于日志输出。
func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
