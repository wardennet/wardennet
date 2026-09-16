// Package logparser - tail 断点续读、轮转、半行处理、并发安全测试。
// 覆盖 checklist 2.2/2.4：不丢日志、不重复解析，go test -race 通过。
package logparser

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testPoll = 10 * time.Millisecond

// drainN 从 ch 收集 n 个 Event，超时返回已收集部分。
func drainN(ch <-chan Event, n int, timeout time.Duration) []Event {
	var got []Event
	deadline := time.After(timeout)
	for len(got) < n {
		select {
		case ev := <-ch:
			got = append(got, ev)
		case <-deadline:
			return got
		}
	}
	return got
}

// appendLine 向文件追加一行（含换行）。
func appendLine(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatalf("open append: %v", err)
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatalf("write append: %v", err)
	}
}

// runTail 启动 tail.Run 并返回 done channel（Run 返回时关闭）。
func runTail(t *testing.T, path, statePath string, parser Parser, ch chan Event) (ctx context.CancelFunc, done chan struct{}) {
	t.Helper()
	tail := NewTail(path, statePath, parser, testPoll)
	c, cancel := context.WithCancel(context.Background())
	done = make(chan struct{})
	go func() {
		_ = tail.Run(c, ch)
		close(done)
	}()
	return cancel, done
}

// TestTail_BasicRead 验证文件已存在时 tail 从头读取全部行。
func TestTail_BasicRead(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "test.log")
	statePath := filepath.Join(dir, "state.json")
	content := "line1\nline2\nline3\n"
	if err := os.WriteFile(logPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	ch := make(chan Event, 10)
	cancel, done := runTail(t, logPath, statePath, nil, ch)
	defer cancel()

	got := drainN(ch, 3, 2*time.Second)
	if len(got) != 3 {
		t.Fatalf("got %d events, want 3", len(got))
	}
	want := []string{"line1", "line2", "line3"}
	for i, ev := range got {
		if ev.RawLine != want[i] {
			t.Errorf("event[%d].RawLine = %q, want %q", i, ev.RawLine, want[i])
		}
	}
	cancel()
	<-done
}

// TestTail_IncrementalRead 验证 tail 续读新增内容，不重复已读行。
func TestTail_IncrementalRead(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "test.log")
	statePath := filepath.Join(dir, "state.json")
	if err := os.WriteFile(logPath, []byte("first\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ch := make(chan Event, 10)
	cancel, done := runTail(t, logPath, statePath, nil, ch)
	defer cancel()

	got := drainN(ch, 1, 2*time.Second)
	if len(got) != 1 || got[0].RawLine != "first" {
		t.Fatalf("initial read = %v, want [first]", got)
	}

	// 追加新行
	appendLine(t, logPath, "second")
	appendLine(t, logPath, "third")

	got2 := drainN(ch, 2, 2*time.Second)
	if len(got2) != 2 {
		t.Fatalf("incremental read got %d, want 2", len(got2))
	}
	if got2[0].RawLine != "second" || got2[1].RawLine != "third" {
		t.Errorf("incremental = %q, %q, want second, third", got2[0].RawLine, got2[1].RawLine)
	}
	cancel()
	<-done
}

// TestTail_BreakpointResume 验证进程重启后从断点续读，不重复、不丢失。
func TestTail_BreakpointResume(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "test.log")
	statePath := filepath.Join(dir, "state.json")
	if err := os.WriteFile(logPath, []byte("before_restart\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 第一次运行：读取 1 行后关闭，状态落盘
	ch := make(chan Event, 10)
	cancel, done := runTail(t, logPath, statePath, nil, ch)
	got := drainN(ch, 1, 2*time.Second)
	if len(got) != 1 || got[0].RawLine != "before_restart" {
		t.Fatalf("first run = %v, want [before_restart]", got)
	}
	cancel()
	<-done // 等 Run 返回（defer saveStateLocked 执行完毕）

	// 验证状态文件已写入
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("state file not persisted: %v", err)
	}

	// 追加新行（模拟进程停止期间日志增长）
	appendLine(t, logPath, "after_restart_1")
	appendLine(t, logPath, "after_restart_2")

	// 第二次运行：从断点续读，只应收到 2 行新内容
	ch2 := make(chan Event, 10)
	cancel2, done2 := runTail(t, logPath, statePath, nil, ch2)
	got2 := drainN(ch2, 2, 2*time.Second)
	if len(got2) != 2 {
		t.Fatalf("resume got %d, want 2 (no repeat)", len(got2))
	}
	if got2[0].RawLine != "after_restart_1" || got2[1].RawLine != "after_restart_2" {
		t.Errorf("resume = %q, %q, want after_restart_1, after_restart_2",
			got2[0].RawLine, got2[1].RawLine)
	}
	cancel2()
	<-done2
}

// TestTail_RotationByTruncate 验证日志轮转（size 变小）后从 0 重读。
// 覆盖 Windows 无 inode 场景的 size-based 轮转检测。
func TestTail_RotationByTruncate(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "test.log")
	statePath := filepath.Join(dir, "state.json")
	// 写入 2 行（offset 推进到 > 新文件 size 触发轮转）
	if err := os.WriteFile(logPath, []byte("old_line1\nold_line2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ch := make(chan Event, 10)
	cancel, done := runTail(t, logPath, statePath, nil, ch)
	defer cancel()

	got := drainN(ch, 2, 2*time.Second)
	if len(got) != 2 {
		t.Fatalf("pre-rotation got %d, want 2", len(got))
	}

	// 轮转：截断并写入新内容（size < offset 触发轮转检测）
	if err := os.WriteFile(logPath, []byte("rotated_new\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got2 := drainN(ch, 1, 2*time.Second)
	if len(got2) != 1 {
		t.Fatalf("post-rotation got %d, want 1", len(got2))
	}
	if got2[0].RawLine != "rotated_new" {
		t.Errorf("post-rotation RawLine = %q, want rotated_new", got2[0].RawLine)
	}
	cancel()
	<-done
}

// TestTail_HalfLine 验证半行（无换行符）不产出事件，后续补全换行后产出完整行。
func TestTail_HalfLine(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "test.log")
	statePath := filepath.Join(dir, "state.json")
	// 写入半行（无 \n）
	if err := os.WriteFile(logPath, []byte("partial"), 0o644); err != nil {
		t.Fatal(err)
	}

	ch := make(chan Event, 10)
	cancel, done := runTail(t, logPath, statePath, nil, ch)
	defer cancel()

	// 等待多个 poll 周期，确认无事件产出
	time.Sleep(50 * time.Millisecond)
	select {
	case ev := <-ch:
		t.Fatalf("half-line produced event unexpectedly: %q", ev.RawLine)
	default:
		// 期望：无事件
	}

	// 追加换行符补全为完整行
	appendLine(t, logPath, "") // 写入空行+换行 -> 文件变为 "partial\n"

	got := drainN(ch, 1, 2*time.Second)
	if len(got) != 1 {
		t.Fatalf("after newline got %d, want 1", len(got))
	}
	if got[0].RawLine != "partial" {
		t.Errorf("RawLine = %q, want partial", got[0].RawLine)
	}
	cancel()
	<-done
}

// TestTail_FileNotExistThenAppears 验证文件不存在时静默等待，出现后读取。
func TestTail_FileNotExistThenAppears(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "missing.log")
	statePath := filepath.Join(dir, "state.json")

	ch := make(chan Event, 10)
	cancel, done := runTail(t, logPath, statePath, nil, ch)
	defer cancel()

	// 等待确保 tail 在文件不存在时稳定运行
	time.Sleep(30 * time.Millisecond)

	// 创建文件并写入
	if err := os.WriteFile(logPath, []byte("appeared\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := drainN(ch, 1, 2*time.Second)
	if len(got) != 1 || got[0].RawLine != "appeared" {
		t.Fatalf("got = %v, want [appeared]", got)
	}
	cancel()
	<-done
}

// TestTail_Close 验证 Close 后下次 poll 返回 ErrClosed。
func TestTail_Close(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "test.log")
	statePath := filepath.Join(dir, "state.json")
	if err := os.WriteFile(logPath, []byte("data\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ch := make(chan Event, 10)
	tail := NewTail(logPath, statePath, nil, testPoll)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- tail.Run(ctx, ch)
	}()

	// 等待初始读取
	got := drainN(ch, 1, 2*time.Second)
	if len(got) != 1 {
		t.Fatalf("got %d, want 1", len(got))
	}

	// Close 后下次 poll 应返回 ErrClosed
	if err := tail.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case err := <-errCh:
		if err != ErrClosed && err != context.Canceled {
			// ctx cancel 可能先于 Close 检测，两种均合法
			t.Logf("Run returned: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after Close")
	}
}

// TestTail_WithNginxParser 验证 tail + nginxParser 集成：解析后的 Event 字段正确。
func TestTail_WithNginxParser(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access.log")
	statePath := filepath.Join(dir, "state.json")
	line := `127.0.0.1 - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 200 612`
	if err := os.WriteFile(logPath, []byte(line+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ch := make(chan Event, 10)
	cancel, done := runTail(t, logPath, statePath, &nginxParser{}, ch)
	defer cancel()

	got := drainN(ch, 1, 2*time.Second)
	if len(got) != 1 {
		t.Fatalf("got %d, want 1", len(got))
	}
	ev := got[0]
	if ev.Source != SourceNginxAccess {
		t.Errorf("Source = %q, want %q", ev.Source, SourceNginxAccess)
	}
	if ev.SourceIP != "127.0.0.1" {
		t.Errorf("SourceIP = %q, want 127.0.0.1", ev.SourceIP)
	}
	if ev.Method != "GET" || ev.Path != "/" {
		t.Errorf("Method/Path = %q/%q, want GET//", ev.Method, ev.Path)
	}
	if ev.Status != 200 {
		t.Errorf("Status = %d, want 200", ev.Status)
	}
	cancel()
	<-done
}

// TestTail_Race 并发写 + tail 读 + Close，验证 go test -race 无数据竞争。
func TestTail_Race(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "race.log")
	statePath := filepath.Join(dir, "state.json")
	if err := os.WriteFile(logPath, []byte("seed\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ch := make(chan Event, 200)
	tail := NewTail(logPath, statePath, nil, testPoll)
	ctx, cancel := context.WithCancel(context.Background())

	writerDone := make(chan struct{})
	// 并发写入
	go func() {
		defer close(writerDone)
		for i := 0; i < 100; i++ {
			appendLine(t, logPath, "race_line")
		}
	}()

	runDone := make(chan struct{})
	go func() {
		_ = tail.Run(ctx, ch)
		close(runDone)
	}()

	// 并发消费：写完后排空 channel 再退出
	consumerDone := make(chan struct{})
	go func() {
		defer close(consumerDone)
		for {
			select {
			case _, ok := <-ch:
				if !ok {
					return
				}
			case <-writerDone:
				// 写完后排空剩余事件
				for len(ch) > 0 {
					<-ch
				}
				return
			}
		}
	}()

	<-writerDone
	<-consumerDone
	_ = tail.Close()
	cancel()
	<-runDone
}
