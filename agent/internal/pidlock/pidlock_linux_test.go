// Linux 平台专属测试：真实 flock 语义验证
package pidlock

import (
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
)

func TestAcquire_Double(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("real flock test only on linux")
	}

	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "test.pid")

	// 第一次获取
	f1, err := os.OpenFile(pidFile, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		t.Fatalf("open f1: %v", err)
	}
	defer f1.Close()
	defer os.Remove(pidFile)

	if err := syscall.Flock(int(f1.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("first flock failed: %v", err)
	}
	defer syscall.Flock(int(f1.Fd()), syscall.LOCK_UN)

	// 第二次获取——应该 EWOULDBLOCK
	f2, err := os.OpenFile(pidFile, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		t.Fatalf("open f2: %v", err)
	}
	defer f2.Close()

	err = syscall.Flock(int(f2.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		t.Fatal("second flock should have failed with EWOULDBLOCK/EAGAIN")
	}
	if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
		t.Errorf("expected EWOULDBLOCK/EAGAIN, got %v", err)
	}
}

func TestIsProcessAlive_Linux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("proc test only on linux")
	}
	if !IsProcessAlive(os.Getpid()) {
		t.Errorf("self pid %d should be alive", os.Getpid())
	}
	if IsProcessAlive(99999999) {
		t.Error("nonexistent pid should not be alive")
	}
	if IsProcessAlive(0) {
		t.Error("pid 0 should return false")
	}
}

func TestAcquire_Zombie(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("real flock test only on linux")
	}

	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "test.pid")

	// 先写一个死掉的 PID 进去
	_ = os.WriteFile(pidFile, []byte("99999999\n"), 0644)

	f, err := os.OpenFile(pidFile, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("flock on zombie pidfile should succeed: %v", err)
	}

	_ = f.Truncate(0)
	_, _ = f.Seek(0, 0)
	_, _ = f.WriteString("4242\n")
	_ = f.Sync()

	time.Sleep(50 * time.Millisecond)

	data, _ := os.ReadFile(pidFile)
	if string(data) != "4242\n" {
		t.Errorf("pidfile content = %q, want '4242\\n'", string(data))
	}

	syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
