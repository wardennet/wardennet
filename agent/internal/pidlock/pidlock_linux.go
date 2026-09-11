//go:build linux

// Package pidlock — Linux 平台真实实现：syscall.Flock 内核级互斥。
package pidlock

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Acquire 尝试获取单实例锁。
//
// 返回值：
//   - (*Lock, nil) 成功拿到锁，调用方 defer lock.Release() 即可。
//   - (nil, error) 另一个活着的 agent 进程持有锁，或其他 IO 错误。
//
// 僵尸处理：如果 PID 文件存在但里面的 PID 已死亡（/proc/PID 不存在），
// 说明上次进程崩溃没来得及清理。Linux flock 锁只在持有 fd 存活时有效，
// 进程死亡后内核已自动解锁，所以新进程的 flock 会直接成功，覆盖写入新 PID。
func Acquire() (*Lock, error) {
	pidFile := resolvePidFile()

	// 确保父目录存在
	dir := filepath.Dir(pidFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		fb := filepath.Join(fallbackDir, "wardennet.pid")
		fbDir := filepath.Dir(fb)
		_ = os.MkdirAll(fbDir, 0755)
		pidFile = fb
	}

	f, err := os.OpenFile(pidFile, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return nil, fmt.Errorf("pidlock open %s: %w", pidFile, err)
	}

	// 非阻塞排他锁
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if err == syscall.EWOULDBLOCK || err == syscall.EAGAIN {
			otherPid := readPidFromFile(pidFile)
			if otherPid > 0 {
				return nil, fmt.Errorf("pidlock: another agent is running (pid %d). lock file: %s",
					otherPid, pidFile)
			}
			return nil, fmt.Errorf("pidlock: another agent is running. lock file: %s", pidFile)
		}
		return nil, fmt.Errorf("pidlock flock: %w", err)
	}

	// 拿到锁了，覆盖写入当前 PID
	myPid := os.Getpid()
	_ = f.Truncate(0)
	if _, err := f.Seek(0, 0); err == nil {
		_, _ = f.WriteString(fmt.Sprintf("%d\n", myPid))
		_ = f.Sync()
	}

	return &Lock{fd: f, pidFile: pidFile, held: true}, nil
}

// Release 释放锁并清理 PID 文件。
// 进程退出时内核会自动释放，显式调用是为了 defer 链路完整。
func (l *Lock) Release() error {
	if !l.held || l.fd == nil {
		return nil
	}
	_ = syscall.Flock(int(l.fd.Fd()), syscall.LOCK_UN)
	l.fd.Close()
	l.held = false
	_ = os.Remove(l.pidFile)
	return nil
}
