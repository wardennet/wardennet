//go:build !linux

// Package pidlock — 非 Linux 开发机 stub：不做任何互斥。
// Agent 目标平台是 Linux，此文件仅用于让 go test ./... 在 Windows 上不报错。
//
// 仅 Acquire/Release 为平台相关：
//   - Linux: pidlock_linux.go 用 syscall.Flock 做真实内核级互斥
//   - 其他平台: 本文件返回 held 的空锁（无锁语义）
//
// 类型定义、常量、纯函数（readPidFromFile / resolvePidFile / IsProcessAlive）全部在 pidlock.go 里。
package pidlock

// Acquire 在非 Linux 平台下直接返回一个 held 的锁——不做任何互斥。
func Acquire() (*Lock, error) {
	return &Lock{held: true, pidFile: defaultPidFile}, nil
}

// Release 在非 Linux 平台下是 no-op。
func (l *Lock) Release() error {
	l.held = false
	return nil
}
