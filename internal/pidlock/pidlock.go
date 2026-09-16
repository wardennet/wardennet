// Package pidlock 实现单实例文件锁，防止同一台服务器启动多个 agent 进程。
// 使用 syscall.Flock(LOCK_EX | LOCK_NB) 做内核级互斥，不依赖进程间通信。
//
// 设计要点：
//  1. 在 main() 最早期、iptables 初始化之前调用 Acquire()，失败即退出。
//  2. 文件锁是内核级的：进程被 kill -9 后内核自动解锁，不需要清理残留。
//  3. 仍然写入 PID 文件：给运维看哪个 PID 在占用，也支持僵尸检测。
//  4. 进程异常重启时，旧文件残留但锁已释放 → Acquire() 能正常拿到锁，覆盖写入新 PID。
//
// Linux 实现在 pidlock_linux.go；非 Linux 开发环境 stub 在 pidlock_other.go。
package pidlock

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// 硬编码默认 PID 文件路径。不放进 config.yaml —— 互斥是进程级机制，
// 不能让 YAML 拼写错误绕过互斥。运维需要改路径可以软链接。
const (
	defaultPidFile = "/run/wardennet/agent.pid"
	fallbackDir    = "/tmp" // /run/wardennet 不可写时的兜底
)

// Lock 代表一个已获取的文件锁。
// 关闭 fd 即释放锁（进程退出时内核也会自动释放）。
type Lock struct {
	fd      *os.File
	pidFile string
	held    bool
}

// Path 返回实际使用的 PID 文件路径（可能经过 fallback）。
func (l *Lock) Path() string { return l.pidFile }

// resolvePidFile 确定实际使用的 PID 文件路径。
// 默认 /run/wardennet/agent.pid（标准 Linux runtime 位置），
// 目录不可写时 fallback 到 /tmp/wardennet.pid。
func resolvePidFile() string {
	dir := filepath.Dir(defaultPidFile)
	// 检测目录可写：试创建文件
	if f, err := os.CreateTemp(dir, ".pidlock-test"); err == nil {
		f.Close()
		os.Remove(f.Name())
		return defaultPidFile
	}
	return filepath.Join(fallbackDir, "wardennet.pid")
}

// readPidFromFile 尝试从 pidfile 里读出另一个进程的 PID。
// 文件可能不存在、格式不对、或内容不是整数——全部返回 0。
func readPidFromFile(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	s := strings.TrimSpace(string(data))
	p, err := strconv.Atoi(s)
	if err != nil || p <= 0 {
		return 0
	}
	return p
}

// IsProcessAlive 检查给定 PID 是否存活。
// Linux 下通过 /proc/PID 存在性检测，其他平台保守返回 false。
func IsProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil
}
