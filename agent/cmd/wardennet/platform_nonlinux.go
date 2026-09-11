//go:build !linux
// +build !linux

package main

import "github.com/wardennet/agent/internal/ipsetutil"

// newIPSetClient 在非 Linux 平台返回内存 Mock 客户端。
func newIPSetClient() ipsetutil.Client {
	return ipsetutil.NewMemClient()
}

// platformInit 在非 Linux 平台为空实现。
func platformInit(lg interface{ Info(string, ...interface{}); Warn(string, ...interface{}) }) {
	// 非 Linux 平台无需 iptables
}

// platformShutdown 在非 Linux 平台为空实现。
func platformShutdown(lg interface{ Info(string, ...interface{}); Warn(string, ...interface{}) }) {
	// 非 Linux 平台无需清理 iptables
}
