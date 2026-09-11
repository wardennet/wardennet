//go:build linux
// +build linux

package main

import "github.com/wardennet/agent/internal/ipsetutil"

// newIPSetClient 在 Linux 上返回真实 ipset 客户端。
func newIPSetClient() ipsetutil.Client {
	return ipsetutil.NewLinuxClient("")
}

// newIptablesManager 在 Linux 上创建 iptables 管理器并确保规则存在。
func newIptablesManager() *ipsetutil.IptablesManager {
	mgr := ipsetutil.NewIptablesManager("", ipsetutil.SetBlacklist, "")
	return mgr
}

// platformInit 在 Linux 上执行平台特定初始化。
// 调用顺序：先 EnsureBanRule 再 EnsureWhitelistAcceptRule，
// 因为 iptables -I 每次插到 INPUT 链最顶端，后插入的 Whitelist ACCEPT 排在前面，
// 保证白名单先匹配 → ACCEPT，然后才是黑名单 → DROP。
func platformInit(lg interface{ Info(string, ...interface{}); Warn(string, ...interface{}) }) {
	mgr := newIptablesManager()
	// 先插入 DROP（靠后），让 ACCEPT 后插入排到最前面
	if err := mgr.EnsureBanRule(); err != nil {
		lg.Warn("iptables ban rule ensure failed", "err", err)
	} else {
		lg.Info("iptables ban rule ensured", "set", ipsetutil.SetBlacklist, "ports", "80,443")
	}
	if err := mgr.EnsureWhitelistAcceptRule(); err != nil {
		lg.Warn("iptables whitelist accept rule ensure failed", "err", err)
	} else {
		lg.Info("iptables whitelist accept rule ensured", "set", ipsetutil.SetWhitelist)
	}
}

// platformShutdown 在 Linux 上执行平台特定清理。
// RemoveBanRule 内部同时移除黑名单 DROP 和白名单 ACCEPT 两条规则。
func platformShutdown(lg interface{ Info(string, ...interface{}); Warn(string, ...interface{}) }) {
	mgr := newIptablesManager()
	if err := mgr.RemoveBanRule(); err != nil {
		lg.Warn("iptables rules removal failed", "err", err)
	} else {
		lg.Info("iptables ban + whitelist accept rules removed")
	}
}
