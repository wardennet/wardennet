//go:build !linux
// +build !linux

package portscan

import "errors"

// newIptablesSource returns error on non-Linux platforms.
// Real implementation lives in source_linux.go (linux build tag).
func newIptablesSource(cfg PortScanConfig) (Source, error) {
	return nil, errors.New("iptables source requires Linux")
}
