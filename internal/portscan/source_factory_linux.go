//go:build linux
// +build linux

package portscan

// newIptablesSource wraps the Linux-specific implementation.
// Kept as a separate function so source_factory.go (cross-platform)
// can call it on Linux and fall through on non-Linux.
func newIptablesSource(cfg PortScanConfig) (Source, error) {
	return newLinuxLogSource(cfg)
}
