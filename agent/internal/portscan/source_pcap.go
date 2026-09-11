//go:build linux || darwin || windows
// +build linux darwin windows

package portscan

import "errors"

// pcapSource is a stub that defers real gopacket implementation.
// Real pcap capture (github.com/google/gopacket) is not compiled by default;
// users who need cross-platform port scanning should add the dependency
// and implement a proper source here.
type pcapSource struct {
	events chan RawPortEvent
}

func newPcapSource(cfg PortScanConfig) (Source, error) {
	return nil, errors.New("pcap source not available: requires github.com/google/gopacket")
}
