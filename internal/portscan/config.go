// Package portscan detects TCP port scanning by tracking distinct port access
// cardinality per source IP across three sliding windows.
//
// This package has ZERO cross-internal-package dependencies — only stdlib.
// It mirrors configuration structures (PortScanConfig, PortWindow) so the
// main package assigns fields during integration (no circular imports).
package portscan

// PortWindow a single sliding window configuration for port scan detection.
type PortWindow struct {
	Size     int `yaml:"size"`      // window size in seconds
	MaxPorts int `yaml:"max_ports"` // allowed distinct ports within this window
}

// PortScanConfig configuration for the port scan detection module.
// Source selects the data acquisition strategy:
//   "auto"       — try iptables LOG first (Linux), fallback to pcap, then noop
//   "iptables"  — tail syslog for iptables --log-prefix output (Linux only)
//   "pcap"       — capture SYN packets via libpcap (cross-platform, requires gopacket)
//   "disabled"   — explicit no-op
type PortScanConfig struct {
	Enabled    bool         `yaml:"enabled"`
	Source     string       `yaml:"source"`     // auto | iptables | pcap | disabled
	LogPath    string       `yaml:"log_path"`   // syslog path for iptables LOG mode
	LogPrefix  string       `yaml:"log_prefix"` // iptables --log-prefix value
	BlockTTL   int          `yaml:"block_ttl"`  // seconds to block
	Weight     int          `yaml:"weight"`     // score contribution on trigger
	PcapIface  string       `yaml:"pcap_iface"` // interface for pcap mode
	PcapFilter string       `yaml:"pcap_filter"` // BPF filter for pcap mode
	Windows    [3]PortWindow `yaml:"windows"`
}

// DefaultPortScanConfig returns a disabled-by-default configuration.
// Users must set enabled:true and configure their data source to activate.
func DefaultPortScanConfig() PortScanConfig {
	return PortScanConfig{
		Enabled:    false,
		Source:     "auto",
		LogPath:    "/var/log/syslog",
		LogPrefix:  "[PORT_SCAN]: ",
		BlockTTL:   3600,
		Weight:     30,
		PcapIface:  "any",
		PcapFilter: "tcp[tcpflags] & tcp-syn != 0",
		Windows: [3]PortWindow{
			{Size: 5, MaxPorts: 5},
			{Size: 30, MaxPorts: 15},
			{Size: 120, MaxPorts: 40},
		},
	}
}

// Validate checks basic configuration validity.
func (c *PortScanConfig) Validate() error {
	src := c.Source
	if src == "" {
		src = "auto"
		c.Source = src
	}
	switch src {
	case "auto", "iptables", "pcap", "disabled":
	default:
		return ErrInvalidSource
	}
	if c.BlockTTL < 0 {
		return ErrNegativeTTL
	}
	if c.Weight < 0 {
		return ErrNegativeWeight
	}
	for i, w := range c.Windows {
		if w.Size <= 0 {
			return ErrInvalidWindowSize(i)
		}
		if w.MaxPorts < 0 {
			return ErrNegativeMaxPorts(i)
		}
	}
	return nil
}
