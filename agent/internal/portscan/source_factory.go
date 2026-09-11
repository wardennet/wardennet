package portscan

import (
	"fmt"
	"log"
	"os"
)

// NewSource creates a Source based on config.Source.
// On any error, returns nil — caller should fallback to noopDetector.
func NewSource(cfg PortScanConfig) (Source, error) {
	src := cfg.Source
	if src == "" {
		src = "auto"
	}

	switch src {
	case "disabled":
		return nil, ErrSourceUnavailable
	case "iptables":
		return newIptablesSource(cfg)
	case "pcap":
		return newPcapSource(cfg)
	case "auto":
		s, err := newIptablesSource(cfg)
		if err != nil {
			s2, err2 := newPcapSource(cfg)
			if err2 != nil {
				return nil, fmt.Errorf("auto source failed: iptables(%v), pcap(%v)", err, err2)
			}
			return s2, nil
		}
		return s, nil
	default:
		return nil, ErrInvalidSource
	}
}

var portscanLogger = log.New(os.Stderr, "[portscan] ", log.LstdFlags)
