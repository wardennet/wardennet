package portscan

import "errors"

var (
	ErrInvalidSource     = errors.New("portscan.source must be auto|iptables|pcap|disabled")
	ErrNegativeTTL       = errors.New("portscan.block_ttl must be non-negative")
	ErrNegativeWeight    = errors.New("portscan.weight must be non-negative")
	ErrSourceUnavailable = errors.New("portscan data source unavailable")
)

func ErrInvalidWindowSize(i int) error {
	return errors.New("portscan.windows[" + itoa(i) + "].size must be positive")
}

func ErrNegativeMaxPorts(i int) error {
	return errors.New("portscan.windows[" + itoa(i) + "].max_ports must be non-negative")
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
