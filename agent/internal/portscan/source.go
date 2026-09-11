package portscan

// Source abstracts TCP scan data acquisition.
// Implementations read netfilter logs or capture SYN packets via pcap.
type Source interface {
	// Start begins data acquisition. Blocks if source is long-running.
	Start() error
	// Stop terminates acquisition and releases resources.
	Stop()
	// Events returns the channel that streams parsed port events.
	// Channel is closed when Stop is called.
	Events() chan RawPortEvent
}

// RawPortEvent a single parsed port access event.
type RawPortEvent struct {
	SrcIP     string
	DstPort   int
	Timestamp int64 // Unix seconds; 0 if unknown
}
