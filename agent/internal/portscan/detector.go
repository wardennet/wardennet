package portscan

import (
	"sync"
)

// PortScanTrigger portscan 触发封禁回调。
// srcIP 是被检测到端口扫描的源 IP，score 是本次触发的权重分。
type PortScanTrigger func(srcIP string, score int)

// PortScanDetector detects TCP port scanning by tracking per-IP distinct
// port counts across three sliding windows.
type PortScanDetector interface {
	// Process feeds a single (srcIP, dstPort) event. Returns whether any
	// window was breached and the score contribution.
	Process(srcIP string, dstPort int) (high bool, score int)
	// Close stops background goroutines and releases resources.
	Close()
}

// -------- noopDetector --------

// noopDetector silent fallback when no data source is available or
// the module is disabled. All methods are zero-cost.
type noopDetector struct{}

func (n *noopDetector) Process(srcIP string, dstPort int) (bool, int) { return false, 0 }
func (n *noopDetector) Close()                                        {}

// -------- portScanDetector --------

type portScanDetector struct {
	cfg     PortScanConfig
	tracker *PortWindowTracker
	source  Source
	trigger PortScanTrigger // 检测到扫描时触发外部封禁回调
	fired   sync.Map        // 已触发封禁的 IP（value: 触发次数），用于去重
	wg      sync.WaitGroup
	stop    chan struct{}
	once    sync.Once
}

// NewPortScanDetector creates a PortScanDetector from config.
//
// trigger 为 nil 时端口扫描事件只记录不触发封禁。
//
// Returns noopDetector if:
//   - config.Enabled is false
//   - data source cannot be created or started
// In either case it logs a warning to stderr but does not return an error,
// allowing the Agent to continue running with port scan detection disabled.
func NewPortScanDetector(cfg PortScanConfig, trigger PortScanTrigger) (PortScanDetector, error) {
	if !cfg.Enabled {
		return &noopDetector{}, nil
	}
	if err := cfg.Validate(); err != nil {
		portscanLogger.Printf("config validation failed: %v → disabling portscan", err)
		return &noopDetector{}, nil
	}

	src, err := NewSource(cfg)
	if err != nil {
		portscanLogger.Printf("data source unavailable (%v) → portscan disabled", err)
		return &noopDetector{}, nil
	}

	if err := src.Start(); err != nil {
		portscanLogger.Printf("data source start failed (%v) → portscan disabled", err)
		return &noopDetector{}, nil
	}

	tracker := NewPortWindowTracker(cfg.Windows)
	d := &portScanDetector{
		cfg:     cfg,
		tracker: tracker,
		source:  src,
		trigger: trigger,
		stop:    make(chan struct{}),
	}
	d.wg.Add(1)
	go d.consumeEvents()
	return d, nil
}

// consumeEvents reads from the source channel, records port hits into the
// tracker, and triggers the external callback when any window threshold is breached.
func (d *portScanDetector) consumeEvents() {
	defer d.wg.Done()
	for {
		select {
		case <-d.stop:
			return
		case ev, ok := <-d.source.Events():
			if !ok {
				return
			}
			if ev.Timestamp > 0 {
				d.tracker.RecordAt(ev.SrcIP, ev.DstPort, ev.Timestamp)
			} else {
				d.tracker.Record(ev.SrcIP, ev.DstPort)
			}
			// 检查是否超限
			counts := d.tracker.Count(ev.SrcIP)
			for i, w := range d.cfg.Windows {
				if counts[i] > w.MaxPorts {
					// 只在首次触发或超过 5 次时回调（封禁幂等，但日志要克制）
					if d.trigger != nil {
						if _, already := d.fired.Load(ev.SrcIP); !already {
							d.fired.Store(ev.SrcIP, 1)
							d.trigger(ev.SrcIP, d.cfg.Weight)
						}
					}
					break
				}
			}
		}
	}
}

// Process checks whether srcIP has breached any port threshold.
// Useful for in-process callers that already parsed events themselves.
func (d *portScanDetector) Process(srcIP string, dstPort int) (bool, int) {
	if srcIP == "" {
		return false, 0
	}
	d.tracker.Record(srcIP, dstPort)
	counts := d.tracker.Count(srcIP)
	for i, w := range d.cfg.Windows {
		if counts[i] > w.MaxPorts {
			return true, d.cfg.Weight
		}
	}
	return false, 0
}

// Close stops source consumption and the tracker's evict loop.
func (d *portScanDetector) Close() {
	d.once.Do(func() { close(d.stop) })
	if d.source != nil {
		d.source.Stop()
	}
	d.wg.Wait()
	if d.tracker != nil {
		d.tracker.Close()
	}
}
