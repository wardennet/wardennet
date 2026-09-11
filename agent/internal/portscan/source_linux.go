//go:build linux
// +build linux

package portscan

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	srcRe = regexp.MustCompile(`\bSRC=(\S+)`)
	dptRe = regexp.MustCompile(`\bDPT=(\d+)`)
)

// linuxLogSource tails syslog for iptables LOG entries.
// Requires: iptables -I INPUT -j LOG --log-prefix "[PORT_SCAN]: " --log-level 4
type linuxLogSource struct {
	logPath   string
	logPrefix string
	events    chan RawPortEvent
	stop      chan struct{}
	once      sync.Once
	wg        sync.WaitGroup
}

func newLinuxLogSource(cfg PortScanConfig) (Source, error) {
	if cfg.LogPath == "" {
		return nil, fmt.Errorf("portscan.log_path not configured")
	}
	if _, err := os.Stat(cfg.LogPath); err != nil {
		return nil, fmt.Errorf("portscan.log_path %s not accessible: %w", cfg.LogPath, err)
	}
	prefix := cfg.LogPrefix
	if prefix == "" {
		prefix = "[PORT_SCAN]: "
	}
	s := &linuxLogSource{
		logPath:   cfg.LogPath,
		logPrefix: prefix,
		events:    make(chan RawPortEvent, 1024),
		stop:      make(chan struct{}),
	}
	return s, nil
}

// Start begins tailing the log file. Returns nil on success; the goroutine
// handles EOF/rotation/re-open internally.
func (s *linuxLogSource) Start() error {
	s.wg.Add(1)
	go s.tailLoop()
	return nil
}

func (s *linuxLogSource) Stop() {
	s.once.Do(func() { close(s.stop) })
	s.wg.Wait()
	close(s.events)
}

func (s *linuxLogSource) Events() chan RawPortEvent {
	return s.events
}

func (s *linuxLogSource) tailLoop() {
	defer s.wg.Done()

	for {
		select {
		case <-s.stop:
			return
		default:
		}

		f, err := os.Open(s.logPath)
		if err != nil {
			select {
			case <-s.stop:
				return
			case <-time.After(3 * time.Second):
				continue
			}
		}

		_, _ = f.Seek(0, io.SeekEnd)
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 1024*1024), 8*1024*1024)

		for {
			select {
			case <-s.stop:
				f.Close()
				return
			default:
			}

			if !scanner.Scan() {
				// EOF or error; sleep and reopen
				_ = f.Close()
				select {
				case <-s.stop:
					return
				case <-time.After(2 * time.Second):
				}
				break
			}

			line := scanner.Text()
			if !strings.Contains(line, s.logPrefix) {
				continue
			}

			ev, ok := parseNetfilterLine(line)
			if !ok {
				continue
			}
			ev.Timestamp = time.Now().Unix()

			select {
			case s.events <- ev:
			case <-s.stop:
				return
			}
		}
	}
}

func parseNetfilterLine(line string) (RawPortEvent, bool) {
	srcMatch := srcRe.FindStringSubmatch(line)
	dptMatch := dptRe.FindStringSubmatch(line)
	if len(srcMatch) < 2 || len(dptMatch) < 2 {
		return RawPortEvent{}, false
	}
	port, err := strconv.Atoi(dptMatch[1])
	if err != nil || port <= 0 || port > 65535 {
		return RawPortEvent{}, false
	}
	return RawPortEvent{SrcIP: srcMatch[1], DstPort: port}, true
}
