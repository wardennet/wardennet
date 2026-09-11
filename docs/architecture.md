# WardenNet Agent Architecture

> Companion docs: [README](../README.md) · [Quick Start](./quick-start.md) · [Configuration](./configuration.md)

---

## Table of Contents

1. [Design Principles](#1-design-principles)
2. [System Layers](#2-system-layers)
3. [Startup Flow](#3-startup-flow)
4. [Data Flow Architecture](#4-data-flow-architecture)
5. [Module Reference](#5-module-reference)
6. [Plugin Interface Contract](#6-plugin-interface-contract)
7. [Feature & Rule Tables](#7-feature--rule-tables)
8. [Core Data Structures](#8-core-data-structures)

---

## 1. Design Principles

| Principle | Description |
|-----------|-------------|
| **Zero external network** | All detection logic runs locally; no HTTP issued when the plugin is absent |
| **Compile-time static** | `CGO_ENABLED=0` static build, single ~4MB artifact |
| **Interface isolation** | Modules are decoupled via Go interfaces; Windows falls back to in-memory mocks automatically |
| **Graceful degradation** | Any component failure does not break the core detection pipeline; missing plugin = NoopPlugin |
| **Security-first** | Unix Socket 0600; idempotent iptables; local whitelist has absolute priority |
| **Data minimization** | Linux Auth events are not uploaded by default; cloud threat scoring returns only scores, not raw details |

---

## 2. System Layers

```
+--------------------------------------------------------------+
|   User-space process (root, managed by systemd)               |
|                                                              |
|   +------+   +------+   +------+   +------+   +------+      |
|   | CLI  |   |Config |   |Logger|   |Stats |   |Plugin|      |
|   ++-----+   ++-----+   ++-----+   ++-----+   ++-----+      |
|    |           |          |          |          |              |
|    v           v          v          v          v              |
|   +---------------------------------------------------+      |
|   |           main.go (orchestration layer)            |      |
|   |   adapter.go (interface bridging) + platform_*.go   |      |
|   +------+------+------+------+------+------+--------+      |
|          |      |      |      |      |      |                |
|          v      v      v      v      v      v                |
|   +-----+  +----+  +---+  +----+  +---+  +----+             |
|   |LogPr|  |Det |  |IPS |  |TTL |  |Snap|  |Clou|  core     |
|   |   sr|  |ector|  |etU |  |    |  |shot|  |dsyn|  modules  |
|   +-----+  +----+  +----+  +----+  +----+  +----+             |
+--------------------------------------------------------------+
                              |
                              v
+--------------------------------------------------------------+
|   Kernel (Linux kernel)                                       |
|   +--------------------------------------------------------+|
|   | ipset: wardennet_blacklist (hash:ip)                    ||
|   | ipset: wardennet_whitelist (hash:net, CIDR + IPv6)      ||
|   | iptables -I INPUT -m set --match-set blacklist DROP     ||
|   +--------------------------------------------------------+|
+--------------------------------------------------------------+
```

---

## 3. Startup Flow

```
main()
  |-- config.Load()              # YAML + built-in defaults merge
  |-- logger.New()               # lumberjack rotation
  |-- plugin.Loader.Load()       # Try libcloudplugin.so (falls back to NoopPlugin)
  |-- logsources.Init()          # Spin tail goroutines per log source
  |-- detector.New()             # Create detector + windows + baseline pre-scan (10min)
  |-- ipsetutil.Manager.New()    # Init ipset + iptables rules on Linux
  |-- ttl.Manager.New()          # TTL expiry + snapshot restore
  |-- snapshot.Manager.New()     # Snapshot persistence goroutine
  |-- cloudsync.New()            # Start heartbeats + Diff when Plugin != nil
  |-- unixsocket.NewServer()     # /var/run/wardennet.sock
  |-- pidlock.Acquire()          # Flock to ensure single instance
  |-- block on signal            # SIGINT/SIGTERM -> graceful Stop
```

---

## 4. Data Flow Architecture

### 4.1 Logs -> Detect -> Block

```
tail goroutine
    |   (polls file size/mtime every N sec)
    v
parser.Registry.Parse(line)     # nginx_access / apache_access / ...
    |   outputs Event{IP, Time, Method, Path, Status, ...}
    v
detector.Detect(event)
    |-- Sliding window scoring (score 0-100)
    |-- Baseline P95 deviation
    |-- 5-dim Consistency co-scoring
    |-- 8-layer false-positive defense
    |-- Multi-event confirmation + freshness check
    v
ipsetutil.Manager.Block(ip)     # idempotent ipset add
    |
    v
ttl.Manager.Add(ip, ttl, source)  # auto-expire countdown
```

### 4.2 Cloud Coordination (optional)

```
plugin.Plugin                   # libcloudplugin.so
    |-- Init(ctx)
    |-- Auth(AuthContext) -> AgentID
    |
    |-- HeartbeatLoop:
    |     |-- Diff(DiffRequest) -> DiffResult
    |     |     |-- threats_global (global pool scores)
    |     |     |-- threats_private (tenant private pool scores)
    |     |     |-- feature updates
    |     |     |-- DecisionWeights (defaults 0.4/0.3/0.3)
    |     |
    |     |-- DecideAll(cloud_score, local_freq, detector_score)
    |     |     cloud * 0.4 + local * 0.3 + detector * 0.3
    |     |     >= 80 -> block, >= 50 -> alert
    |
    |-- ThreatEventReport
    |-- CommandPollAndAck
```

**Hard constraint**: the `cloudsync` package **never** owns HTTP clients, HMAC logic, or credentials — these all live inside `internal/cloudplugin/` (closed). Open-source code only calls through `plugin.Plugin`.

---

## 5. Module Reference

### 5.1 logparser — log ingestion & parsing

| File | Purpose |
|------|---------|
| `parser.go` | `Parser` interface + `Registry` |
| `tail.go` | Poll-based tail with size/mtime checks + 30s heartbeat + seek resume |
| `nginx.go` | Nginx combined / common / main formats |
| `apache.go` | Apache combined / common |
| `tomcat.go` | Tomcat access log |
| `linux_auth.go` | SSH audit events (not uploaded by default) |
| `portscan.go` | SYN/RST pattern detection |
| `custom.go` | Custom regex + group mapping |

Core interface:

```go
type Parser interface {
    Parse(line string) (*Event, error)
    Name() string
}
```

### 5.2 detector — detection engine

Internal sub-files:

| File | Responsibility |
|------|----------------|
| `detector.go` | `Detector` assembly; static whitelist; BlockTrigger; multi-event observation + freshness snapshots |
| `window.go` | 3 sliding windows (10/30/60s) |
| `scorer.go` | 11-dim scoring; empty-Referer hard cap; 401 down-weighting; real-user reward |
| `consistency.go` | 5-dim Consistency scoring |
| `baseline.go` | P95 self-learning + MAD outlier removal + hard pre-screening |
| `resource_baseline.go` | CPU / memory / FD baseline |
| `decode.go` | URL / Unicode / Hex / HTML Entity attack-pattern decoding |
| `detail.go` | Debug-scoring detail logs |
| `featurelist.go` | 3-stage feature-list merge |

Multi-event confirmation (core false-positive defense):

```go
const (
    ObserveWindowSec = 30   // observation window
    MergeWindowSec    = 5    // merge window for consecutive duplicates
    ConfirmCount      = 2    // need >= 2 independent high-score events
)
```

**Freshness check** (v1.4): only increments `count` when at least one of 12 attack-input counters is **actually growing**. Prevents normal user token-expiry + browser-404 from accumulating inside the 30s window and triggering a false block.

### 5.3 ipsetutil — ipset management

| File | Purpose |
|------|---------|
| `client.go` | `Client` interface |
| `client_linux.go` | `os/exec` against `ipset` CLI |
| `client_mem.go` | In-memory mock (Windows dev + tests) |
| `iptables.go` | DROP rule injection; idempotent check |
| `manager.go` | Aggregates blacklist + whitelist + ApplyCloud + ForceBlock |

Key design:

- **Whitelist has absolute priority**: `Contains(ip) == true` skips all detection and blocking
- **Two ipsets**:
  - `wardennet_blacklist` — `hash:ip`, exact match
  - `wardennet_whitelist` — `hash:net`, supports CIDR + IPv6
- **ForceBlock**: `--force` CLI flag bypasses the whitelist for emergency DDoS blocks

### 5.4 ttl — TTL expiry

Countdown expiry triggers automatic `ipset del`:

```go
type Entry struct {
    IP        string
    Source    Source       // Local / Cloud
    ExpiresAt time.Time
    TTL       int          // seconds
}
```

### 5.5 cloudsync — cloud sync orchestration (open side)

**Important**: this package **only orchestrates** — no HTTP, no HMAC, no credentials.

```go
type SyncEngine struct {
    p          plugin.Plugin    // closed-source impl
    ipMgr      *ipsetutil.Manager
    cfg        config.CloudSection
    globalBase string
    globalSeq  int64
    tenantSeq  int64
}
```

60-second loop:

```
Heartbeat -> Diff (dual-layer incremental) -> DecideAll (composite) -> ApplyCloud (ipset)
```

**Composite decision engine**:

```
composite = cloud_score * 0.4 + local_freq * 0.3 + detector_score * 0.3
  >= 80  -> block
  >= 50  -> alert
  <  50  -> ignore
```

Cloud can hot-patch the weights, but their sum must land in [0.5, 1.5] (anti-poisoning check).

### 5.6 plugin — plugin interface (architecture contract)

Full interface lives in `internal/plugin/plugin.go`. 13 core methods:

| Lifecycle | Method |
|-----------|--------|
| Load | `Init(ctx)` |
| Destroy | `Shutdown()` |
| Auth | `Auth(AuthContext) -> AuthResult` |
| Health | `Health() -> Ready` |
| Heartbeat | `Heartbeat()` |
| Sync | `Diff(DiffRequest) -> DiffResult` |
| Snapshot | `FetchFullGlobalSnapshot / FetchTenantSnapshot` |
| Report | `ReportEvent / ReportThreat` |
| Remote cmd | `CommandPoll / CommandAck` |

**Two integration modes**:

1. **Default** `go build ./cmd/wardennet` — runtime `plugin.Open("libcloudplugin.so")`
2. **Compile-time** `go build -tags=plugin ./cmd/wardennet` — CloudPlugin compiled into the binary (recommended for production: `wardennet_linux_static`)

### 5.7 Other modules

| Module | Purpose |
|--------|---------|
| `cli` | Command registry + handlers |
| `unixsocket` | `/var/run/wardennet.sock` JSON protocol (0600) |
| `config` | YAML loading + defaults merge + dual-format feature lists |
| `logger` | lumberjack rotation + levels |
| `stats` | Statistics collector + periodic report |
| `features` | 3-stage feature-list manager |
| `pidlock` | `syscall.Flock` + PID file for single-instance mutual exclusion |
| `snapshot` | TTL + blacklist snapshot serialize/restore |
| `portscan` | SYN/RST port-scan detection (pcap + pure socket) |

---

## 6. Plugin Interface Contract

This is the contract that the closed-source CloudPlugin must satisfy. Open-source code must **never** bypass this interface.

### 6.1 Plugin interface

```go
type Plugin interface {
    // Lifecycle
    Init(ctx context.Context) error
    Shutdown() error

    // Auth
    Auth(AuthContext) AuthResult

    // Health
    Health() bool

    // Sync
    Heartbeat()
    Diff(DiffRequest) DiffResult
    FetchFullGlobalSnapshot(ctx context.Context) (SnapshotResult, error)
    FetchTenantSnapshot(ctx context.Context) (SnapshotResult, error)

    // Report
    ReportEvent(ReportEvent) error
    ReportThreat(ThreatReport) error

    // Remote commands
    CommandPoll(ctx context.Context) ([]Command, error)
    CommandAck(commandID string, result string) error
}
```

### 6.2 Data carriers

- `ThreatScore{IP, Score(0-100), VoteCount, Source}` — cloud only returns scores, never issues raw block commands
- `DiffResult{Global, Tenant}` — dual-layer incremental result
- `DecisionWeightsConfig{Cloud, Local, Detector}` — cloud-hot-patchable weights

### 6.3 NoopPlugin

Built into open-source, auto-enabled when the real plugin is absent. All methods are no-ops; the Agent degrades to pure local mode.

---

## 7. Feature & Rule Tables

### 7.1 Default scoring weights

| Dimension | Type | Weight | Notes |
|-----------|------|--------|-------|
| dangerous_pattern | Absolute | 5 | URL/Unicode/Hex/HTML-Entity decoded attack patterns |
| dangerous_method | Absolute | 3 | PUT / DELETE / TRACE / CONNECT |
| file_upload | Absolute | 20 | Large uploads or common upload paths |
| Other 8 | P95 relative | Self-adaptive | Engine auto-learns each dimension |

### 7.2 False-positive hard caps

| Rule | Value | Notes |
|------|-------|-------|
| Empty-Referer hard cap | `score_high / 4` | 12.5 when score_high=50 |
| 401 standalone weight | 1/5 + cap | Weight reduced; same `score_high / 4` cap |
| Baseline pre-screen isLikelyAttacker | Rate4xx>0.80 / Rate404>0.80 / RateBotUA>0.90 / DangerousPatternHit>=3 / PathTraversalHit>=3 | Excluded from baseline calc |
| Cluster Consensus Fast Path | VoteCount>=20 && Score>=90 | Global pool only; bypasses weighted formula -> direct block |

### 7.3 3-stage feature-list merge

```
Final = DefaultBuiltins + CloudFetch + LocalConfig
        - Excludes
        [ - disable_builtin -> skip DefaultBuiltins ]
        [ - disable_cloud   -> skip CloudFetch ]
```

---

## 8. Core Data Structures

### Event (log parser output)

```go
type Event struct {
    IP             string
    Time           time.Time
    RequestMethod  string
    RequestPath    string
    Status         int
    Bytes          int64
    Referer        string
    UA             string
    Source         string    // nginx_access / apache_access / ...
    LocalRiskScore float64    // filled by detector
}
```

### ThreatScore (cloud dispatch)

```go
type ThreatScore struct {
    IP        string  `json:"ip"`
    Score     float64 `json:"score"`       // 0-100
    VoteCount int     `json:"vote_count"`  // populated for global pool
    Source    string  `json:"source"`      // global / private
}
```

### DiffResult (dual-layer incremental)

```go
type DiffResult struct {
    Global struct {
        NeedBase      bool
        BaseName      string
        ThreatScoring []ThreatScore
        IncrList      []GlobalIncr
    }
    Tenant struct {
        FullSync      bool
        TenantSeq     int64
        ThreatScoring []ThreatScore
        WhiteAdd      []string
        WhiteDel      []string
    }
}
```