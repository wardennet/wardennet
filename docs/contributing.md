# Contributing Guide

> Companion docs: [README](../README.md) · [Architecture](./architecture.md)

Thank you for looking at WardenNet Agent! This guide applies to the open-source portion of the repository.

---

## Table of Contents

1. [Open-Source Scope](#1-open-source-scope)
2. [Dev Environment](#2-dev-environment)
3. [Code Standards](#3-code-standards)
4. [Architecture Red Lines](#4-architecture-red-lines)
5. [Pull Request Flow](#5-pull-request-flow)
6. [Testing Requirements](#6-testing-requirements)

---

## 1. Open-Source Scope

| Directory | License | Notes |
|-----------|---------|-------|
| `agent/` (excluding closed cloudplugin) | AGPLv3 | Go client core — content of this repo |
| `agent/internal/cloudplugin/` | Closed | Cloud SaaS connector — **not included** |
| `cloud/` + Web frontend | Closed | Commercial SaaS platform |

**This guide applies only to open-source content**. Cloud SaaS and closed plugins must not be copied or redistributed without authorization.

---

## 2. Dev Environment

### Go

```bash
cd agent
go build ./...
go vet ./...
go test ./...
```

| Item | Requirement |
|------|-------------|
| Go SDK | >= 1.27 |
| Target | Windows/macOS -> in-memory mock; Linux -> real ipset/iptables |
| Formatting | `gofmt` (Go standard, no extra tooling needed) |

### Run in plugin-less mode

```bash
cd agent/cmd/wardennet
go run .
```

No `libcloudplugin.so` = auto NoopPlugin fallback. Windows/macOS auto-mock.

---

## 3. Code Standards

### Hard rules

- **No file over 500 lines** — split into sub-modules
- **Business logic in independent modules** — `main.go` only wires components
- **Never `_ = someFunc()` to silence errors** — every `error` must be handled
- **Tests first** — every feature change must include unit tests; no bare-code PRs
- **Concurrent code must pass `go test -race`**

### Go idioms

Follow [Effective Go](https://go.dev/doc/effective_go) + `gofmt`.

Conventions:

```go
// Package comment: one line of purpose
package detector // Package detector implements sliding-window attack scoring.

// Errors must be named Err*
var ErrInvalidConfig = errors.New("invalid configuration")

// Internal packages use interfaces for decoupling -> easy mocking
type WhitelistChecker interface {
    Contains(ip string) bool
}
```

### Config & constants

- Runtime thresholds use YAML + Go defaults — no magic numbers
- Compile-time constants use `const` (e.g. `ObserveWindowSec = 30`)
- Closed plugin gated with the `plugin` build tag

---

## 4. Architecture Red Lines

The following rules are **non-negotiable**. PRs violating them will be rejected.

### Red line 1: never bypass the Plugin interface

```go
// NO
import "github.com/wardenet/agent/internal/cloudplugin"

// YES
import "github.com/wardenet/agent/internal/plugin"
// and call plugin.Plugin.Auth() / plugin.Plugin.Diff() / ...
```

### Red line 2: never issue HTTP from open source

```go
// NO
resp, err := http.Post("https://api.wardenet.io/...", ...)

// YES — all cloud capability goes through plugin.Plugin
```

### Red line 3: never hold cloud credentials in open source

`cloudsync` can only hold a `plugin.Plugin` reference — no cloudclient imports, no plain `agent_secret`.

### Red line 4: zero cross-package internal deps

| Open-source package | Can depend on | Cannot depend on |
|---------------------|---------------|------------------|
| `detector` | `logger`, `config` | `ipsetutil`, `cloudsync`, `plugin` |
| `cloudsync` | `plugin`, `ipsetutil`, `config` | `cloudplugin` (closed), `net/http` stdlib |
| `ipsetutil` | `logger` | `detector`, `cloudsync` |

**Rule of thumb**: lower layers must never know upper layers exist. `detector` does not know `ipsetutil`. `ipsetutil` does not know `detector`. `main.go` wires them together.

### Red line 5: no tech-stack changes

- Agent stays Go; Cloud SaaS stays Python FastAPI
- Go version fixed at >= 1.27

---

## 5. Pull Request Flow

1. Fork and branch
   ```bash
   git checkout -b feature/add-xxx
   # or
   git checkout -b fix/issue-xxx
   ```

2. Develop + test
   ```bash
   cd agent
   go build ./...
   go vet ./...
   go test -race ./...
   ```

3. Commit
   ```bash
   git add .
   git commit -m "feat(detector): add xxx scoring dimension"
   ```

4. Push and open PR

### Commit message format

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>

feat(detector): add MAD-based outlier removal
fix(ipsetutil): handle empty whitelist CIDR parsing
docs(architecture): update data flow diagram
refactor(cli): extract handler from main.go
test(detector): add baseline cold start regression test
```

types: `feat` / `fix` / `docs` / `refactor` / `test` / `chore` / `build` / `ci`

---

## 6. Testing Requirements

### Unit tests

- Every `internal/*` package should have a `_test.go`
- Table-driven tests preferred
- Mock dependencies (interface-based decoupling)
- `go test -race` must pass

### Existing test references

| Package | Test file | Coverage focus |
|---------|-----------|----------------|
| `detector` | `detector_test.go` / `consistency_test.go` / `window.go` (embedded) | Windows, scoring, multi-event confirm |
| `ipsetutil` | `manager_test.go` / `priority_test.go` | Whitelist priority, ApplyCloud ordering |
| `cloudsync` | `decision_test.go` | Composite decision engine |
| `config` | `loader_test.go` | Config merge, default fallback |
| `logparser` | `parsers_test.go` / `tail_test.go` | Multi-format parse, tail resume |
| `pidlock` | `pidlock_linux_test.go` | Flock single-instance mutual exclusion |

### Not mandatory

- Pure data-structure adapters (`cmd/wardennet/adapter.go`) — no dedicated standalone test required
- YAML config example files — no test

---

## License

By contributing code you agree to license it under AGPLv3. The closed-source CloudPlugin and Cloud SaaS are not covered by this license.