# Quick Start

> Companion docs: [README](../README.md) · [Architecture](./architecture.md) · [Configuration](./configuration.md) · [Build & Deploy](./build.md)

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Build](#2-build)
3. [3-step Deploy](#3-3-step-deploy)
4. [Verify](#4-verify)
5. [Dev Mode (no ipset)](#5-dev-mode-no-ipset)
6. [Next Steps](#6-next-steps)

---

## 1. Prerequisites

**Target server**:

| Component | Required |
|-----------|----------|
| OS | Ubuntu 20.04+ / Debian 11+ / CentOS 7+ / RHEL 7+ |
| ipset | >= 6.x (`apt install ipset`) |
| iptables | >= 1.8.x |
| Privileges | Must run as root |

**Build machine (any)**:

| Component | Required |
|-----------|----------|
| Go SDK | >= 1.27 |
| Platform | Windows / macOS / Linux all produce Linux binaries (CGO_ENABLED=0) |

---

## 2. Build

One-liner:

```bash
cd agent
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -o wardennet_linux -trimpath -ldflags="-s -w -X main.Version=v0.2" ./cmd/wardennet
```

Flags:

| Flag | Purpose |
|------|---------|
| `CGO_ENABLED=0` | Fully static, **zero deps**, runs anywhere |
| `-trimpath` | Remove local build paths |
| `-ldflags="-s -w"` | Strip symbols + DWARF -> binary ~40% smaller |
| `-X main.Version=v0.2` | Injects version (`wardennet status` shows it) |

Multi-arch:

```bash
# ARM servers
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o wardennet_linux_arm64 ./cmd/wardennet
```

### build-all.ps1 (recommended)

On Windows dev box via WSL2 (if closed-source CloudPlugin is available):

```powershell
./build-all.ps1 -Mode static -Version v0.2
```

- `static` — CGO=0 + CloudPlugin compiled in (if present). **Recommended for production**.
- `online` — CGO=0 + NoopPlugin. Pure local mode.
- `cloud` — CGO=1 + CloudPlugin integrated (glibc-version dependent).
- `so` — CGO=1 + standalone `.so` plugin.

---

## 3. 3-step Deploy

### Upload files

```bash
scp wardennet_linux \
    agent/configs/wardennet.production.yaml \
    agent/configs/wardennet-agent.service \
    agent/deploy.sh \
    root@your-server:/tmp/
```

### One-shot deploy

```bash
ssh root@your-server 'bash /tmp/deploy.sh'
```

Layout:

```
/opt/wardennet/wardennet         # binary
/etc/wardennet/config.yaml       # config
/var/lib/wardennet/              # TTL snapshots
/var/log/wardennet/              # rotated logs
/etc/systemd/system/wardennet-agent.service
```

### Verify

```bash
wardennet status
# expect: uptime / blocked_count / whitelist_count / detector_enabled

# fallback
echo '{"command":"status","args":{}}' | socat - UNIX-CONNECT:/var/run/wardennet.sock
```

---

## 4. Verify

5-minute check list:

| # | Check | Command | Expected |
|---|-------|---------|----------|
| 1 | Service status | `systemctl status wardennet-agent` | `active (running)` |
| 2 | Startup log | `journalctl -u wardennet-agent -n 20` | No errors |
| 3 | UnixSocket | `ls -la /var/run/wardennet.sock` | `srwx------` |
| 4 | CLI reachable | `wardennet status` | Returns status |
| 5 | iptables rules | `iptables -S INPUT | grep wardennet` | DROP rule present |
| 6 | Blacklist | `ipset list wardennet_blacklist` | `hash:ip` |
| 7 | Whitelist | `ipset list wardennet_whitelist` | `hash:net` |

---

## 5. Dev Mode (no ipset)

On Windows / macOS just `go run`:

```bash
cd agent/cmd/wardennet
go run .
```

Non-Linux platforms switch to an in-memory mock automatically. Minimal config:

```yaml
log_sources:
  nginx_access:
    path: ./test-access.log
    parser: nginx_access

detector:
  enabled: true
  score_high: 50
  sensitivity: medium
```

---

## 6. Next Steps

- Configure your log sources -> [Configuration](./configuration.md)
- Add whitelist entries for internal IPs -> `ipset.whitelist` in config
- Tune detector -> `score_high` / `sensitivity` / baseline pre-scan
- Enable cloud coordination -> get `tenant_id` + `agent_secret` from Cloud SaaS, set `cloud.enabled: true`

---

## Troubleshooting

| Symptom | Check |
|---------|-------|
| `ipset not found` | `apt install ipset` |
| `Permission denied` | Confirm running as root |
| `plugin not loaded` | Normal — Agent falls back to local-only when no `.so` is present |
| `log tail failed` | Confirm `log_sources.*.path` is an absolute path and the file exists |