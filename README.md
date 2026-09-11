# WardenNet Agent

[![Go 1.27+](https://img.shields.io/badge/Go-1.27%2B-blue)](https://go.dev/)
[![License](https://img.shields.io/badge/License-AGPLv3-green)](./LICENSE)
[![Build mode](https://img.shields.io/badge/Build-static-steelblue)](./docs/build.md)

**A local sliding-window malware scan protection engine - analyze access logs in real time on your server, automatically push high-risk IPs into the kernel ipset -> iptables DROP chain for zero-latency interception.**

[中文 README](./README.zh.md) · [Quick Start](./docs/quick-start.md) · [Architecture](./docs/architecture.md) · [Configuration](./docs/configuration.md)

---

## Key Features

- **Sliding windows + baseline self-learning**: Three sliding windows (10s / 30s / 60s) cover both instant bursts and persistent scans; the baseline engine auto-learns the P95 distribution of each dimension and scores deviation 0-100.
- **5-dimensional Consistency scoring**: Prefix coherence, path concentration, status homogeneity, method semantics, scanner behavior - multi-dimensional joint judgment with per-dimension caps, confidence discounting, and hard floors.
- **Multi-event confirmation + freshness check**: A high-risk event must fire >= 2 times before a block is triggered, and attack inputs must be genuinely evolving (prevents false blocks from single token-expiries + 404s).
- **8-layer false-positive defense**: Empty-Referer hard cap, 401 down-weighting, known HTTP-client UA whitelist, status-code correlation, exact segment matching, attack-pattern decoding, real-user reward, local IP whitelist.
- **Pre-scan on startup eliminates cold starts**: Automatically scans the last 10 minutes of log tail to seed P95 baselines.
- **Kernel-level interception**: ipset wardennet_blacklist (hash:ip) + iptables -I INPUT -m set --match-set DROP - zero latency, zero CPU.
- **Multiple log sources**: Nginx / Apache / Tomcat / Linux Auth (SSH) + custom regex log sources.
- **Optional cloud integration**: Compile-time integration or .so dynamic loading of libcloudplugin for dual-layer Diff sync, threat-scoring composite decisions, and global threat intelligence.
- **Observer mode**: mode: report scores and reports only, no local blocking - safe rollout for initial deployment.
- **Single static binary**: CGO_ENABLED=0 cross-compile, ~4MB, runs on any Linux.

---

## Project Status

**This repository is the open-source WardenNet Agent (partial open-source).**

| Component | License | Notes |
|-----------|---------|-------|
| gent/ (Go core + log parser + detector + ipset manager) | AGPLv3 | This repository |
| gent/internal/cloudplugin/ | Closed | Cloud SaaS connector - **not included** |
| cloud/ (Cloud SaaS + Web frontend) | Closed | Commercial SaaS platform - not open-sourced |

The Agent runs fully in local mode with all protection capabilities intact when no CloudPlugin is present.

---

## Quick Start

### Build (zero dependencies)

`ash
cd agent
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -o wardennet_linux -trimpath -ldflags="-s -w" ./cmd/wardennet
`

### 3-step deploy

`ash
# 1. Upload
scp wardennet_linux agent/configs/wardennet.production.yaml \
    agent/configs/wardennet-agent.service agent/deploy.sh \
    root@your-server:/tmp/

# 2. One-shot deploy
ssh root@your-server 'bash /tmp/deploy.sh'

# 3. Verify
wardennet status
`

### Minimal config

`yaml
log_sources:
  nginx_access:
    path: /var/log/nginx/access.log
    parser: nginx_access

detector:
  enabled: true
  score_high: 50
  sensitivity: medium   # high / medium / low
  mode: block           # block / report
`

For all configuration fields see [docs/configuration.md](./docs/configuration.md)

---

## Architecture Overview

`
logparser -> detector -> ipsetutil -> ttl
     |           |            |
     v           v            v
tail logs    baseline scoring   snapshot persistence
                   |
                   v
            plugin.Plugin interface
                   |
       libcloudplugin.so (optional)
`

Hard rule: **this codebase never imports cloudplugin or issues HTTP directly**. All cloud capabilities go through the plugin.Plugin interface and silently degrade to NoopPlugin when absent.

For module-by-module explanations see [docs/architecture.md](./docs/architecture.md)

---

## Documentation Index

| Doc | Use case |
|-----|----------|
| [Quick Start](./docs/quick-start.md) | Get an instance running |
| [Architecture](./docs/architecture.md) | How modules collaborate |
| [Configuration](./docs/configuration.md) | Full YAML field reference |
| [Build & Deploy](./docs/build.md) | Build flags, multi-arch, systemd |
| [CLI Reference](./docs/cli.md) | Unix Socket CLI commands |
| [Contributing](./docs/contributing.md) | Dev standards, red lines, PR flow |

---

## System Requirements

| Component | Requirement |
|-----------|-------------|
| OS | Ubuntu 20.04+ / Debian 11+ / CentOS 7+ / RHEL 7+ |
| Go | Dev build >= 1.27; **runtime needs NO Go** (static binary) |
| ipset | >= 6.x (apt install ipset) |
| iptables | >= 1.8.x |
| Privileges | Agent must run as root (ipset/iptables operations) |
| Memory | >= 256MB |
| Disk | >= 1GB (log rotation) |

Dev environment (Windows / macOS): local in-memory mock, no real ipset, run with go run ./cmd/wardennet.

---

## Community & Feedback

- Issues & suggestions -> GitHub Issues
- Code contributions -> [docs/contributing.md](./docs/contributing.md)
- Commercial inquiries -> WardenNet Cloud SaaS (closed product)

---

## License

WardenNet Agent is open-sourced under the **AGPLv3** license. See [LICENSE](./LICENSE). The closed-source CloudPlugin and Cloud SaaS are not covered by this license.