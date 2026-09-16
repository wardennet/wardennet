# WardenNet

[![Go 1.27+](https://img.shields.io/badge/Go-1.27%2B-blue)](https://go.dev/)
[![License AGPLv3](https://img.shields.io/badge/License-AGPLv3-green)](./LICENSE)
[![Build mode](https://img.shields.io/badge/Build-static-steelblue)](./docs/build.md)
[![GitHub stars](https://img.shields.io/github/stars/wardennet/wardennet?style=social)](https://github.com/wardennet/wardennet)

A lightweight coordinated defense Agent for Web servers. Real-time log analysis with sliding-window baseline self-learning, pushing high-risk IPs into kernel ipset -> iptables DROP for zero-latency interception.

> When every server becomes a sentinel, together they are an army.

[中文 README](./README.zh.md) . [Quick Start](./docs/quick-start.md) . [Architecture](./docs/architecture.md) . [Configuration](./docs/configuration.md)

---

## What Problem Does It Solve?

If you run any public-facing Web server, open your Nginx access log for one minute. You'll see 30+ IPs from 20+ countries scanning /.env, /wp-login.php, /admin/config.php, .git/config -- automated enumeration bots that probe silently until one day they find a zero-day.

Traditional defenses all fail here:

| Approach | Why It Fails |
|----------|-------------|
| fail2ban (regex rules) | Blocks legitimate crawlers, misses distributed slow scans |
| Nginx rate_limit (QPS cap) | Botnets simply throttle to 2-5 QPS and bypass |
| Commercial WAF | Expensive, static rules, doesn't learn your traffic |
| Manual ipset add | 20 minutes/week of repetitive ops |

**WardenNet solves this with three ideas**: sliding windows + baseline self-learning (no hard-coded thresholds), 5-dimensional consistency scoring (distinguishes bots from real users), and optional cloud coordination (one server discovers a threat, all servers block it).

---

## Quick Try -- 3 Minutes

No compilation needed. Download the pre-built zip, unzip, run the deploy script. That's it.

```bash
# 1. Download the release bundle (single zip, zero external deps)
wget https://github.com/user-attachments/files/32177070/wardennet.zip
unzip wardennet.zip

# 2. One-shot deploy -- auto-detects Nginx, generates config, registers systemd
sudo bash deploy.sh

# 3. Verify
wardennet status
```

The zip contains four files, nothing else:

| File | Purpose |
|------|---------|
| wardennet_linux | Go static binary, ~5.8MB |
| deploy.sh | Auto-deployment script (environment detection + config generation) |
| wardennet.production.yaml | Production config template |
| AGENT_OPS.md | Operation manual |

After deploy.sh completes, you get:
- systemd service wardennet-agent running as root
- ipset wardennet_blacklist (hash:ip) + wardennet_whitelist (hash:net)
- iptables DROP rule wired to the blacklist
- CLI command wardennet globally available

### Verify everything is green

```bash
# Service alive
systemctl status wardennet-agent

# Agent self-check
wardennet status

# ipset sets created
ipset list wardennet_blacklist
ipset list wardennet_whitelist

# iptables DROP rule active
iptables -S INPUT | grep wardennet
```

### First-time safe rollout

New install? Use **Observer Mode** -- scores and logs everything, blocks nothing. Confirm the detector behaves sensibly for 24h, then flip to block:

```bash
# Switch to observer mode
sed -i 's/mode: block/mode: report/' /etc/wardennet/config.yaml

# 24h later, flip to block
sed -i 's/mode: report/mode: block/' /etc/wardennet/config.yaml
```

Agent hot-reloads config every 5 seconds -- no restart needed.

---

## Quick Start -- Build from Source

Prefer compiling yourself? One-liner on any OS (CGO_ENABLED=0 produces fully static binary):

```bash
cd agent
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \\
  go build -o wardennet_linux -trimpath -ldflags="-s -w" ./cmd/wardennet
```

See [docs/quick-start.md](./docs/quick-start.md) for full build + deploy walkthrough, multi-arch (arm64), and dev mode.

---

## Architecture Overview

```
logparser -> detector -> ipsetutil -> ttl
     |           |            |
     v           v            v
tail logs    baseline scoring   snapshot persistence
                   |
                   v
            plugin.Plugin interface
                   |
       libcloudplugin.so (optional)
```

Hard rule: **this codebase never imports cloudplugin or issues HTTP directly**. All cloud capabilities go through the plugin.Plugin interface and silently degrade to NoopPlugin when absent. Cloud SaaS downtime? Agent keeps working locally.

Module-by-module explanation: [docs/architecture.md](./docs/architecture.md)

---

## Key Features

| Feature | What It Does |
|---------|-------------|
| Sliding windows + baseline self-learning | Three independent windows (10s / 30s / 60s). Scores deviation from auto-learned P95 baselines, no hard-coded thresholds |
| 5-dimensional consistency scoring | Prefix coherence, path concentration, status homogeneity, method semantics, scanner behavior -- multi-dimension joint judgment with per-dimension caps and confidence discounting |
| Multi-event confirmation + freshness | High-risk event must fire >= 2 times before blocking; attack inputs must be genuinely evolving. Prevents false blocks from single token expiries + 404s |
| 8-layer false-positive defense | Empty-Referer hard cap, 401 down-weighting, known HTTP-client UA whitelist, status-code correlation, exact segment matching, attack-pattern decoding, real-user reward, local IP whitelist |
| Startup pre-scan eliminates cold start | Auto-scans last 10 minutes of log tail to seed P95 baselines before real traffic arrives |
| Kernel-level interception | ipset wardennet_blacklist (hash:ip) + iptables -I INPUT -m set --match-set DROP -- zero latency, zero CPU overhead |
| Multiple log sources | Nginx / Apache / Tomcat / Linux Auth (SSH) + custom regex log sources |
| Optional cloud coordination | Compile-time integration or .so dynamic loading of CloudPlugin for dual-layer Diff sync, threat-scoring composite decisions, and global threat intelligence |
| Observer mode | mode: report scores and logs only, no local blocking -- safe rollout for initial deployment |
| Single static binary | CGO_ENABLED=0 cross-compile, ~5.8MB, runs on any Linux |

---

## How Well Does It Work?

Real-world data from a 2C4G Ubuntu 22.04 server running Hugo + Nginx:

| Metric | Before (7 days) | After (7 days) | Change |
|--------|:--------------:|:--------------:|:------:|
| Unique scanner IPs | 1,247 | 89 | **-92.9%** |
| 4xx request ratio | 37.2% | 4.8% | **-87.1%** |
| Total scan requests | 53,210 | 1,230 | **-97.7%** |
| False positives | -- | 0 | -- |
| Nginx avg response time | 128ms | 94ms | -26.6% |
| WardenNet memory | -- | 16.4 MB | -- |
| WardenNet CPU | -- | 0.3% | -- |

---

## Project Status

This repository is **the open-source WardenNet Agent (partial open-source)**. The Agent runs fully in local mode with all protection capabilities intact -- Cloud coordination is purely optional.

| Component | License | Notes |
|-----------|---------|-------|
| agent/ (Go core + log parser + detector + ipset manager) | AGPLv3 | **This repository** |
| agent/internal/cloudplugin/ | Closed | Cloud SaaS connector -- **not included** |
| Cloud SaaS + Web frontend | Closed | Commercial platform -- not open-sourced |

---

## Documentation

| Doc | When You Need It |
|-----|------------------|
| [Quick Start](./docs/quick-start.md) | Get an instance running |
| [Architecture](./docs/architecture.md) | How modules collaborate |
| [Configuration](./docs/configuration.md) | Full YAML field reference |
| [Build & Deploy](./docs/build.md) | Build flags, multi-arch, systemd |
| [CLI Reference](./docs/cli.md) | Unix Socket CLI commands |
| [Contributing](./docs/contributing.md) | Dev standards, red lines, PR flow |

---

## System Requirements

| Component | Minimum |
|-----------|---------|
| OS | Ubuntu 20.04+ / Debian 11+ / CentOS 7+ / RHEL 7+ |
| Runtime | **No Go needed** (static binary). Dev build needs Go >= 1.27 |
| ipset | >= 6.x (apt install ipset) |
| iptables | >= 1.8.x |
| Privileges | Must run as root (ipset/iptables operations) |
| Memory | >= 256 MB |
| Disk | >= 1 GB (log rotation) |

Dev environment (Windows / macOS): local in-memory mock, no real ipset, run with go run ./cmd/wardennet.

---

## Community & Feedback

- Issues & bug reports -> GitHub Issues
- Code contributions -> [docs/contributing.md](./docs/contributing.md)
- Pull requests welcome -- please read the Contributing Guide first

---

## License

WardenNet Agent is open-sourced under the **AGPLv3** license. See [LICENSE](./LICENSE). Closed-source CloudPlugin and Cloud SaaS are not covered by this license.
