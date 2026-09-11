# Build & Deploy

> Companion docs: [Quick Start](./quick-start.md) · [Architecture](./architecture.md) · [CLI Reference](./cli.md)

---

## Table of Contents

1. [Build Modes](#1-build-modes)
2. [Basic Commands](#2-basic-commands)
3. [Multi-arch Cross Compile](#3-multi-arch-cross-compile)
4. [build-all.ps1](#4-build-allps1)
5. [systemd Deploy](#5-systemd-deploy)
6. [Offline / No-plugin Mode](#6-offline--no-plugin-mode)

---

## 1. Build Modes

| Mode | CGO | -tags | Artifact | Use case |
|------|-----|-------|----------|----------|
| **static** (recommended) | 0 | plugin | CloudPlugin compiled in; single ~4MB binary | Production deploy |
| **online** | 0 | (none) | NoopPlugin; no cloud | Pure local protection |
| **cloud** | 1 | plugin | CloudPlugin integrated; glibc-version dependent | Cloud dev/test |
| **so** | 1 | (none) | Main binary + separate `libcloudplugin.so` | Traditional plugin load |

Deploy **static** mode: zero glibc dependency, single file, CloudPlugin already baked in.

---

## 2. Basic Commands

### Default build (dynamic .so loader)

```bash
cd agent
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -o wardennet_linux -trimpath -ldflags="-s -w" ./cmd/wardennet
```

### Static build with CloudPlugin (when cloudplugin package exists in source)

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -tags=plugin -o wardennet_linux_static -trimpath \
    -ldflags="-s -w -X main.Version=v0.2" ./cmd/wardennet
```

### Dev test

```bash
# Windows / macOS local
go run ./cmd/wardennet

# Unit tests
go test ./...

# Static check
go vet ./...
```

### Key flags

| Flag | Purpose |
|------|---------|
| `CGO_ENABLED=0` | Fully static, no C deps |
| `-tags=plugin` | Enables `cloud_integrated.go`; bakes CloudPlugin into binary |
| `-trimpath` | Strips local build paths |
| `-ldflags="-s -w"` | Removes symbol table + DWARF -> ~40% smaller |
| `-X main.Version=v0.2` | Injects version (`wardennet status` shows it) |

---

## 3. Multi-arch Cross Compile

```bash
# amd64 (x86_64)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -o wardennet_linux_amd64 ./cmd/wardennet

# arm64 (ARM servers)
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -o wardennet_linux_arm64 ./cmd/wardennet
```

---

## 4. build-all.ps1

On Windows dev box, WSL2 cross-build all 4 modes (when closed-source CloudPlugin is present):

```powershell
./build-all.ps1                        # interactive
./build-all.ps1 -Mode static -Version v0.2
./build-all.ps1 -Mode all    -Version v0.2
```

Output goes to `dist/`.

---

## 5. systemd Deploy

### Manual

```bash
# 1. Layout
mkdir -p /opt/wardennet /etc/wardennet /var/lib/wardennet /var/log/wardennet

# 2. Stage files
cp wardennet_linux /opt/wardennet/wardennet
chmod +x /opt/wardennet/wardennet
cp wardennet.production.yaml /etc/wardennet/config.yaml
cp wardennet-agent.service /etc/systemd/system/wardennet-agent.service

# 3. Start
systemctl daemon-reload
systemctl enable --now wardennet-agent

# 4. Check
systemctl status wardennet-agent
journalctl -u wardennet-agent -f
```

### deploy.sh one-shot

```bash
bash /tmp/deploy.sh
```

### wardennet-agent.service key settings

```ini
[Unit]
Description=WardenNet Agent
After=network.target

[Service]
Type=simple
User=root
ExecStart=/opt/wardennet/wardennet --config /etc/wardennet/config.yaml
Restart=always
RestartSec=5

# Hardening
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=read-only

[Install]
WantedBy=multi-user.target
```

### Upgrade / Rollback

```bash
# Upgrade
cp wardennet_new /opt/wardennet/wardennet
systemctl restart wardennet-agent

# Rollback (with old binary)
cp wardennet_backup /opt/wardennet/wardennet
systemctl restart wardennet-agent
```

Rollback needs no config change — ipset blacklists are persisted and auto-restored.

---

## 6. Offline / No-plugin Mode

Without CloudPlugin the Agent degrades fully:

```bash
# Startup logs show:
#   plugin not loaded, running in offline mode
#   cloudsync skipped - no plugin loaded (offline mode)
```

All local protection (log parse -> detect -> ipset -> TTL) keeps working.

Use cases:
- Air-gapped / isolated networks
- Initial rollout without Cloud SaaS
- Cloud-hosted servers avoiding external gateways

Explicitly disable cloud:

```yaml
cloud:
  enabled: false
```