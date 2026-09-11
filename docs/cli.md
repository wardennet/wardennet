# CLI Reference

> Companion docs: [Quick Start](./quick-start.md) · [Architecture](./architecture.md) · [Configuration](./configuration.md)

The Agent exposes a **Unix Socket** (`/var/run/wardennet.sock`) with a JSON protocol. You can use the built-in `wardennet` subcommands, `socat`, or `wardennet_cli.py`.

---

## Table of Contents

1. [Command List](#1-command-list)
2. [status](#2-status)
3. [blocklist](#3-blocklist)
4. [reload](#4-reload)
5. [Python Client](#5-python-client)
6. [Unix Socket JSON Protocol](#6-unix-socket-json-protocol)

---

## 1. Command List

| Command | Description |
|---------|-------------|
| `wardennet status` | Agent runtime status + stats |
| `wardennet blocklist add <ip> [--force]` | Manual blacklist add |
| `wardennet blocklist del <ip>` | Remove from blacklist |
| `wardennet blocklist status` | Current blacklist stats |
| `wardennet reload` | Hot-reload config file |

---

## 2. status

```bash
wardennet status
```

Output sample:

```json
{
  "ok": true,
  "data": {
    "uptime": "2d 3h 45m",
    "uptime_seconds": 189900,
    "blocked_count": 42,
    "whitelist_count": 3,
    "ttl_entries": 40,
    "detector_enabled": true,
    "score_high": 50,
    "processed_events": 150234,
    "total_events": 152000,
    "high_score_count": 87,
    "top_blocked": { "192.168.1.100": 12, "10.0.0.55": 8 }
  }
}
```

---

## 3. blocklist

### Add

```bash
wardennet blocklist add 192.168.1.100
wardennet blocklist add 192.168.1.100 --force   # bypass whitelist for emergency
```

### Remove

```bash
wardennet blocklist del 192.168.1.100
```

### Status

```bash
wardennet blocklist status
```

```json
{
  "ok": true,
  "data": {
    "local_blocked_count": 42,
    "local_whitelist_count": 3
  }
}
```

`--force` scenario: emergency DDoS block that overrides the whitelist.

---

## 4. reload

```bash
wardennet reload
```

Re-reads `/etc/wardennet/config.yaml`. **No restart needed**.

---

## 5. Python Client

`agent/scripts/wardennet_cli.py` is a pure Python client (no Go binary needed):

```bash
python3 agent/scripts/wardennet_cli.py status
python3 agent/scripts/wardennet_cli.py blocklist add 1.2.3.4
python3 agent/scripts/wardennet_cli.py blocklist del 1.2.3.4
python3 agent/scripts/wardennet_cli.py blocklist status
python3 agent/scripts/wardennet_cli.py reload
```

Connectivity error:

```
Error: Agent socket not found (/var/run/wardennet.sock)
Confirm Agent is running
```

---

## 6. Unix Socket JSON Protocol

Direct debug with `socat`:

```bash
echo '{"command":"status","args":{}}' | socat - UNIX-CONNECT:/var/run/wardennet.sock
```

### Request

```json
{
  "command": "<name>",
  "args": { "key": "value" }
}
```

### Response

```json
{
  "ok": true,
  "error": "",
  "data": { ... },
  "message": ""
}
```

### Registered command names

```go
const (
    CmdBlockListAdd    = "blocklist.add"
    CmdBlockListDel    = "blocklist.del"
    CmdBlockListStatus = "blocklist.status"
    CmdStatus          = "status"
    CmdReload          = "reload"
)
```

Each handler is wrapped in `recover()` — a single command panic never crashes the whole Agent.

### Registry (`cli.Registry`)

Handlers register with `Registry.Register(name, handler)`. Duplicate registrations overwrite. `Registry.Registered()` returns all names (used by `status`).