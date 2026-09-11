# Configuration Reference

> Companion docs: [README](../README.md) · [Architecture](./architecture.md) · [Quick Start](./quick-start.md)

Default path `/etc/wardennet/config.yaml`. **All fields fall back to built-in defaults when omitted** — no field is mandatory.

> Full example at `agent/configs/wardennet.yaml.example`

---

## Table of Contents

1. [Loading Rules](#1-loading-rules)
2. [agent section](#2-agent-section)
3. [log section](#3-log-section)
4. [stats section](#4-stats-section)
5. [log_sources section](#5-log_sources-section)
6. [detector section](#6-detector-section)
7. [ipset section](#7-ipset-section)
8. [unix_socket section](#8-unix_socket-section)
9. [cloud section (optional)](#9-cloud-section-optional)
10. [ttl section](#10-ttl-section)

---

## 1. Loading Rules

Priority (highest -> lowest):

1. `--config /path/to/config.yaml` CLI flag
2. `WARDENNET_CONFIG=/path/to/config.yaml` env var
3. Default `/etc/wardennet/config.yaml`
4. Built-in Go defaults

Missing fields silently fall back — no error.

---

## 2. agent section

```yaml
agent:
  local_block_ttl: 3600
  cloud_block_ttl: 7200
  cloud_max_ttl:   86400
```

| Field | Default | Notes |
|-------|---------|-------|
| `local_block_ttl` | 3600 | TTL for local detector-triggered blocks |
| `cloud_block_ttl` | 7200 | Upper cap on cloud-dispatched TTL |
| `cloud_max_ttl` | 86400 | Global max TTL for cloud tiers |

---

## 3. log section

```yaml
log:
  level: info
  file: /var/log/wardennet/agent.log   # empty = stdout only
  max_size:    100
  max_backups: 7
  max_age:     30
  compress:    true
```

Use `info` in production. `debug` emits per-request scoring details.

---

## 4. stats section

```yaml
stats:
  report_interval: 60   # seconds; 0 disables
```

Every 60 seconds the Agent logs cumulative stats: `processed_events` / `total_ips` / `high_score_count` / `top_blocked`.

---

## 5. log_sources section

Multiple independent sources:

```yaml
log_sources:
  nginx_access:
    path: /var/log/nginx/access.log
    parser: nginx_access

  apache_access:
    path: /var/log/apache2/access.log
    parser: apache_access

  linux_auth:
    path: /var/log/auth.log
    parser: linux_auth
    # allow_upload: false     # default false; compliance-first

  # Custom regex format
  custom_app:
    path: /var/log/myapp/access.log
    parser: custom
    custom_regex: '^(\S+) - - \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) (\d+) "([^"]*)" "([^"]*)"'
    regex_groups:
      ip: 1
      time: 2
      request_method: 3
      request_path: 4
      status: 5
      bytes: 6
      referer: 7
      uagent: 8
```

Available parsers: `nginx_access` / `apache_access` / `tomcat_access` / `linux_auth` / `custom`

---

## 6. detector section

### Basic switches & thresholds

```yaml
detector:
  enabled: true
  score_high: 50
  score_medium: 30
  score_low: 15

  # ---- Sensitivity (3 built-in tiers, no fine-tuning needed) ----
  # high:   triggers at 2x deviation
  # medium: triggers at 5x    (default recommended)
  # low:    triggers at 10x
  sensitivity: medium

  # ---- Mode ----
  # block:  normal blocking
  # report: score-only, no local block (safe rollout)
  mode: block
```

### Feature lists (3-stage merge architecture)

Three feature-list fields support **both formats**:

```yaml
# Format 1: simple list (backward compatible)
known_http_clients: ["okhttp", "python-requests", "curl"]
sensitive_paths: ["/.env", "/admin/config"]
dangerous_patterns: ["\\.\\./", "union.*select"]

# Format 2: structured (recommended)
known_http_clients:
  local: ["my-custom-client"]
  excludes: ["internal-api"]
  disable_builtin: false
  disable_cloud: false
```

Merge order:

```
Final = DefaultBuiltins + CloudFetch + LocalConfig
       - Excludes
       [ - disable_builtin -> skip DefaultBuiltins ]
       [ - disable_cloud   -> skip CloudFetch ]
```

### Consistency params (optional)

```yaml
detector:
  consistency:
    prefix_coherence_threshold: 0.5
    path_concentration_threshold: 0.4
    status_homogeneity_threshold: 0.6
    method_semantics_weight: 0.3
    scanner_behavior_weight: 0.5
```

Unset -> code defaults (balanced).

---

## 7. ipset section

```yaml
ipset:
  whitelist:
    - "127.0.0.1"
    - "::1"
    - "10.0.0.0/8"
    - "192.168.0.0/16"
  blacklist: []     # pre-loaded local blacklist (offline mode fallback)
```

**Whitelist hard rule**: a whitelist hit skips all detection and blocking. Supports single IPs or CIDRs.

---

## 8. unix_socket section

```yaml
unix_socket:
  path: /var/run/wardennet.sock
```

Default `/var/run/wardennet.sock`, mode 0600.

---

## 9. cloud section (optional)

```yaml
cloud:
  enabled: false
  base_url: https://api.wardenet.io
  tenant_id: your-tenant-id
  agent_secret: your-agent-secret
```

| Field | Notes |
|-------|-------|
| `enabled` | Only takes effect when `libcloudplugin.so` is also present |
| `base_url` | Cloud SaaS endpoint |
| `tenant_id` | Issued after SaaS registration |
| `agent_secret` | Issued after SaaS registration (used for HMAC signing) |

Without a plugin, even `cloud.enabled: true` issues no HTTP — the Agent logs a warning and skips.

---

## 10. ttl section

```yaml
ttl:
  default_ttl: 3600
  cleanup_interval: 60
```