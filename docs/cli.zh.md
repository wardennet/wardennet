# CLI 命令手册

> 配套文档：[快速开始](./quick-start.zh.md) · [架构总览](./architecture.zh.md) · [配置参考](./configuration.zh.md)

Agent 通过 **Unix Socket**（`/var/run/wardennet.sock`）以 JSON 协议接收命令。CLI 客户端可以是 Agent 自带的 `wardennet` 子命令，也可以直接用 `socat` 或 Python `wardennet_cli.py`。

---

## 目录

1. [命令列表](#1-命令列表)
2. [status — 状态查询](#2-status--状态查询)
3. [blocklist — 黑名单管理](#3-blocklist--黑名单管理)
4. [reload — 热重载配置](#4-reload--热重载配置)
5. [Python 客户端](#5-python-客户端)
6. [Unix Socket JSON 协议](#6-unix-socket-json-协议)

---

## 1. 命令列表

| 命令 | 说明 |
|------|------|
| `wardennet status` | Agent 运行状态、统计信息 |
| `wardennet blocklist add <ip> [--force]` | 手动添加黑名单 |
| `wardennet blocklist del <ip>` | 从黑名单移除 |
| `wardennet blocklist status` | 查看黑名单当前状态 |
| `wardennet reload` | 热重载配置文件 |

---

## 2. status — 状态查询

```bash
wardennet status
```

输出示例：

```json
{
  "command": "status",
  "args": {}
}
```

Response（简化）：

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

## 3. blocklist — 黑名单管理

### 添加

```bash
wardennet blocklist add 192.168.1.100
wardennet blocklist add 192.168.1.100 --force   # 绕过白名单硬封锁
```

Response：

```json
{
  "ok": true,
  "message": "IP 192.168.1.100 added to blacklist"
}
```

`--force` 场景：紧急封禁 DDoS IP，即使该 IP 在白名单里也强制执行。

### 删除

```bash
wardennet blocklist del 192.168.1.100
```

### 查看状态

```bash
wardennet blocklist status
```

输出 ipset 统计：

```json
{
  "ok": true,
  "data": {
    "local_blocked_count": 42,
    "local_whitelist_count": 3
  }
}
```

---

## 4. reload — 热重载配置

```bash
wardennet reload
```

Agent 重新读 `/etc/wardennet/config.yaml`，**不需要重启**。

---

## 5. Python 客户端

`agent/scripts/wardennet_cli.py` 提供纯 Python 实现，无需编译 Agent：

```bash
# 状态
python3 agent/scripts/wardennet_cli.py status

# 黑名单操作
python3 agent/scripts/wardennet_cli.py blocklist add 1.2.3.4
python3 agent/scripts/wardennet_cli.py blocklist del 1.2.3.4
python3 agent/scripts/wardennet_cli.py blocklist status
python3 agent/scripts/wardennet_cli.py reload
```

连接错误时：

```
错误: Agent Socket 不存在 (/var/run/wardennet.sock)
请确认 Agent 正在运行
```

---

## 6. Unix Socket JSON 协议

直接用 `socat` 调试：

```bash
echo '{"command":"status","args":{}}' | socat - UNIX-CONNECT:/var/run/wardennet.sock
```

请求格式：

```json
{
  "command": "<命令名>",
  "args": { "key": "value" }
}
```

响应格式：

```json
{
  "ok": true,
  "error": "",
  "data": { ... },
  "message": ""
}
```

### 已注册命令名常量

```go
const (
    CmdBlockListAdd    = "blocklist.add"
    CmdBlockListDel    = "blocklist.del"
    CmdBlockListStatus = "blocklist.status"
    CmdStatus          = "status"
    CmdReload          = "reload"
)
```

Handler 内部带 recover，单个命令 panic 不会让 Agent 崩溃。

### 命令注册表（`cli.Registry`）

每个命令通过 `Registry.Register(name, handler)` 注册，同名重复注册会被覆盖。`Registry.Registered()` 返回所有已注册命令名（用于 `status`）。