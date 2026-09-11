# 快速开始

> 配套文档：[README](../README.zh.md) · [架构总览](./architecture.zh.md) · [配置参考](./configuration.zh.md) · [构建与部署](./build.zh.md)

---

## 目录

1. [准备条件](#1-准备条件)
2. [编译](#2-编译)
3. [三步部署](#3-三步部署)
4. [验证](#4-验证)
5. [开发模式（无 ipset）](#5-开发模式无-ipset)
6. [下一步](#6-下一步)

---

## 1. 准备条件

目标服务器：

| 组件 | 要求 |
|------|------|
| 操作系统 | Ubuntu 20.04+ / Debian 11+ / CentOS 7+ / RHEL 7+ |
| ipset | >= 6.x (`apt install ipset` 或 `yum install ipset`) |
| iptables | >= 1.8.x |
| 权限 | 以 root 运行 |

编译机（任意）：

| 组件 | 要求 |
|------|------|
| Go SDK | >= 1.27 |
| 架构 | Windows / macOS / Linux 都能编译 Linux 产物（CGO_ENABLED=0） |

---

## 2. 编译

最简单的一行：

```bash
cd agent
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -o wardennet_linux -trimpath -ldflags="-s -w -X main.Version=v0.2" ./cmd/wardennet
```

参数说明：

| 参数 | 作用 |
|------|------|
| `CGO_ENABLED=0` | 静态编译，**零依赖**，产物任何 Linux 通吃 |
| `-trimpath` | 清除编译路径 |
| `-ldflags="-s -w"` | 去掉符号表，体积小 40% |
| `-X main.Version=v0.2` | 注入版本号（可选） |

多架构：

```bash
# ARM 服务器
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o wardennet_linux_arm64 ./cmd/wardennet
```

### build-all.ps1（推荐）

在 Windows 开发机上用 WSL2 编译闭源 CloudPlugin 整合版：

```powershell
./build-all.ps1 -Mode static -Version v0.2
```

- `static` — CGO=0 + CloudPlugin 整合（如果存在），**推荐部署用**
- `online` — CGO=0 + 无插件，纯离线模式
- `cloud` — CGO=1 + CloudPlugin 整合（依赖 glibc 版本）
- `so` — CGO=1 + 独立 `.so` 插件

---

## 3. 三步部署

### ① 上传文件

```bash
scp wardennet_linux \
    agent/configs/wardennet.production.yaml \
    agent/configs/wardennet-agent.service \
    agent/deploy.sh \
    root@your-server:/tmp/
```

### ② 一键部署

```bash
ssh root@your-server 'bash /tmp/deploy.sh'
```

脚本会自动：

```
/opt/wardennet/wardennet         # 二进制
/etc/wardennet/config.yaml       # 配置
/var/lib/wardennet/              # TTL 快照
/var/log/wardennet/              # 日志轮转
/etc/systemd/system/wardennet-agent.service
```

### ③ 验证

```bash
wardennet status
# 期望输出：uptime / blocked_count / whitelist_count / detector_enabled

# 备选
echo '{"command":"status","args":{}}' | socat - UNIX-CONNECT:/var/run/wardennet.sock
```

---

## 4. 验证

5 分钟自检清单：

| # | 检查项 | 命令 | 期望 |
|---|--------|------|------|
| 1 | 服务状态 | `systemctl status wardennet-agent` | `active (running)` |
| 2 | 启动日志 | `journalctl -u wardennet-agent -n 20` | 无 error |
| 3 | UnixSocket | `ls -la /var/run/wardennet.sock` | `srwx------` |
| 4 | CLI 连通 | `wardennet status` | 返回状态 |
| 5 | iptables 规则 | `iptables -S INPUT | grep wardennet` | DROP 规则存在 |
| 6 | 黑名单 | `ipset list wardennet_blacklist` | `hash:ip` 类型 |
| 7 | 白名单 | `ipset list wardennet_whitelist` | `hash:net` 类型 |

---

## 5. 开发模式（无 ipset）

在 Windows 开发机上直接 `go run`：

```bash
cd agent/cmd/wardennet
go run .
```

Windows 平台自动切换为内存 Mock Client，不会操作真实 ipset/iptables。可以用以下最小 YAML：

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

## 6. 下一步

- 配置你的日志源 → [配置参考](./configuration.zh.md)
- 加入白名单保护内部 IP → 配置文件 `ipset.whitelist`
- 调优检测器 → `score_high` / `sensitivity` / 基线预扫描
- 连接云端协同 → 在 Cloud SaaS 获取 `tenant_id` + `agent_secret`，在 YAML 配 `cloud.enabled: true`

---

## 故障排查

| 现象 | 排查 |
|------|------|
| `ipset not found` | `apt install ipset` |
| `Permission denied` | 确认 root 运行 |
| `plugin not loaded` | 无 `.so` 属正常，Agent 退化本地模式 |
| `log tail failed` | 确认 `log_sources.*.path` 是绝对路径且文件存在 |