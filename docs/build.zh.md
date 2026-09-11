# 构建与部署

> 配套文档：[快速开始](./quick-start.zh.md) · [架构总览](./architecture.zh.md) · [CLI 命令手册](./cli.zh.md)

---

## 目录

1. [构建模式](#1-构建模式)
2. [基础命令](#2-基础命令)
3. [多架构交叉编译](#3-多架构交叉编译)
4. [build-all.ps1 脚本](#4-build-allps1-脚本)
5. [systemd 部署](#5-systemd-部署)
6. [离线/无插件模式](#6-离线无插件模式)

---

## 1. 构建模式

| 模式 | CGO | -tags | 产物特征 | 适用场景 |
|------|-----|-------|----------|----------|
| **static**（推荐） | 0 | plugin | CloudPlugin 编译进主程序；单文件 ~4MB | 生产部署 |
| **online** | 0 | （无） | NoopPlugin 降级；无云端能力 | 纯本地防护 |
| **cloud** | 1 | plugin | CloudPlugin 整合；依赖 glibc 版本 | 云端协同开发 |
| **so** | 1 | （无） | 主程序 + 独立 `libcloudplugin.so` | 传统插件加载 |

推荐部署 **static** 模式：零 glibc 依赖、单文件、CloudPlugin 已整合。

---

## 2. 基础命令

### 默认构建（动态加载 .so）

```bash
cd agent
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -o wardennet_linux -trimpath -ldflags="-s -w" ./cmd/wardennet
```

### 静态整合 CloudPlugin（如果源码中存在 cloudplugin 包）

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -tags=plugin -o wardennet_linux_static -trimpath \
    -ldflags="-s -w -X main.Version=v0.2" ./cmd/wardennet
```

### 开发测试

```bash
# Windows / macOS 本地
go run ./cmd/wardennet

# 单元测试
go test ./...

# 静态检查
go vet ./...
```

### 关键编译参数

| 参数 | 作用 |
|------|------|
| `CGO_ENABLED=0` | 静态二进制，无 C 库依赖 |
| `-tags=plugin` | 启用 `cloud_integrated.go`，CloudPlugin 编译进主程序 |
| `-trimpath` | 清除本地绝对路径 |
| `-ldflags="-s -w"` | 去掉符号表 + DWARF，体积减少 ~40% |
| `-X main.Version=v0.2` | 注入版本号，`wardennet status` 会显示 |

---

## 3. 多架构交叉编译

```bash
# amd64 (x86_64) — 主流服务器
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -o wardennet_linux_amd64 ./cmd/wardennet

# arm64 — ARM 服务器（华为鲲鹏、Apple Silicon 容器）
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -o wardennet_linux_arm64 ./cmd/wardennet
```

---

## 4. build-all.ps1 脚本

Windows 开发机用 WSL2 批量构建多种模式（如果有闭源 CloudPlugin 源码）：

```powershell
# 交互式选择
./build-all.ps1

# 指定模式 + 版本
./build-all.ps1 -Mode static -Version v0.2

# 构建全部 4 种
./build-all.ps1 -Mode all -Version v0.2
```

脚本输出到 `dist/` 目录。

---

## 5. systemd 部署

### 手动部署

```bash
# 1. 目录准备
mkdir -p /opt/wardennet /etc/wardennet /var/lib/wardennet /var/log/wardennet

# 2. 放置文件
cp wardennet_linux /opt/wardennet/wardennet
chmod +x /opt/wardennet/wardennet
cp wardennet.production.yaml /etc/wardennet/config.yaml
cp wardennet-agent.service /etc/systemd/system/wardennet-agent.service

# 3. 启动
systemctl daemon-reload
systemctl enable --now wardennet-agent

# 4. 查看状态
systemctl status wardennet-agent
journalctl -u wardennet-agent -f
```

### deploy.sh 一键部署

```bash
bash /tmp/deploy.sh
```

### wardennet-agent.service 关键配置

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

### 升级 / 回滚

```bash
# 升级
cp wardennet_new /opt/wardennet/wardennet
systemctl restart wardennet-agent

# 回滚（使用旧二进制）
cp wardennet_backup /opt/wardennet/wardennet
systemctl restart wardennet-agent
```

回滚不需要额外配置——Agent 用 ipset 持久化黑名单，快照自动恢复。

---

## 6. 离线/无插件模式

没有 CloudPlugin 时 Agent 完全降级：

```bash
# 启动日志会显示：
#   plugin not loaded, running in offline mode
#   cloudsync skipped - no plugin loaded (offline mode)
```

所有本地防护能力（日志解析 → 检测 → ipset 封禁 → TTL）**不受影响**。

适合场景：
- 内网/隔离网络环境
- 初期上线不想接 Cloud SaaS
- 云服务商托管服务器，不想走外部网关

可在 `config.yaml` 显式关闭云端：

```yaml
cloud:
  enabled: false
```