# WardenNet Agent 编译、部署与运维手册

> 版本：v0.4
> 适用：Linux（生产）/ Windows（开发测试）/ WSL2（Plugin 编译）
> 项目路径：`agent/`
> 变更：新增 CloudPlugin 闭源插件打包（Linux 原生 / Windows+WSL2 双方式），Agent 二进制从 cloudclient 剥离后体积降至 4MB 级别，Agent/Plugin 彻底物理解耦

---

## 目录

1. [系统要求](#1-系统要求)
2. [编译构建](#2-编译构建)
   - [2.1 Agent — 开发机本地编译](#21-agent--开发机本地编译)
   - [2.2 Agent — 交叉编译 Linux 产物（推荐）](#22-agent--交叉编译-linux-产物推荐)
   - [2.3 Agent — 产物说明](#23-agent--产物说明)
   - [2.4 Agent — 多架构批量编译](#24-agent--多架构批量编译)
   - [2.5 CloudPlugin — Linux 原生编译](#25-cloudplugin--linux-原生编译)
   - [2.6 CloudPlugin — Windows 开发机通过 WSL2 编译](#26-cloudplugin--windows-开发机通过-wsl2-编译)
   - [2.7 CloudPlugin — 产物说明与部署](#27-cloudplugin--产物说明与部署)
3. [快速部署](#3-快速部署)
4. [配置详解](#4-配置详解)
5. [运维操作](#5-运维操作)
6. [CLI 命令手册](#6cli-命令手册)
7. [日志与监控](#7日志与监控)
8. [故障排查](#8故障排查)
9. [架构说明](#9架构说明)

---

## 1. 系统要求

### 生产环境（Linux）

| 组件 | 要求 |
|---|---|
| 操作系统 | Ubuntu 20.04+ / Debian 11+ / CentOS 7+ / RHEL 7+ |
| Go 运行时 | 由编译目标决定，静态编译产物**无需**目标机安装 Go |
| ipset | `>= 6.x`（`apt install ipset` 或 `yum install ipset`） |
| iptables | `>= 1.8.x`（与 ipset 配合实现内核级 DROP） |
| 权限 | Agent 需以 **root** 身份运行（操作 ipset/iptables 需要） |
| 磁盘 | ≥ 1GB（日志轮转 + 快照） |
| 内存 | ≥ 256MB（滑动窗口缓存） |

### 开发环境（Windows）

| 组件 | 要求 |
|---|---|
| Go SDK | `>= 1.21` |
| 编辑器 | VS Code / Goland |
| 注意 | Windows 下使用**内存 Mock 客户端**，不操作真实 ipset/iptables |

---

## 2. 编译构建

### 2.1 Agent — 开发机本地编译

```bash
cd agent/

# 本地开发编译（当前平台，Go 默认 CGO_ENABLED=1）
# Windows 上会使用内存 Mock Client（无真实 ipset/iptables 操作）
go build -o wardennet -ldflags="-s -w -X main.Version=v0.2" ./cmd/wardennet

# 单元测试
go test ./...

# 静态检查
go vet ./...
```

### 2.2 Agent — 交叉编译 Linux 产物（推荐）

Agent 不依赖 CGO（Linux 上调用 ipset/iptables 使用 `os/exec` 纯 Go 实现），完全可以零依赖交叉编译：

```bash
# 在 Windows / Mac / Linux 上都能产出 Linux 二进制
set CGO_ENABLED=0 
set GOOS=linux 
set GOARCH=amd64 
go build -o wardennet_linux -trimpath -ldflags="-s -w -X main.Version=v0.2" ./cmd/wardennet
```

| 编译参数 | 作用 |
|---------|------|
| `CGO_ENABLED=0` | 静态编译，产物无外部 C 库依赖 |
| `GOOS=linux` | 目标操作系统 |
| `GOARCH=amd64` | 目标架构（ARM 服务器改为 `arm64`） |
| `-trimpath` | 清除本地绝对路径，防止构建环境泄漏 |
| `-ldflags="-s -w"` | 去掉符号表和 DWARF 调试信息，体积 ↓40% |
| `-ldflags="-X ...Version=..."` | 注入版本号，`wardennet status` 会显示 |

### 2.3 Agent — 产物说明

```bash
ls -lh wardennet_linux
# -rwxr-xr-x 1 user user 4.1M xxx xx 12:00 wardennet_linux
```

**产物大小约 4MB**（stripped + trimpath）。

> v0.4 起 Agent 不再内置 HTTP 客户端（net/http、crypto/hmac、encoding/json 等约 2MB 的依赖被剥离），云端对接能力移至闭源 CloudPlugin.so，Agent 体积显著下降。

**无 CloudPlugin 时 Agent 行为**：启动日志会显示 `plugin not loaded, running in offline mode` + `cloudsync skipped — no plugin loaded (offline mode)`，Agent 退化为纯本地运行，所有防护能力不受影响。

### 2.4 Agent — 多架构批量编译

```bash
# amd64 (x86_64)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -o wardennet_linux_amd64 ./cmd/wardennet

# arm64 (ARM 服务器)
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build \
    -o wardennet_linux_arm64 ./cmd/wardennet

# 一键批量
for arch in amd64 arm64; do
    CGO_ENABLED=0 GOOS=linux GOARCH=$arch \
        go build -o wardennet_linux_$arch ./cmd/wardennet
done
```

### 2.5 CloudPlugin — Linux 原生编译

CloudPlugin 是 Agent 与云端 SaaS 对接的闭源 `.so` 插件。**只能在 Linux（或 WSL2）上编译**——Go 的 `buildmode=plugin` 是平台相关的，Windows 不支持 DLL 动态加载。

#### 前置依赖

- **CGO** 必须启用（`CGO_ENABLED=1`，Go plugin 平台限制）
- **gcc** 或 clang 可用

```bash
# Ubuntu / Debian
sudo apt update && sudo apt install -y gcc golang-go

# CentOS / RHEL
sudo yum install -y gcc golang
```

#### 编译

```bash
cd agent/

# libcloudplugin/ 被 .gitignore 忽略（闭源保护）
# 编译为 Go plugin 共享对象
CGO_ENABLED=1 go build -buildmode=plugin \
    -o libcloudplugin.so \
    ./libcloudplugin/
```

编译成功后会在 `agent/` 目录下产出 `libcloudplugin.so`（约 16MB）。

#### 验证产物能被 Go runtime 正常加载

```bash
# 编写一个极简验证脚本
cat > /tmp/verify_plugin.go << 'EOF'
package main

import (
    "fmt"
    "plugin"
)

func main() {
    p, err := plugin.Open("libcloudplugin.so")
    if err != nil {
        fmt.Println("❌ plugin.Open failed:", err)
        return
    }
    sym, err := p.Lookup("NewPlugin")
    if err != nil {
        fmt.Println("❌ Lookup NewPlugin failed:", err)
        return
    }
    factory, ok := sym.(func() interface{})
    if !ok {
        fmt.Println("❌ NewPlugin has wrong type:", sym)
        return
    }
    _ = factory()
    fmt.Println("✅ CloudPlugin loaded successfully, NewPlugin type:", sym.Type())
}
EOF

CGO_ENABLED=1 go run /tmp/verify_plugin.go
```

#### 可选：注入版本号

```bash
CGO_ENABLED=1 go build -buildmode=plugin \
    -o libcloudplugin.so \
    -ldflags="-X main.pluginVersion=v0.4.0" \
    ./libcloudplugin/
```

### 2.6 CloudPlugin — Windows 开发机通过 WSL2 编译

Windows 上无法原生编译 Go plugin，但你有 **WSL2 Ubuntu** 可以直接编。

#### Step 1：确认 WSL2 有 Go 和 gcc

```powershell
# PowerShell 里检查
wsl -d Ubuntu -- bash -c "go version && gcc --version | head -1"
# 期望：
#   go version go1.24.x linux/amd64
#   gcc (Ubuntu xx.x.x-ubuntu1~xx.xx.x) xx.x.x

# 如果缺 Go（WSL2 里网络可用时）
wsl -d Ubuntu -u root -- bash -c "
curl -sL https://go.dev/dl/go1.24.3.linux-amd64.tar.gz -o /tmp/go.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tar.gz
ln -sf /usr/local/go/bin/go /usr/local/bin/go
go version
"

# 如果缺 gcc
wsl -d Ubuntu -u root -- apt install -y gcc
```

#### Step 2：一键编译

```powershell
# PowerShell 里一条命令完成：进 WSL2 → 编 .so → 回 Windows
wsl -d Ubuntu -- bash -c "
  cd /mnt/d/coder/business/WardenNet/agent &&
  CGO_ENABLED=1 go build -buildmode=plugin -o libcloudplugin.so ./libcloudplugin/ &&
  ls -lh libcloudplugin.so
"
```

> `/mnt/d/...` 是 Windows D 盘在 WSL2 里的挂载路径（大小写自适应，Go 能正确识别）。

#### Step 3：验证

```powershell
# 验证 .so 文件在 Windows 上可见
ls d:\coder\business\WardenNet\agent\libcloudplugin.so

# 让 Agent 加载它的 WSL2 同路径验证运行时兼容性
# （可选，生产部署直接拿 .so 丢到目标机即可）
wsl -d Ubuntu -- bash -c "
  cd /mnt/d/coder/business/WardenNet/agent &&
  CGO_ENABLED=1 go run -exec '' - <<'GOEOF'
package main
import (
    \"fmt\"
    \"plugin\"
)
func main() {
    p, err := plugin.Open(\"./libcloudplugin.so\")
    if err != nil { fmt.Println(\"open:\", err); return }
    sym, _ := p.Lookup(\"NewPlugin\")
    fmt.Println(\"✅ NewPlugin type:\", sym.Type())
}
GOEOF
"
```

### 2.7 CloudPlugin — 产物说明与部署

#### 产物

```
agent/
├── wardennet_linux          # Agent 主进程（4MB，静态编译）
└── libcloudplugin.so        # 云端对接插件（~16MB）
```

| 产物 | 大小 | 运行环境 | 说明 |
|------|------|---------|------|
| `wardennet_linux` | ~4MB | Linux amd64/arm64 | 开源，静态编译，无外部依赖 |
| `libcloudplugin.so` | ~16MB | Linux amd64/arm64 | 闭源，Go plugin 格式 |

#### 部署到服务器

```bash
# 1. 上传两个产物
scp wardennet_linux libcloudplugin.so \
    root@your-server:/tmp/

# 2. 登录服务器
ssh root@your-server

# 3. 安装 Agent
cp /tmp/wardennet_linux /opt/wardennet/wardennet
chmod +x /opt/wardennet/wardennet

# 4. 安装 CloudPlugin（放到默认路径）
mkdir -p /usr/lib/wardennet
cp /tmp/libcloudplugin.so /usr/lib/wardennet/libcloudplugin.so
chmod 644 /usr/lib/wardennet/libcloudplugin.so

# 5. 可选：通过 cloud.plugin_path 配置自定义路径
vim /etc/wardennet/config.yaml
# 追加：
#   cloud:
#     enabled: true
#     plugin_path: /opt/wardennet/libcloudplugin.so   # 自定义位置

# 6. 重启 Agent
systemctl restart wardennet-agent

# 7. 验证插件加载成功
journalctl -u wardennet-agent -n 20 | grep -E "plugin|cloudsync"
# 期望输出：
#   plugin loaded successfully
#   cloudsync started tenant_id=... node_id=...
```

#### 插件降级行为

| 场景 | Agent 行为 |
|------|----------|
| `.so` 不存在 | 启动日志 `plugin not loaded, running in offline mode`，CloudSync 全部跳过，Agent 正常本地运行 |
| `cloud.enabled=false` | 即使有 `.so` 也跳过，日志 `cloudsync skipped — cloud.enabled=false` |
| `.so` 有但 `plugin.Open()` 失败 | 自动降级为 NoopPlugin，日志打印错误但不崩溃 |
| 鉴权失败 | 10min 指数退避重试，超时后继续本地运行 |
| Diff 拉取失败 | 单周期跳过，下一轮继续拉，不阻塞本地防护 |

#### 闭源保护

`libcloudplugin/` 目录已在项目根 `.gitignore` 中配置忽略。**不要**把闭源代码提交到公开仓库：

```gitignore
# .gitignore（根目录）
agent/libcloudplugin/
*.so
```

---

## 3. 快速部署

### 3.1 一键部署（推荐）

```bash
# 1. 上传文件到服务器
scp wardennet_linux \
    configs/wardennet-agent.service \
    configs/wardennet.production.yaml \
    deploy.sh \
    root@your-server:/tmp/

# 2. 登录服务器执行部署
ssh root@your-server
bash /tmp/deploy.sh

# 3. 验证部署
systemctl status wardennet-agent
```

`deploy.sh` 执行流程：

```
[1/5] 检查系统依赖 → 确认 ipset/iptables 已安装
[2/5] 创建目录     → /opt/wardennet, /etc/wardennet, /var/lib/wardennet, /var/log/wardennet
[3/5] 安装 Agent    → 复制二进制到 /opt/wardennet/wardennet
[4/5] 配置服务     → 安装 systemd service
[5/5] 启动 Agent    → 启动并验证运行状态
```

### 3.2 手动部署

```bash
# 创建目录
mkdir -p /opt/wardennet
mkdir -p /etc/wardennet
mkdir -p /var/lib/wardennet
mkdir -p /var/log/wardennet

# 复制二进制
cp wardennet_linux /opt/wardennet/wardennet
chmod +x /opt/wardennet/wardennet

# 复制配置
cp wardennet.production.yaml /etc/wardennet/config.yaml

# 安装 systemd service
cat > /etc/systemd/system/wardennet-agent.service << 'EOF'
[Unit]
Description=WardenNet Agent - 本地恶意扫描防护
After=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/opt/wardennet/wardennet --config /etc/wardennet/config.yaml
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# 启动服务
systemctl daemon-reload
systemctl enable wardennet-agent
systemctl start wardennet-agent

# 查看状态
systemctl status wardennet-agent
```

### 3.3 验证部署

```bash
# 检查进程状态
systemctl status wardennet-agent
# 期望输出: active (running)

# 查看启动日志
journalctl -u wardennet-agent -n 30 --no-pager

# 检查 UnixSocket 是否就绪
ls -la /var/run/wardennet.sock
# 期望输出: srwxr-xr-x ... wardennet.sock

# 测试 CLI 连通性
echo '{"command":"status","args":{}}' | socat - UNIX-CONNECT:/var/run/wardennet.sock
# 期望输出: {"ok":true,"data":{"version":"v0.1",...}}

# 检查 iptables 规则
iptables -S INPUT | grep wardennet
# 期望输出: -A INPUT -p tcp -m set --match-set wardennet_blacklist src -j DROP

# 检查 ipset 集合
ipset list wardennet_blacklist
# 期望输出: Name: wardennet_blacklist, Type: hash:ip

ipset list wardennet_whitelist
# 期望输出: Name: wardennet_whitelist, Type: hash:net  ← v0.3 起改为 hash:net 支持 CIDR/IPv6
```

### 3.4 卸载 Agent

#### 3.4.1 完整卸载（推荐）

```bash
# 1. 停止并禁用服务
systemctl stop wardennet-agent
systemctl disable wardennet-agent

# 2. 卸载 systemd service
rm -f /etc/systemd/system/wardennet-agent.service
systemctl daemon-reload

# 3. 移除 iptables 规则
iptables -D INPUT -p tcp -m set --match-set wardennet_blacklist src -m multiport --dports 80,443 -j DROP 2>/dev/null
# 如果上面的命令失败，使用查找方式：
iptables -S INPUT | grep wardennet | sed 's/-A/-D/' | while read cmd; do
    iptables $cmd
done

# 4. 删除 ipset 集合
ipset destroy wardennet_blacklist 2>/dev/null
ipset destroy wardennet_whitelist 2>/dev/null

# 5. 删除 Agent 相关文件
rm -rf /opt/wardennet                    # 二进制、脚本
rm -rf /etc/wardennet                    # 配置文件
rm -rf /var/lib/wardennet                # 快照/状态
rm -rf /var/log/wardennet                # 日志文件（可选保留）
rm -f /var/run/wardennet.sock             # Unix Socket

# 6. 验证卸载完成
systemctl status wardennet-agent 2>&1 | grep -q "not found" && echo "服务已卸载"
ipset list | grep -q wardennet && echo "警告: ipset 集合未完全清除" || echo "ipset 已清除"
```

#### 3.4.2 保留数据卸载（仅卸载程序）

如果需要保留配置、日志和黑名单数据：

```bash
# 1. 停止服务
systemctl stop wardennet-agent

# 2. 移除 systemd service
rm -f /etc/systemd/system/wardennet-agent.service
systemctl daemon-reload

# 3. 移除二进制（保留配置和数据）
rm -f /opt/wardennet/wardennet

# 4. 保留以下目录/文件：
#   /etc/wardennet/          # 配置文件
#   /var/lib/wardennet/      # 快照/黑名单数据
#   /var/log/wardennet/      # 日志文件
```

#### 3.4.3 临时停止（不卸载）

如果只是临时停用 Agent 防护：

```bash
# 停止服务（进程仍会在下次开机自动启动）
systemctl stop wardennet-agent

# 禁用开机自启（手动启动仍可用）
systemctl disable wardennet-agent

# 手动重新启用
systemctl enable wardennet-agent
systemctl start wardennet-agent
```

#### 3.4.4 只清空黑名单（保留 Agent）

如果只想清空当前所有黑名单 IP：

```bash
# 方法一：通过 CLI 逐个删除
echo '{"command":"blocklist.status"}' | socat - UNIX-CONNECT:/var/run/wardennet.sock
# 获取黑名单 IP 列表后逐个删除

# 方法二：直接清空 ipset（跳过 Agent，立即生效）
ipset flush wardennet_blacklist
# 注意：Agent 重启后会从快照恢复，如需永久清空需同时删除快照
rm -f /var/lib/wardennet/state.json
systemctl restart wardennet-agent
```

#### 3.4.5 卸载注意事项

| 项目 | 说明 |
|---|---|
| **卸载后防护立即失效** | 停止 Agent 后，iptables 规则被移除，服务器不再受 WardenNet 保护 |
| **黑名单持久化** | 卸载时 ipset 集合会被删除，重新安装后需要重新配置黑名单 |
| **配置保留** | 建议在卸载前备份 `/etc/wardennet/config.yaml` |
| **日志可选保留** | `/var/log/wardennet/` 下的日志文件可按需保留或删除 |
| **系统影响** | 卸载不会影响其他服务，仅移除 WardenNet 相关组件 |

---

## 4. 配置详解

### 4.1 配置文件路径

默认：`/etc/wardennet/config.yaml`

可通过 `--config` 参数指定：
```bash
/opt/wardennet/wardennet --config /path/to/config.yaml
```

### 4.2 完整配置项

```yaml
# ===== Agent 基础参数 =====
agent:
  local_block_ttl: 259200    # 本地拉黑 TTL（秒），默认 72h
  cloud_block_ttl: 7200      # 云端下发拉黑 TTL 上限
  cloud_max_ttl: 86400       # 云端下发最大 TTL 上限

# ===== 日志输出 =====
log:
  level: info                 # debug / info / warn / error
  file: /var/log/wardennet/agent.log
  max_size: 100              # 单文件最大 MB
  max_backups: 7             # 保留旧文件数
  max_age: 30                # 旧文件保留天数
  compress: true             # 旧文件 gzip 压缩

# ===== 日志源采集 =====
log_sources:
  nginx_access:              # nginx 访问日志
    path: /var/log/nginx/access.log
    parser: nginx_access
  apache_access:             # Apache 访问日志（可选）
    path: /var/log/apache2/access.log
    parser: apache_access
  tomcat_access:             # Tomcat 访问日志（可选）
    path: /usr/local/tomcat/logs/localhost_access_log.txt
    parser: tomcat_access
  linux_auth:                # Linux 认证日志（可选）
    path: /var/log/auth.log
    parser: linux_auth

# ===== 滑动窗口检测引擎 =====
detector:
  enabled: true              # 是否启用检测
  score_high: 100            # 触发拉黑的风险分阈值
  weights:                   # 各检测维度权重（见 4.3）
    req_per_sec: 2
    status_4xx: 3
    status_5xx: 1
    auth_fail: 10
    status_404_ratio: 5
    sensitive_path: 8
    dangerous_pattern: 5    # 危险攻击模式（解码后匹配）
    bot_ua: 5
    empty_referer: 3
    real_user_bonus: 2
  windows:                   # 三档滑动窗口（见 4.4）
    # 10 秒窗口
    - size: 10
      max_req: 50
      max_4xx: 20
      max_5xx: 10
      max_fail: 3
      max_404_ratio: 80
      max_sensitive_path: 0
      max_bot_ua: 5
      max_empty_referer: 10
    # 30 秒窗口
    - size: 30
      max_req: 120
      max_4xx: 50
      max_5xx: 25
      max_fail: 5
      max_404_ratio: 80
      max_sensitive_path: 2
      max_bot_ua: 10
      max_empty_referer: 30
    # 60 秒窗口
    - size: 60
      max_req: 200
      max_4xx: 80
      max_5xx: 40
      max_fail: 10
      max_404_ratio: 80
      max_sensitive_path: 5
      max_bot_ua: 20
      max_empty_referer: 60

  # ===== 三段式特征列表 =====
  # 每个特征列表均支持两种 YAML 格式：
  # 格式一（简单列表，向后兼容）：
  #   known_http_clients: ["okhttp", "python-requests"]
  # 格式二（结构化，支持排除项和云端控制）：
  #   known_http_clients:
  #     local: ["okhttp", "python-requests"]   # 本地新增
  #     excludes: ["internal-api"]              # 排除业务确实存在的路径
  #     disable_builtin: false                  # 禁用内置默认值
  #     disable_cloud: false                    # 禁用云端拉取
  # 合并规则：Builtin + Local + Cloud → 去重 → 排除 Excludes → 最终生效列表

  # 合法 HTTP 客户端 UA 白名单（三段式）
  known_http_clients:
    # local: ["okhttp", "python-requests", "your-custom-client"]
    # excludes: ["internal-api"]

  # 敏感路径关键词列表（三段式，仅 status>=400 时计数）
  sensitive_paths:
    # local: ["actuator", "env", "your-custom-probe"]
    # excludes: ["env"]  # 业务中确实需要访问的路径

  # 危险攻击模式列表（三段式，解码后匹配 SQL 注入/XSS/路径遍历等）
  dangerous_patterns:
    # local: ["select ", "<script", "../", "etc/passwd"]
    # excludes: ["../"]  # 业务中确实存在的路径
    # disable_cloud: false  # 云端动态更新威胁情报

  # ===== 多事件确认机制（防误封） =====
  # 背景：单次高分可能是 NAT 出口 IP 后某客户端/插件/老旧代理网关
  #       一过性发几个请求（如安全探针），而非真正攻击。
  #       真实扫描器会在几秒内持续触发高分。
  # 机制：
  #   首次 isHigh → IP 进入观察名单，不计封。
  #   merge_window_sec 内连续 isHigh → 算同一次事件（只刷新时间）。
  #   observe_window_sec 内再次 isHigh（≥ merge_window_sec 后） → 计数 +1。
  #   count >= confirm_count → 触发封禁。
  #   observe_window_sec 过期未凑够 → 观察记录自动清除。
  #
  # confirm_count:    触发封禁需要的独立高分次数，默认 2。设为 1 关闭确认
  # observe_window_sec: 观察窗口（秒），默认 30
  # merge_window_sec:   同一次事件合并窗口（秒），默认 5
  confirm_count: 2
  observe_window_sec: 30
  merge_window_sec: 5

# ===== IP 黑白名单 =====
ipset:
  whitelist:                 # 本地白名单（永不拉黑）
    - 127.0.0.1
    - ::1
    - 192.168.220.0/24      # CIDR 网段（白名单已改为 hash:net 类型）
  blacklist: []              # 预加载黑名单（断网兜底）

# ===== UnixSocket CLI =====
unix_socket:
  path: /var/run/wardennet.sock
```

### 4.3 检测维度权重说明

| 参数 | 含义 | 推荐范围 | 说明 |
|---|---|---|---|
| `req_per_sec` | QPS 超限每单位加分数 | 1-5 | 快速突发攻击的主判据（**不作为空 Referer 的佐证信号**） |
| `status_4xx` | 4xx 超阈值每次加分 | 2-5 | 扫描器核心特征（401 降权为 1/5，纯 401 风暴硬上限 score_high/4；legitimateUserContext 场景额外降权 90% → 1 折；**concentrated4xx（v1.1）**：4xx 集中 ≤2 条归一化路径 + 非浏览器 + 非 Bot → 降权 50%） |
| `status_5xx` | 5xx 超阈值每次加分 | 1-3 | 辅助判断（权重较低，业务 Bug 可能触发） |
| `auth_fail` | 认证失败超阈值每次加分 | 5-15 | 爆破检测 |
| `status_404_ratio` | 404 比率超限每 10% 加分 | 3-8 | 目录扫描特征（legitimateUserContext 场景降权 90% → 1 折） |
| `sensitive_path` | 敏感路径命中每次加分 | 5-10 | `.env`, `.git`, `admin` 等（仅统计 status>=400） |
| `dangerous_pattern` | 危险攻击模式命中每次加分 | 3-8 | 解码后匹配 SQL 注入/XSS/路径遍历等（无论状态码），支持 max_dangerous_pattern 阈值控制 |
| `dangerous_method` | 危险 HTTP 方法每次加分 | 2-5 | CONNECT/TRACE/DELETE/PUT/PATCH/OPTIONS 等危险方法（独立权重，每请求上限 3× 权重） |
| `bot_ua` | 扫描器 UA 每次加分 | 3-8 | 扫描器 UA 检测（okhttp/python-requests 等已知 HTTP 客户端豁免） |
| `empty_referer` | 空 Referer 每次加分 | 2-5 | 扫描器通常不带 Referer（**始终受 score_high/4 硬上限保护**） |
| `real_user_bonus` | 真实用户行为扣分 | 1-3 | 静态资源 + 有效 Referer 双维度扣分 |
| `skip_paths` | 跳过检测的路径列表 | 配置项（YAML） | 匹配路径在 Process() 最前端直接跳过（/favicon.ico、/robots.txt、/.well-known/ 等默认值） |
| `honeypot_paths` | 蜜罐路径列表（v1.3 新增） | 配置项（YAML） | 扫描器必扫路径，命中即绝对封禁。绕过多事件确认、绕过 Consistency 降权 gate。支持精确匹配（`/admin`）和前缀匹配（`/traps/`）。默认空列表不启用 |
| `legitimate_user_context` | 正常浏览器场景降权 | 内部逻辑（自动判定） | 致命攻击特征为零 + 浏览器占比 ≥ 95% 时按比例容忍噪音 → status_4xx 和 status_404_ratio 降权 90%（× 0.1）；浏览器占比不足时保持严格（所有攻击特征计数必须为零） |
| `concentrated_4xx` | 4xx 路径集中度降权 | 内部逻辑（自动判定） | 4xx 集中在 ≤2 条归一化路径 + 非浏览器 + 非 Bot → status_4xx 降权 50%（× 0.5）；与 legitimateUserContext 互斥 |

#### 防误杀机制详解

| 机制 | 行为 | 影响 |
|---|---|---|
| **空 Referer × 404 协同置信度** | 空 Referer 同时伴随 ≥50% 404 比率时，硬上限从 score_high/4（25 分）放宽至 score_high/2（50 分） | 扫描器（空 Referer + 大量 404）置信度显著提高；合法 API（空 Referer + 少量 404）不受影响 |
| **QPS 不作为佐证信号** | 合法 API 客户端 QPS 突发是常态，不作为解锁空 Referer 防御的佐证信号 | 高频 API 调用不会绕过空 Referer 的硬上限 |
| **空 Referer 佐证降级** | 有真正攻击特征（4xx/404/敏感路径/Bot UA/危险方法/危险模式）时给予完整权重；无佐证时额外降级 80% | 扫描器（通常有多个攻击信号叠加）不受影响 |
| **401 单独降权** | 401 未授权（Token/Session 过期）权重降为 1/5，纯 401 风暴硬上限 score_high/4 | 合法 API 客户端 Token 过期重试不会误杀 |
| **已知 HTTP 客户端 UA 豁免** | okhttp、python-requests、axios、Postman 等 14 种 UA 不判定为 Bot | 合法 API 调用不会被 Bot UA 维度扣分 |
| **敏感路径状态码关联** | 敏感路径命中仅在 status >= 400 时计入 | 合法用户加载 `/env.js` 返回 200 不会被计为敏感路径 |
| **路径段精确匹配** | `env` 不匹配 `env.js`，`admin` 不匹配 `admin.js` | JavaScript 文件不会被误判为敏感路径 |
| **危险攻击模式解码检测** | 解码 URL/Unicode/Hex/HTML entity 编码后匹配攻击模式（50+ 模式覆盖 SQL 注入/XSS/路径遍历/命令注入/SSRF/SSTI 等 8 类） | 编码绕过的攻击可被识别，支持 max_dangerous_pattern 阈值控制 |
| **危险方法独立权重** | CONNECT/TRACE/DELETE 等危险 HTTP 方法使用独立权重（默认 3），不复用 status_4xx 权重 | 调低 4xx 敏感度不会影响危险方法检测 |
| **危险方法/模式贡献上限** | 危险方法每请求上限 3× 权重；危险模式贡献上限 score_high/2 | 防止单次请求贡献过量分数导致误判 |
| **真实用户奖励扣分** | 静态资源 + 有效 Referer 双维度扣分 | 降低合法用户的最终得分 |
| **SkipPaths 跳过检测** | 匹配 `skip_paths` 的路径在 Process() 最前端直接跳过（完全不计数、不计分） | /favicon.ico、/robots.txt、/.well-known 等浏览器/爬虫常规行为不参与检测 |
| **HoneypotPaths 蜜罐绝对封禁（v1.3）** | 匹配 `honeypot_paths` 的路径在 Process() 最前端直接给 ceiling 分（ScoreHigh×2）+ 绕过多事件确认 + 绕过 Consistency 降权 gate。单次命中即封 | 正常用户不可能访问你故意设的陷阱路径，蜜罐命中是零误报的最高置信度信号。report-only 模式尊重用户选择只上报不封禁 |
| **legitimateUserContext 降权** | 致命攻击特征（危险攻击模式/危险方法/文件上传拦截）为零 + 浏览器占比 ≥ 95% 时按比例容忍噪音（BotUA≤3%且≤5次/SensPath≤2%且≤3次/AuthFail≤2%且≤3次）→ status_4xx 和 status_404_ratio 两个维度降权 90%（× 0.1）；浏览器占比不足 95% 时保持严格（所有攻击特征计数必须为零） | 合法用户访问"坏掉的后端"（nginx 反代错误/后端未启动）导致前端 SPA 批量 404 时不被误杀；正常浏览器占 ≥ 95% 说明就是真人，零星 BotUA/SensPath 只是噪音；扫描器因含攻击特征或浏览器占比不足不会触发此降权 |
| **concentrated4xx 降权（v1.1）** | 4xx 集中在 ≤2 条归一化路径 + 非浏览器（NormalBrowserHit=0）+ 非 Bot（BotUAHit=0）→ status_4xx 降权 50%（× 0.5）。与 legitimateUserContext 互斥（后者要求 NormalBrowserHit>0） | 合法 HTTP 客户端（Apache-HttpClient/OkHttp）反复调单一坏端点（如 `/oauth/token` 返回 400）时不被误杀；扫描器天然分散探测 5-10+ 路径，Distinct4xxPaths 远超阈值，无法触发 |
| **本地 IP 白名单优先** | 命中白名单直接跳过所有检测 | 运维/健康检查 IP 完全豁免 |
| **多事件确认（v0.4.1）** | 单次高分不立即封，要求同一 IP 在观察窗口内凑够 `confirm_count` 次独立高分才封；`merge_window_sec` 内连续触发合并为同一次事件；`observe_window_sec` 过期自动清除 | NAT 出口 IP 后某客户端/插件一过性请求不会被封；真实扫描器几秒内持续触发会二次确认凑够次数 |

### 4.4 三档窗口说明

| 窗口 | 检测目标 | 适用场景 |
|---|---|---|
| **10s** | 快速突发 | CC 攻击、暴力破解、高频扫描 |
| **30s** | 中等速度 | 常规扫描、漏洞探测 |
| **60s** | 慢速分布式 | 低频扫描、分布式攻击 |

### 4.5 配置热重载

修改配置文件后 Agent 自动热重载（5 秒轮询），无需重启：

```bash
vim /etc/wardennet/config.yaml
# 保存后 5 秒内生效
```

也可通过 CLI 手动触发：
```bash
echo '{"command":"reload","args":{}}' | socat - UNIX-CONNECT:/var/run/wardennet.sock
```

---

## 5. 运维操作

### 5.1 服务管理

```bash
# 启动
systemctl start wardennet-agent

# 停止
systemctl stop wardennet-agent

# 重启
systemctl restart wardennet-agent

# 查看状态
systemctl status wardennet-agent

# 开机自启（部署时已自动执行）
systemctl enable wardennet-agent

# 查看最近日志
journalctl -u wardennet-agent -n 50

# 实时跟踪日志
journalctl -u wardennet-agent -f

# 查看启动以来的所有日志
journalctl -u wardennet-agent --since "today"
```

### 5.2 升级 Agent

```bash
# 1. 编译新版本
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -o wardennet_linux \
    -ldflags="-s -w -X main.Version=v0.2" \
    ./cmd/wardennet

# 2. 上传并替换二进制
scp wardennet_linux root@server:/opt/wardennet/wardennet
# 或直接在服务器上：
cp wardennet_linux /opt/wardennet/wardennet
chmod +x /opt/wardennet/wardennet

# 3. 重启服务（自动保存快照）
systemctl restart wardennet-agent

# 4. 验证新版本
echo '{"command":"status","args":{}}' | socat - UNIX-CONNECT:/var/run/wardennet.sock
# 检查 version 字段
```

### 5.3 降级 / 回滚

```bash
# 保留旧版本二进制
cp /opt/wardennet/wardennet /opt/wardennet/wardennet.bak.v0.1

# 回滚
cp /opt/wardennet/wardennet.bak.v0.1 /opt/wardennet/wardennet
systemctl restart wardennet-agent
```

### 5.4 手动管理 IP 黑名单

```bash
# 手动拉黑 IP（带 1 小时 TTL）
echo '{"command":"blocklist.add","args":{"ip":"203.0.113.100","ttl":3600}}' \
  | socat - UNIX-CONNECT:/var/run/wardennet.sock

# 永久拉黑（TTL 为 0 表示使用配置默认值 259200 秒）
echo '{"command":"blocklist.add","args":{"ip":"10.0.0.99"}}' \
  | socat - UNIX-CONNECT:/var/run/wardennet.sock

# 解除拉黑
echo '{"command":"blocklist.del","args":{"ip":"203.0.113.100"}}' \
  | socat - UNIX-CONNECT:/var/run/wardennet.sock

# 查看黑名单状态
echo '{"command":"blocklist.status","args":{}}' \
  | socat - UNIX-CONNECT:/var/run/wardennet.sock
```

### 5.5 直接操作 ipset（绕过 Agent）

```bash
# 查看黑名单集
ipset list wardennet_blacklist

# 添加 IP（直接操作，不推荐）
ipset add wardennet_blacklist 203.0.113.100

# 删除 IP
ipset del wardennet_blacklist 203.0.113.100

# 清空集合（危险操作）
ipset flush wardennet_blacklist

# 创建集合（Agent 启动时自动创建，一般无需手动）
# 注意：wardennet_whitelist 使用 hash:net 类型（支持 CIDR 和 IPv6）
ipset create wardennet_blacklist hash:ip
ipset create wardennet_whitelist hash:net family inet hashsize 1024 maxelem 65536
```

### 5.6 iptables 规则管理

```bash
# 查看当前规则
iptables -S INPUT | grep wardennet

# 查看规则详情
iptables -L INPUT -n -v | grep -A 3 wardennet

# 手动添加规则（一般由 Agent 自动完成）
iptables -I INPUT -p tcp -m set --match-set wardennet_blacklist src \
    -m multiport --dports 80,443 -j DROP

# 手动删除规则
iptables -D INPUT -p tcp -m set --match-set wardennet_blacklist src \
    -m multiport --dports 80,443 -j DROP
```

### 5.7 配置备份与恢复

```bash
# 备份配置
cp /etc/wardennet/config.yaml /etc/wardennet/config.yaml.bak.$(date +%Y%m%d)

# 恢复配置
cp /etc/wardennet/config.yaml.bak.20260827 /etc/wardennet/config.yaml
# Agent 会在 5 秒内自动热重载，或手动触发：
echo '{"command":"reload","args":{}}' | socat - UNIX-CONNECT:/var/run/wardennet.sock
```

### 5.8 快照恢复

```bash
# 查看快照文件
cat /var/lib/wardennet/state.json | python3 -m json.tool

# 手动触发快照保存
echo '{"command":"status","args":{}}' | socat - UNIX-CONNECT:/var/run/wardennet.sock
# 快照每 60 秒自动保存，优雅关闭时也会保存

# 从快照恢复（重启 Agent 时自动执行）
systemctl restart wardennet-agent
# 日志中会显示：snapshot restored, ttl_entries=N
```

---

## 6. CLI 命令手册

所有 CLI 命令通过 Unix Socket 发送 JSON 请求。

### 6.1 通信方式

```bash
# 方式一：socat（推荐）
echo '{"command":"命令","args":{}}' | socat - UNIX-CONNECT:/var/run/wardennet.sock

# 方式二：bash /dev/tcp
exec 3<>/var/run/wardennet.sock
echo '{"command":"status","args":{}}' >&3
cat <&3
exec 3<&-

# 方式三：Python 脚本
python3 -c "
import socket, json
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('/var/run/wardennet.sock')
s.sendall(json.dumps({'command':'status','args':{}}).encode() + b'\n')
print(s.recv(4096).decode())
s.close()
"
```

### 6.2 命令列表

| 命令 | 说明 | 请求参数 |
|---|---|---|
| `status` | Agent 整体状态 | 无 |
| `blocklist.add` | 添加黑名单 IP | `ip`（必填）, `ttl`（可选，秒）, `force`（可选，bool） |
| `blocklist.del` | 移除黑名单 IP | `ip`（必填） |
| `blocklist.status` | 黑白名单统计 | 无 |
| `reload` | 热重载配置 | 无 |

### 6.3 命令示例

**status — 查看 Agent 状态**
```bash
echo '{"command":"status","args":{}}' | socat - UNIX-CONNECT:/var/run/wardennet.sock

# 响应示例：
# {
#   "ok": true,
#   "data": {
#   "version": "v0.2",
#     "timestamp": 1756383600,
#     "blocked_count": 1,
#     "whitelist_count": 2,
#     "ttl_entries": 1
#   }
# }
```

**blocklist.add — 添加黑名单**
```bash
# 永久拉黑（使用配置默认 TTL）
echo '{"command":"blocklist.add","args":{"ip":"203.0.113.100"}}' \
  | socat - UNIX-CONNECT:/var/run/wardennet.sock

# 临时拉黑 1 小时
echo '{"command":"blocklist.add","args":{"ip":"10.0.0.1","ttl":3600}}' \
  | socat - UNIX-CONNECT:/var/run/wardennet.sock

# 即使在白名单中也强制拉黑
echo '{"command":"blocklist.add","args":{"ip":"127.0.0.1","force":true}}' \
  | socat - UNIX-CONNECT:/var/run/wardennet.sock

# 响应示例：
# {
#   "ok": true,
#   "data": {
#     "ip": "203.0.113.100",
#     "accepted": true,
#     "ttl": 259200,
#     "expires_at": 1756642800
#   }
# }
```

**blocklist.del — 移除黑名单**
```bash
echo '{"command":"blocklist.del","args":{"ip":"203.0.113.100"}}' \
  | socat - UNIX-CONNECT:/var/run/wardennet.sock

# 响应示例：
# {"ok":true,"data":{"ip":"203.0.113.100"}}
```

**blocklist.status — 查看名单统计**
```bash
echo '{"command":"blocklist.status","args":{}}' \
  | socat - UNIX-CONNECT:/var/run/wardennet.sock

# 响应示例：
# {
#   "ok": true,
#   "data": {
#     "blocked_count": 5,
#     "whitelist_count": 3,
#     "ttl_entries": 5
#   }
# }
```

**reload — 热重载配置**
```bash
echo '{"command":"reload","args":{}}' | socat - UNIX-CONNECT:/var/run/wardennet.sock

# 响应示例：
# {"ok":true,"message":"reloaded successfully"}
```

### 6.4 错误响应格式

```json
{
  "ok": false,
  "error": "错误描述信息"
}
```

常见错误：

| 错误 | 原因 | 解决方案 |
|---|---|---|
| `missing or invalid 'ip' arg` | 未提供 ip 参数或格式错误 | 检查 ip 字段 |
| `SKIP: ip in local whitelist` | IP 在白名单中不会被拉黑 | 使用 `force: true` 或从白名单移除 |
| `ipset command failed` | ipset 命令执行失败 | 检查 ipset 是否已安装 |
| `connection refused` | Unix Socket 未就绪 | 检查 Agent 是否在运行 |

---

## 7. 日志与监控

### 7.1 日志文件

默认路径：`/var/log/wardennet/agent.log`

日志轮转配置：
- 单文件最大：100MB
- 保留旧文件：7 个
- 保留天数：30 天
- 压缩：启用

### 7.2 日志级别

| 级别 | 用途 | 示例 |
|---|---|---|
| `debug` | 开发调试 | 每个事件的详细处理过程 |
| `info` | 常规运行 | 启动、停止、配置变更、拉黑事件 |
| `warn` | 警告 | ipset 操作失败、配置加载失败 |
| `error` | 错误 | 严重故障 |

**生产环境建议 `info`**，调试时临时改为 `debug`。

### 7.3 关键日志标记

| 关键字 | 含义 |
|---|---|
| `wardennet agent starting` | Agent 启动 |
| `auto blocked by detector` | 检测引擎自动拉黑 |
| `auto block failed` | 自动拉黑失败（检查 ipset） |
| `snapshot restored` | 从快照恢复成功 |
| `snapshot restore skipped` | 快照恢复跳过（首次启动） |
| `iptables ban rule ensured` | iptables 规则已就绪 |
| `iptables ban rule remove` | iptables 规则已移除 |
| `config watcher started` | 配置热重载已启动 |
| `log tail started` | 日志 tail 已启动 |
| `agent fully initialized` | Agent 全链路就绪 |
| `received signal, shutting down` | 收到退出信号 |
| `final snapshot saved` | 最终快照已保存 |
| `detector score detail` | 每次事件的三档窗口评分详情（debug 级别） |

#### 评分详情日志解读

debug 级别下，每个事件都会输出评分详情：

```
level=DEBUG msg="detector score detail" ip=106.58.181.146 score=102 is_high=true
  source=nginx_access path="/api/env" method=GET status=404
  ua="sqlmap/1.5.2"
  win10s="win=10s score=102 [qps=0 4xx=0 5xx=0 fail=0 404=0 sens=0 ua=0 ref=102 method=0 bonus=0]
    cnt[req=44 4xx=0 5xx=0 404=0 fail=0 sens=0 ua=0 ref=44 method=0 static=0]"
```

**字段解读**：
- `score`：三档窗口最高分，`is_high=true` 表示已触发拉黑阈值
- `win10s/win30s/win60s`：三档窗口各自的得分详情
- `qps/4xx/5xx/fail/404/sens/ua/ref/method/bonus`：各维度贡献分数
- `cnt[req=... 4xx=... ...]`：原始计数
- `ref=102(mitigated)`：空 Referer 已降级 80%（佐证信号机制生效）

### 7.4 日志查询示例

```bash
# 查看最近 30 分钟的拉黑事件
grep "auto blocked" /var/log/wardennet/agent.log | grep "$(date -d '30 minutes ago' '+%Y-%m-%d %H')"

# 查看所有被拉黑的 IP
grep "auto blocked" /var/log/wardennet/agent.log | awk '{print $NF}' | sort -u

# 查看 ipset 操作失败
grep "failed" /var/log/wardennet/agent.log

# 查看配置变更记录
grep -E "reload|config" /var/log/wardennet/agent.log

# 实时监控新拉黑事件
tail -f /var/log/wardennet/agent.log | grep --line-buffered "auto blocked"
```

### 7.5 健康检查脚本

```bash
#!/bin/bash
# healthcheck.sh — WardenNet Agent 健康检查

SOCK="/var/run/wardennet.sock"
LOG="/var/log/wardennet/agent.log"

# 1. 检查进程
if ! systemctl is-active --quiet wardennet-agent; then
    echo "FAIL: Agent 未运行"
    exit 1
fi

# 2. 检查 Unix Socket
if [ ! -S "$SOCK" ]; then
    echo "FAIL: Unix Socket 不存在"
    exit 1
fi

# 3. 检查 CLI 响应
RESP=$(echo '{"command":"status","args":{}}' | socat - UNIX-CONNECT "$SOCK" 2>/dev/null)
if ! echo "$RESP" | grep -q '"ok":true'; then
    echo "FAIL: CLI 无响应"
    exit 1
fi

# 4. 检查日志错误
ERRORS=$(grep -c "level=error" "$LOG" 2>/dev/null || echo 0)
if [ "$ERRORS" -gt 10 ]; then
    echo "WARN: 日志中存在 $ERRORS 条错误"
fi

echo "OK: Agent 运行正常"
echo "    状态: $RESP"
exit 0
```

使用方法：
```bash
chmod +x healthcheck.sh
./healthcheck.sh

# 配合 crontab 定时检查
# */5 * * * * /path/to/healthcheck.sh >> /var/log/wardennet/healthcheck.log 2>&1
```

---

## 8. 故障排查

### 8.1 常见问题

#### Q1: Agent 启动后立即退出

```bash
# 查看详细错误
journalctl -u wardennet-agent -n 50 --no-pager

# 常见原因：
# 1. 配置文件路径错误
# 2. 日志目录权限不足
# 3. ipset 命令不存在
```

**排查步骤**：
```bash
# 手动启动查看错误
/opt/wardennet/wardennet --config /etc/wardennet/config.yaml

# 检查依赖
which ipset
which iptables

# 检查目录权限
ls -la /var/log/wardennet/
ls -la /var/lib/wardennet/
ls -la /var/run/
```

#### Q2: IP 未被真正封禁

```bash
# 1. 检查 ipset 集合是否存在
ipset list wardennet_blacklist

# 2. 检查 IP 是否在集合中
ipset test wardennet_blacklist <IP>

# 3. 检查 iptables 规则
iptables -S INPUT | grep wardennet

# 4. 检查日志中是否有拉黑记录
grep "auto blocked" /var/log/wardennet/agent.log
```

#### Q3: ipset 操作报 "set doesn't exist"

```bash
# 手动创建集合（Agent 启动时应自动创建）
ipset create wardennet_blacklist hash:ip
ipset create wardennet_whitelist hash:net family inet hashsize 1024 maxelem 65536

# 重启 Agent
systemctl restart wardennet-agent
```

#### Q4: Unix Socket 无法连接

```bash
# 检查文件是否存在
ls -la /var/run/wardennet.sock

# 检查权限（需 root 可访问）
stat /var/run/wardennet.sock

# 检查 Agent 是否在运行
systemctl status wardennet-agent
```

#### Q5: 检测引擎过于敏感或迟钝

```bash
# 修改配置文件 /etc/wardennet/config.yaml
# 调低 score_high 阈值 → 更敏感
# 调高 score_high 阈值 → 更迟钝

# 调整窗口参数：
#   max_req 降低 → 更敏感
#   max_404_ratio 提高 → 对 404 更宽容

# 调整权重参数：
#   sensitive_path 降低 → 忽略敏感路径
#   bot_ua 降低 → 忽略扫描器 UA

# 热重载生效
echo '{"command":"reload","args":{}}' | socat - UNIX-CONNECT:/var/run/wardennet.sock
```

### 8.2 调试模式

临时启用 debug 日志级别：

```bash
# 修改配置
sed -i 's/level: info/level: debug/' /etc/wardennet/config.yaml

# 热重载
echo '{"command":"reload","args":{}}' | socat - UNIX-CONNECT:/var/run/wardennet.sock

# 查看实时日志
tail -f /var/log/wardennet/agent.log | grep --line-buffered "level=debug"

# 调试完毕后恢复
sed -i 's/level: debug/level: info/' /etc/wardennet/config.yaml
echo '{"command":"reload","args":{}}' | socat - UNIX-CONNECT:/var/run/wardennet.sock
```

### 8.3 紧急操作

```bash
# 紧急停止所有封禁（保留 Agent 运行）
# 方法：清空 ipset 集合
ipset flush wardennet_blacklist

# 完全停止 Agent
systemctl stop wardennet-agent

# 停止后 ipset 集合和 iptables 规则保留，重启 Agent 后继续生效
# 如需完全清除：
ipset flush wardennet_blacklist
iptables -D INPUT -p tcp -m set --match-set wardennet_blacklist src \
    -m multiport --dports 80,443 -j DROP 2>/dev/null
```

### 8.4 性能调优

| 场景 | 建议 |
|---|---|
| **高 QPS 网站** | 增大 10s 窗口 `max_req` 到 50+，避免误杀正常用户 |
| **API 服务器** | 空 Referer 已自动降级 80% + 硬上限；401 已降权 1/5 + 硬上限；`bot_ua` 对 okhttp/python-requests 等已知 HTTP 客户端豁免 |
| **内部系统** | 增大 `bot_ua` 阈值（内部系统可能用 curl/wget 调用）；使用 `excludes` 排除确实存在的业务路径 |
| **CDN 后端** | 将 CDN IP 段加入 whitelist（CIDR 网段已支持，白名单改为 hash:net 类型） |
| **业务存在特殊路径** | 在 `dangerous_patterns.excludes` 中排除确实需要访问的路径（如 `../`、`select` 等） |
| **云端威胁情报** | `dangerous_patterns.disable_cloud: false` 启用云端动态更新，获取最新攻击模式 |
| **误杀排查** | 开启 debug 日志查看 `detector score detail`，关注 `(mitigated)` 标记和 `danger=` 字段 |

### 8.5 与现有 Python 脚本共存

如果之前使用了 `demo/ban_watch.py`，两者可以共存：

```bash
# 1. 停掉 Python 脚本
pkill -f ban_watch.py

# 2. （可选）清理旧 ipset 集合
ipset destroy web_black  # 如果之前用的是这个名字

# 3. 启动 Agent（自动创建 wardennet_blacklist 和 iptables 规则）
systemctl start wardennet-agent
```

两个系统使用**不同的 ipset 集合名**，iptables 规则独立，不会冲突。

---

## 9. 架构说明

### 9.1 模块架构

```
┌─────────────────────────────────────────────────────┐
│                    WardenNet Agent                    │
│                                                        │
│  ┌──────────┐   ┌──────────┐   ┌──────────────────┐  │
│  │ logparser │──▶│ detector  │──▶│   ipsetutil     │  │
│  │ (日志解析) │   │ (检测引擎)│   │ (IPSET 管理)     │  │
│  └──────────┘   └──────────┘   └────────┬─────────┘  │
│                                           │            │
│                                           ▼            │
│                                    ┌──────────────────┐│
│                                    │   ttl (TTL 管理)  ││
│                                    └────────┬─────────┘│
│                                             │          │
│  ┌──────────┐   ┌──────────┐               │          │
│  │ unixsocket│   │ snapshot  │               │          │
│  │ (CLI 服务) │   │ (状态持久化)│              │          │
│  └─────┬─────┘   └──────────┘               │          │
│        │                                    │          │
│        ▼                                    ▼          │
│  ┌──────────┐   ┌──────────┐                        │
│  │   cli    │   │  plugin   │                        │
│  │ (命令处理)│   │ (云端插件) │                         │
│  └──────────┘   └──────────┘                        │
│                                                        │
└─────────────────────────────────────────────────────┘
         │                              │
         ▼                              ▼
   Linux ipset                    iptables DROP
   (内核 IP 集合)                (内核流量拦截)
```

### 9.2 数据流

```
nginx access.log                    Agent 内部处理                    内核
     │                                  │                              │
     │ tail 读取                        │                              │
     ▼                                  │                              │
 ┌─────────┐     解析     ┌─────────┐   │                              │
 │logparser │─────────────▶│ detector │   │                              │
 │          │  nginx_access│          │   │                              │
 └─────────┘              └────┬────┘   │                              │
                               │ 12 维打分 + 11 层防误杀               │
                               ▼         │                              │
                        ┌─────────┐     │                              │
                        │ 评分 ≥ 50?│    │                              │
                        └────┬────┘     │                              │
                     Yes │          No  │                              │
                         ▼              │                              │
                   ┌─────────────┐      │                              │
                   │ ipsetutil   │      │                              │
                   │ Block(ip)   │──────┼──────────────────────────────▶│ DROP
                   │ (带 timeout)│      │                              │
                   └──────┬──────┘      │                              │
                          │             │                              │
                          ▼             │                              │
                   ┌─────────────┐      │                              │
                   │ ttl Manager │      │                              │
                   │ Add(Local)   │      │                              │
                   └─────────────┘      │                              │
                                        │                              │
Plugin fetch 云端威胁评分          applyDecisions
     │                                  │                              │
     ▼                                  ▼                              │
 ┌─────────┐                   ┌─────────────┐                          │
 │DecideAll │─────────────────▶│ ipsetutil   │─────────────────────────▶│ DROP
 │两层决策   │                   │ ApplyCloud  │ (带 kernel timeout)      │
 └─────────┘                   └──────┬──────┘                          │
                                      │                              
                                      ▼                              
                               ┌─────────────┐                       
                               │ ttl Manager │                       
                               │ Add(Cloud)  │                       
                               └─────────────┘                       
```

> **修复记录**：v0.4.2 之前 `applyDecisions` 构造的 ipset Entry 无 Timeout 字段 → 云端封锁只有 TTL Sweep 单通道解封，进程崩溃 + 快照丢失时封锁永久化。修复后云端封锁与本地一致：ipset add 带 `--timeout cloud_block_ttl` + TTL Manager 注册 SourceCloud。详见 §9.4 解封架构。

### 9.3 检测维度详解

| 维度 | 检测方法 | 攻击特征 | 防误杀机制 |
|---|---|---|---|
| **QPS 频率** | 三档窗口内单 IP 请求数 | 暴力扫描、CC 攻击 | - |
| **4xx 比率** | 404/403 占总请求比例 | 目录扫描、漏洞探测 | 401 降权 1/5 + 硬上限 |
| **404 比率** | 404 占比超阈值加分 | 扫描器核心特征 | - |
| **敏感路径** | 路径段精确匹配 + 仅 status≥400 | 信息泄露、后台探测 | 状态码关联 + 路径段精确匹配 |
| **危险攻击模式** | URL/Unicode/Hex 解码后匹配 SQL 注入/XSS/路径遍历 | 注入攻击、路径遍历、命令执行 | 任一窗口内 hit ≥ 2 才触发高置信度直封；单次 hit 进多事件确认 |
| **Bot UA** | UA 匹配扫描器关键词 | 自动化扫描器 | 已知 HTTP 客户端 UA 白名单豁免 |
| **空 Referer** | Referer 为空或无意义 | 非真实用户访问 | 佐证信号机制（单独触发降级 80% + 硬上限） |
| **危险方法** | CONNECT/TRACE/DELETE 等 | 请求方法探测 | - |
| **认证失败** | linux_auth Failed/Invalid 次数 | 密码爆破 | - |
| **真实用户奖励** | 静态资源 + 有效 Referer | 降低误判 | 双维度扣分 |

### 9.4 解封架构：本地 vs 云端双通道

Agent 有两类封锁来源，解封策略都是**双通道冗余**（内核 timeout + TTL Sweep），但参数不同：

```
┌─────────────────────────────────────────────────────────────────┐
│                        本地封锁（SourceLocal）                  │
│  触发方：detector.BlockTrigger / CLI blocklist.add               │
│  TTL 值：config.local_block_ttl（默认 3600s，可 CLI 指定）       │
│                                                                   │
│  通道 1: ipset kernel timeout                                    │
│    ipset add --timeout 3600 → 内核到点自动删除条目               │
│                                                                   │
│  通道 2: TTL Sweep → onExpire → ipMgr.Unblock                    │
│    ttlMgr.Add(ip, 3600, SourceLocal) → 每 30s Sweep 到期清理     │
│    Unblock 无条件 delete blocked map（防 kernel timeout 竞态残留）│
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                        云端封锁（SourceCloud）                   │
│  触发方：SyncEngine.applyDecisions（含联防快速通道）              │
│  TTL 值：config.cloud_block_ttl（默认 7200s，硬上限 cloud_max_ttl）│
│                                                                   │
│  通道 1: ipset kernel timeout  ← v0.4.2 新增                     │
│    ipset add --timeout 7200 → 内核兜底（进程崩溃快照丢失时仍能解封）│
│                                                                   │
│  通道 2: TTL Sweep → onExpire → ipMgr.Unblock                    │
│    ttlMgr.Add(ip, 0, SourceCloud) → adjustTTL 自动填 CloudBlockTTL│
│    每轮云端 diff 评分仍高时 → 重新 Block + 刷新 TTL               │
│    云端评分下降 / threat_pool TTL 到期 → 双通道触发解封            │
└─────────────────────────────────────────────────────────────────┘

关键设计点：
- **为什么云端也要 kernel timeout**：v0.4.1 只有 TTL Sweep 单通道，进程被 kill -9 时最后 60s 快照间隔内的 TTL 条目丢失 → 内核条目永存 → **云端封锁永久化**。本地封锁一直有 kernel timeout，云端没有。v0.4.2 补齐。
- **TTL 刷新**：云端封锁每轮 diff 都重新 Block + Add（ttl.Add 覆盖旧条目）。不是"倒计时不中断"，是"每次看到威胁重新计时"。
- **白名单豁免的封锁不注册 TTL**：ApplyCloud 先过滤白名单，被豁免的 IP 跳过 Add。
- **OpDel 幂等**：client_linux.go 的 OpDel 加 `-exist` 标志（条目不存在时静默成功），配合 Unblock 无条件清内存 map，消除 kernel timeout 与 TTL Sweep 的竞态残留。

### 9.5 联防两层决策架构

```
ThreatScore { Source, Score, VoteCount }
              │
              ▼
┌──────────────────────────────────────────────────────────────┐
│ 层 2: 联防快速通道（首发阻断核心）                           │
│                                                              │
│   触发条件（全部硬编码，不可热更）：                           │
│     Source == "global"                                       │
│     AND VoteCount ≥ 20      ← 20+ 独立租户跨共识             │
│     AND Score ≥ 90           ← 云端原始评分极高威胁            │
│                                                              │
│   直接 Block，FastPath=true                                  │
│   不管本地有没有见过这个 IP（本地白名单除外）                  │
│   解封：走 SourceCloud 双通道（§9.4）                         │
│                                                              │
│   安全：private 池永远不能触发（VoteCount 语义不同）          │
│   安全：20 是硬门槛，云端热更权重也绕不过去                    │
└──────────────────────────────────────────────────────────────┘
              │ 不满足快速通道
              ▼
┌──────────────────────────────────────────────────────────────┐
│ 层 1: 默认加权（协同增强）                                   │
│                                                              │
│   cloudConfidenceMultiplier(VoteCount)：                     │
│     vote≥20 → 1.00   vote≥10 → 0.90   vote≥5 → 0.75         │
│     vote≥3 → 0.60    vote=1 → 0.40   未知 → 0.70            │
│                                                              │
│   effective_cloud = cloud_score × multiplier                 │
│   final = effective_cloud×0.4 + freq×0.3 + det×0.3          │
│                                                              │
│   ≥ 80 → BLOCK   ≥ 50 → ALERT   < 50 → IGNORE               │
│                                                              │
│   安全：单租户 vote=1 时 multiplier=0.40，                   │
│         单租户误报 cloud=100 → final=46 → IGNORE             │
│         本地 Score 可由 detector 真实评分提供                  │
└──────────────────────────────────────────────────────────────┘

安全边界（全部硬编码，不可热更）：
| 常量 | 值 | 说明 |
|---|---|---|
| CONSENSUS_MIN_VOTES | 20 | 至少 20 个独立付费租户投票 |
| CONSENSUS_MIN_SCORE | 90 | 云端原始评分必须极高 |
| decisionBlockThreshold | 80 | 加权层 composite ≥ 80 才封 |

vote=1 时 multiplier=0.40 的安全效果：
```
单租户误报 cloud=100:
  effective = 100 × 0.40 = 40
  final = 40×0.4 + 50×0.3 + 50×0.3 = 16 + 15 + 15 = 46 → IGNORE
  ✓ 安全否决

联防快速通道 cloud=95, vote=50:
  Source=global, 50≥20, 95≥90 → 直接 Block, FastPath=true
  ✓ 首发阻断生效
```

关键依赖：diff_service._load_global_scores() 和 _format_global_incr() 必须返回 `"source": "global"`。没有这个字段时 VoteCount confidence multiplier 走默认 0.70 而非分层值，快速通道永远不触发。

---

*文档版本：v0.4.2*
*适用 Agent 版本：v0.4.2+（含双通道解封架构、联防两层决策、云端封锁 kernel timeout 修复）*
*更新时间：2026-09-09*

---

## 附录 A：v1.2 变更说明

### Consistency 5 维行为连贯性评分（新增防误杀第 13 层）

- **背景**：合法 API 客户端突发 QPS（如批量同步 30 req/s），Scorer 因基线偏离给 score_high 触发封禁。但这种突发在**行为形状**上仍是合法的（路径连贯、状态稳定），与扫描器每条路径只扫一次的发散模式有本质区别
- **零业务依赖**：只用 access.log 必有字段——path、method、status，不看 header、query、业务路径语义
- **5 维评分**（加 2 维反信号，共 7 项）：

| 维度 | 含义 | 正向阈值 | 反信号 |
|------|------|---------|--------|
| 前缀连贯 | 连续请求同前缀路径 | avgRunLen ≥ 3 或 dominant ≥ 50% | — |
| 新颖度饱和 | 新人先覆盖旧路径，后面不扫新路 | 前 30% 覆盖 ≥ 70% + 后 30% 新增 ≤ 40% | — |
| 路径集中 | Top5 路径覆盖比例 | ≥ 25% | — |
| 状态同质 | 同路径返回稳定状态码 | CV < 0.6 | — |
| 方法语义 | GET/POST 为主，PUT/DELETE 少 | GET [50%, 99%] + POST [1%, 49%] | — |
| 反复撞墙 | — | — | 动态路径 ≥5 次全错 → -5 |
| 发散扫描 | — | — | 早 30% < 50% + 后 30% 新增 > 70% + Top5 < 40% → -3 |

- **降权 gate 位置**：Scorer 之后、shouldBlock 之前。条件满足时强制 finalScore 从 score_high 降到 score_medium，让多事件确认机制去处理——真正的攻击会持续触发 shouldBlock，合法突发会被时间窗口稀释
- **参数化**：所有阈值、权重、工程参数集中在 `ConsistencyThresholds` 结构，可通过 YAML `detector.consistency` 段覆盖；nil 字段保留程序默认值。默认值与 hardcoded 版本一致，生产行为零变化
- **内存**：ring buffer 512 条/IP，每条 ~64 字节；500 活跃 IP ≈ 16 MB
- **配置位置**：`detector.consistency.*`（详见 AGENT_OPS.md §6.2）

---

## 附录 B：v0.4.1 变更说明

### 多事件确认机制（防误封）

- **背景**：单次高分可能是 NAT 出口 IP 后某客户端/插件/老旧代理网关一过性请求（如安全探针探测、某个嵌入式设备无 UA 发几个请求），而非真正攻击。之前只要单次高分就封，导致 NAT 共享 IP 上的合法用户被误封
- **核心机制**：新增观察名单，单次 isHigh 只进观察名单不封，要求 `confirm_count`（默认 2）次独立高分才真正封禁
- **合并窗口**：`merge_window_sec`（默认 5s）内连续 isHigh 合并为同一次事件，防止同一波请求被算多次
- **观察窗口过期清除**：`observe_window_sec`（默认 30s）内未凑够次数自动清除，视为一过性噪声
- **向后兼容**：`confirm_count=1` 时关闭确认，单次高分即封
- **实时场景**：
  - 误封 IP 场景（14.20.151.79）：2 秒内 7 个空 UA 探测请求 → 全被 mergeWindow 合并成 1 次 → count=1 → 不封 ✓
  - 真实扫描器场景：几秒后又继续探测 → count=2 → 封 ✓
- **配置位置**：`detector.confirm_count` / `detector.observe_window_sec` / `detector.merge_window_sec`

---

## 附录 A（续）：v0.4 变更说明

### CloudPlugin 闭源插件体系
- **云端对接能力彻底从 Agent 二进制剥离**：原 `cloudclient/` 包（HTTP 客户端、HMAC 签名、重试）迁移至闭源 `libcloudplugin/`，Agent 二进制体积从 ~6MB 降至 ~4MB
- **Agent/Plugin 物理解耦**：Agent 主进程完全不依赖 net/http、crypto/hmac、encoding/json 等网络库，无 Plugin 时零开销降级
- **CloudPlugin 接口契约**：13 个 Plugin 方法（Init/Shutdown/Auth/Heartbeat/Diff/Fetch*/*Report/Command*）由闭源实现，Agent 开源代码只调接口
- **双层 Diff 同步**：Global Base + Incremental + Tenant Diff 双层设计，need_base / full_sync 场景自动降级拉快照

### CloudPlugin 打包方式
- **Linux 原生编译**：`CGO_ENABLED=1 go build -buildmode=plugin -o libcloudplugin.so ./libcloudplugin/`
- **Windows + WSL2**：`wsl -d Ubuntu -- bash -c "CGO_ENABLED=1 go build -buildmode=plugin ..."`
- **产物大小**：Agent ~4MB，Plugin ~16MB（Go plugin 格式固有开销）
- **降级保障**：无 Plugin / Plugin 加载失败 / cloud.enabled=false 均自动退化为 NoopPlugin，Agent 本地防护不受影响

### CloudSection 配置
- 新增 `cloud:` 顶级 YAML 配置块（enabled/base_url/tenant_id/agent_secret/plugin_path/sync_interval/heartbeat_interval/command_interval/feature_interval）
- CloudSync 四循环架构：Heartbeat / Diff / Command / Feature，完全由 Plugin 实现网络层

### v0.3 变更说明（历史）
（略，见 AGENT_MANUAL.md v0.3 版本）

### 新特性
- **三段式特征列表架构**：`known_http_clients`、`sensitive_paths`、`dangerous_patterns` 支持 Builtin（内置）+ Local（YAML）+ Cloud（云端）合并，支持 `excludes` 排除业务确实存在的条目，支持 `disable_builtin`/`disable_cloud` 开关
- **危险攻击模式解码检测**：新增 `decode.go` 模块，对路径进行 URL(%xx)、Unicode(\uXXXX)、Hex(\xHH)、HTML entity(&#60;) 多重解码后匹配 SQL 注入/XSS/路径遍历/命令注入/SSRF/SSTI 等 8 类 50+ 攻击模式
- **白名单支持 CIDR 和 IPv6**：`wardennet_whitelist` ipset 类型由 `hash:ip` 改为 `hash:net`，支持网段 CIDR 与 IPv6 地址
- **夜间模式倍率调整**：新增 `night_mode` 配置，夜间（可配置时段）对各维度权重施加倍率，基于 HTTP 类日志时间戳（含时区偏移）判断；linux_auth/custom 等无时区日志自动跳过倍率

### 防误杀机制增强
- **空 Referer 硬上限（始终生效）**：空 Referer 贡献**永远**不超过 `score_high/4`（25 分），无论是否有佐证信号
- **QPS 不作为佐证信号**：合法 API 客户端 QPS 突发是常态，不作为解锁空 Referer 防御的佐证信号
- **危险方法独立权重**：`dangerous_method` 新增独立权重（默认 3），不再复用 `status_4xx` 权重
- **危险模式阈值控制**：新增 `max_dangerous_pattern` 阈值（默认 0=不启用），支持渐进式计分
- **危险方法/模式贡献上限**：危险方法每请求上限 3× 权重；危险模式贡献上限 score_high/2
- **401 单独降权 + 硬上限**：纯 401（Token/Session 过期）风暴权重降为 1/5，同时新增 `score_high/4` 硬上限
- **路径段精确匹配**：`env` 不再错误匹配 `env.js`，`admin` 不匹配 `admin.js`

### 夜间模式（可选增强）
夜间（默认 0:00-5:00）扫描器活跃度显著升高，可通过 `night_mode` 配置对各维度权重施加倍率。

**关键设计**：**只加不减**——白天权重完全不变，夜间权重仅向上调整。

**时间判断**：
- 使用 HTTP 类日志（nginx/apache/tomcat）自带的时间戳（含时区偏移量如 `+0800`），**不依赖服务器系统时区配置**
- 即使服务器时区设置错误，只要 Nginx 日志中的偏移量正确就不受影响
- linux_auth/custom 日志无可靠时区信息时，时间戳回退为 0，自动跳过夜间倍率
- 支持跨午夜窗口（如 23:00-06:00）

**典型配置示例**：
```yaml
detector:
  night_mode:
    enabled: true
    start_hour: 0           # 夜间开始
    end_hour: 5             # 夜间结束
    timezone_offset: 8      # 东八区
    # 夜间各维度倍率（1.0 = 不变，> 1 = 增强检测灵敏度）
    qps_score: 1.5
    status_4xx: 1.5
    status_404_ratio: 2.0
    dangerous_pattern: 2.0
    bot_ua: 1.5
    empty_referer: 1.3
    real_user_bonus: 0.8    # < 1 减少夜间真实用户扣分
```

**日志输出**：夜间触发的记分在日志中自动标注 `(night:4xx=1.5 404=2.0 ...)`，便于运维识别。

### 兼容性
- **YAML 向后兼容**：特征列表同时支持简单列表（`["okhttp"]`）与结构化（`local/excludes/disable_builtin/disable_cloud`）两种格式
- **旧白名单自动迁移**：启动时检测到 `wardennet_whitelist` 类型不匹配时会自动销毁重建为 `hash:net`，保留原有条目
- **配置合并修复**：修复旧版 `mergeWithDefaults` 丢弃 `ipset` 和 `detector` 段的问题，现所有 YAML 段与默认值正确合并

### 升级提示
1. 编译新二进制并替换 `/opt/wardennet/wardennet`
2. 建议同步更新 `/etc/wardennet/config.yaml` 为最新版（参考 `configs/wardennet.production.yaml`）
3. 重启后检查 `ipset list wardennet_whitelist`，确认类型为 `hash:net`
4. 如需使用云端威胁情报，在 `dangerous_patterns` 下设置 `disable_cloud: false`（默认已开启）

---

## 附录 B：v1.3 变更说明

### 蜜罐路径（HoneypotPaths）

- **背景**：扫描器一定会扫 `/admin`、`/.env`、`/phpmyadmin`、`/.git/config` 等路径——这是行为模式，不是靠规则匹配。敏感路径 `sensitive_paths` 只能做基线偏离评分（相对特征），而蜜罐命中是绝对判定（零误报）。本次新增让用户可以配置"触之必死"的蜜罐路径列表
- **零依赖**：不需要 Nginx 配合，access log 里记录了请求路径即可。扫描器扫什么，detector 就看到什么
- **短路链路**：`Process()` 中 `normalizeRequestPath` 之后、`ShouldSkipPath` 之前插入蜜罐检测——命中直接给 `ScoreHigh×2` 分（ceiling）+ 绕过多事件确认 + 绕过 Consistency 降权 gate + 绕过 Scorer/Record 整个评分链路。单次命中即封
- **report-only 尊重**：report-only 模式下只上报告警云端，不封禁
- **安全性**：所有配置项走 `sanitizeSkipPaths` 防御性校验——拒绝含 `..` 的恶意配置、拒绝非 `/` 开头的路径。启动时 `len==0` 不启用，`IsHoneypotPath()` 首行返回 false，未部署时零开销
- **匹配模式**：与 `skip_paths` 完全一致（大小写不敏感）——精确匹配 `/admin` 或前缀匹配 `/traps/`
- **优先级**：蜜罐 > SkipPaths（先检测蜜罐，命中直接返回，不走 SkipPaths）
- **YAML 配置**：
```yaml
detector:
  honeypot_paths:
    - /admin
    - /phpmyadmin
    - /.env
    - /.git/config
    - /wp-admin
    - /traps/          # 前缀匹配
```
- **配置位置**：`detector.honeypot_paths`（默认空列表）
- **热重载**：支持（下次请求处理时生效）
- **日志标记**：命中蜜罐时 `ScoreDetail.HoneypotHit=true`，debug 日志输出 `(honeypot)` 标记便于区分"正常评分封禁"vs"蜜罐绝对封禁"
- **与敏感路径的区别**：

| 特性 | sensitive_paths | honeypot_paths |
|------|-----------------|----------------|
| 判定类型 | 基线偏离评分（相对特征） | 绝对判定（零误报） |
| 状态码关联 | 仅 status >= 400 计数 | 无论状态码 |
| 触发强度 | 贡献 ScoreHigh/2 以内分 | 直接 ceiling 分 + 跳过确认 |
| 降权 gate | 受 Consistency BENIGN 降权 | 绕过所有降权 |
| 绕过确认 | 否（需多事件确认） | 是（单次即封） |
| 默认值 | 有内置默认（敏感路径关键词） | 空（必须用户显式配置） |
