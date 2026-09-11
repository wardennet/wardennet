# WardenNet Agent 运维手册

> 版本：v2.0（基线自学习重大升级）
> 目标读者：服务器运维 / SRE / DevOps
> 适用平台：Linux（Ubuntu 20.04+ / Debian 11+ / CentOS 7+ / RHEL 7+）
> 配套文档：`AGENT_MANUAL.md`（编译构建）、`CODE_WIKI.md`（代码架构）

---

## 目录

1. [快速上手](#1-快速上手)
2. [架构速览](#2-架构速览)
3. [关键路径与端口](#3-关键路径与端口)
4. [日常运维操作](#4-日常运维操作)
5. [CLI 命令速查](#5-cli-命令速查)
6. [配置管理](#6-配置管理)
7. [监控与健康检查](#7-监控与健康检查)
8. [故障排查手册](#8-故障排查手册)
9. [紧急操作手册](#9-紧急操作手册)
10. [快照与数据恢复](#10-快照与数据恢复)
11. [升级与回滚](#11-升级与回滚)
12. [卸载与清理](#12-卸载与清理)
13. [CloudPlugin 闭源插件运维](#13-cloudplugin-闭源插件运维)
14. [附录](#14-附录)

---

## 1. 快速上手

### 1.1 三步部署

```bash
# ① 上传文件到目标服务器
scp wardennet_linux wardennet-agent.service wardennet.production.yaml deploy.sh root@your-server:/tmp/

# ② 执行一键部署
ssh root@your-server 'bash /tmp/deploy.sh'

# ③ 验证
wardennet status
# 期望输出显示 Agent 运行状态、版本号、blocked_count 等
# 备选：echo '{"command":"status","args":{}}' | socat - UNIX-CONNECT:/var/run/wardennet.sock
```

### 1.2 部署自检清单（5 分钟）

| # | 检查项 | 命令 | 期望结果 |
|---|--------|------|----------|
| 1 | 服务状态 | `systemctl status wardennet-agent` | `active (running)` |
| 2 | 启动日志 | `journalctl -u wardennet-agent -n 20` | 无 error，最后一行含 `agent fully initialized` |
| 3 | UnixSocket | `ls -la /var/run/wardennet.sock` | `srwx------` 权限 |
| 4 | CLI 连通 | `wardennet status` | 输出 Agent 状态信息，退出码 0 表示正常 |
| 5 | iptables 规则 | `iptables -S INPUT \| grep wardennet` | 存在 DROP 规则 |
| 6 | 黑名单 ipset | `ipset list wardennet_blacklist` | 类型 `hash:ip` |
| 7 | 白名单 ipset | `ipset list wardennet_whitelist` | 类型 `hash:net`（支持 CIDR/IPv6） |
| 8 | 白名单条目 | `ipset test wardennet_whitelist 127.0.0.1` | `127.0.0.1 is in set wardennet_whitelist.` |
| 9 | 日志采集 | `grep "log tail started" /var/log/wardennet/agent.log` | 显示已启动的日志源列表 |

### 1.3 最小化手动部署（无 deploy.sh）

```bash
mkdir -p /opt/wardennet /etc/wardennet /var/lib/wardennet /var/log/wardennet

cp wardennet_linux /opt/wardennet/wardennet && chmod +x /opt/wardennet/wardennet
cp wardennet.production.yaml /etc/wardennet/config.yaml
cp wardennet-agent.service /etc/systemd/system/wardennet-agent.service

systemctl daemon-reload
systemctl enable --now wardennet-agent
```

---

## 2. 架构速览

### 2.1 一句话定位

Agent 是**本地运行的滑动窗口恶意扫描防护引擎**，在服务器上实时分析访问日志，自动将高危 IP 加入内核 ipset → iptables DROP 链，实现内核级零延迟拦截。

### 2.2 三层防护关系

```
┌──────────────────────────────────────────────────────────┐
│  用户态（进程）                                            │
│  ┌────────────────────────────────────────────────────┐ │
│  │  wardennet  (root, systemd 托管)                    │ │
│  │                                                      │ │
│  │  logparser ─▶ detector ─▶ ipsetutil ─▶ ttl          │ │
│  │     │              │          │                      │ │
│  │     ▼              ▼          ▼                      │ │
│  │  tail 日志   基线自学习评分  快照持久化               │ │
│  └────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘
                          │
                          ▼
┌──────────────────────────────────────────────────────────┐
│  内核态                                                  │
│  ┌────────────────────────────────────────────────────┐ │
│  │  ipset: wardennet_blacklist (hash:ip)              │ │
│  │  ipset: wardennet_whitelist (hash:net)             │ │
│  │  iptables INPUT: -m set --match-set ... -j DROP    │ │
│  └────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘
```

### 2.3 黑白名单优先级

```
本地配置白名单 (ipset.whitelist)  ← 最高，绝对豁免
          │
          ▼
云端下发白名单（Phase 2）
          │
          ▼
本地黑名单 / 云端黑名单 → ipset → iptables DROP
```

### 2.4 检测引擎评分逻辑（运维视角）

v2.0 起采用**基线自学习评分引擎**，不再依赖手工配置阈值。

- **输入**：Nginx / Apache / Tomcat / Linux Auth 日志 tail
- **窗口**：三档并行（10s / 30s / 60s），每个窗口独立维护 8 个相对特征的 P95 基线（QPS、4xx 比率、404 比率、认证失败比率、敏感路径命中率、Bot UA 比率、空 Referer 比率、5xx 比率）
- **评分公式**：`score = Σ(偏离 P95 的倍数 → 线性映射为分数) × sensitivity 系数 + 3 个绝对特征固定权重`
- **绝对特征**：危险攻击模式（weight=5）、危险 HTTP 方法（weight=3）、文件上传拦截（weight=20），保留固定权重不参与基线学习
- **输出**：`score ≥ score_high (默认 50)` → 自动加入黑名单 + TTL 计时
- **配置量**：从 v1.x 的 45 个参数降到 **7 个**（enabled / mode / sensitivity / score_high / score_medium / score_low / weights 3 项 / windows 3 档 size），运维日常只需要关心 `sensitivity` 一个参数

> 基线自学习会自动追踪时段流量变化、共享 NAT IP QPS、双11 流量暴涨等正常波动，详见 §6.5。

### 2.5 防误杀机制（运维需要知道的 13 条）

| # | 机制 | 效果 |
|---|------|------|
| 1 | **单维度封顶（v0.8 新增）** | 任意单维度异常最多贡献 `score_high × 60%`（默认 30 分）；只有 1 个相对维度异常时封顶 `score_medium`（默认 30 分）→ **单维度永远不封** |
| 2 | **绝对特征叠加（v0.8 新增）** | DangerousPattern/DangerousMethod/FileUpload 不受单维度封顶限制，可以叠加到 score_high → **有攻击特征才封禁** |
| 3 | **置信度打折（v0.8 新增）** | Preload confidence < 0.3 时 QPS 偏离分 × 0.5；confidence < 0.1 时永不封禁（score_high 强制降到 49）→ **基线不准时保守处理** |
| 4 | **纯尖峰打折（v0.8 新增）** | 只有 QPS 单维度异常 + 无任何攻击特征 → QPS 分 × 0.3 → **正常浏览不触发** |
| 5 | **Baseline MIN_BASELINE_QPS 硬保底（v0.8 新增）** | QPS P95 永远不低于 1.0 req/s → **凌晨低峰基线不会压到 0.2** |
| 6 | **Preload MAD 极端值剔除（v0.8 新增）** | 扫描器/爬虫/batch sync 产生的极端 QPS 桶被 MAD 方法从样本中删除 → **基线不被污染** |
| 7 | legitimateUserContext 降权 | 致命攻击特征为零 + 浏览器占比 ≥ 95% 时按比例容忍噪音 → 4xx/404 分打 1 折 |
| 8 | 基线自学习自动适应 | 时段流量变化、共享 NAT IP QPS、双11 流量暴涨自动追踪基线 |
| 9 | 空 Referer 硬上限 | 空 Referer 单独贡献不超过 `score_high/4`（默认 12），不会单独触发拉黑 |
| 10 | 401 降权 | 401 自动降权为 1/5 + 硬上限 `score_high/4`，合法 Token 过期重试不会误杀 |
| 11 | 已知 HTTP 客户端豁免 | okhttp / python-requests / axios / curl 等 14 种 UA 不判定为 Bot |
| 12 | 本地白名单绝对优先 | 命中白名单 → 直接跳过所有检测，包括强制拉黑（除非 `force:true`） |
| 13 | **Consistency 行为降权 gate（v1.2 新增）** | Scorer 给了 score_high，但 IP 的行为序列形状明显是正常用户（路径连贯、状态稳定）→ 强制降权到 score_medium，让多事件确认机制处理 |

---

## 3. 关键路径与端口

### 3.1 文件路径速查表

| 类别 | 路径 | 说明 |
|------|------|------|
| 二进制 | `/opt/wardennet/wardennet` | 可执行文件 |
| 配置 | `/etc/wardennet/config.yaml` | 主配置（deploy 时从 `wardennet.production.yaml` 复制） |
| Service | `/etc/systemd/system/wardennet-agent.service` | systemd 单元 |
| 日志 | `/var/log/wardennet/agent.log` | Agent 运行日志（可在 YAML 中改路径，空则仅 stdout） |
| 快照 | `/etc/wardennet/state.json` | 黑名单 + TTL 状态快照，重启后恢复（位于 config.yaml 同目录） |
| Tail 状态 | `/etc/wardennet/tail_<name>_state.json` | 每个日志源的读取位置，重启后续读不丢事件 |
| UnixSocket | `/var/run/wardennet.sock` | CLI 通信入口，0600 权限 |

### 3.2 内核资源

| 资源 | 名称 | 类型 |
|------|------|------|
| 黑名单 ipset | `wardennet_blacklist` | `hash:ip` |
| 白名单 ipset | `wardennet_whitelist` | `hash:net`（支持 CIDR / IPv6） |
| iptables 链 | `INPUT` 表 | `-p tcp -m set --match-set wardennet_blacklist src -j DROP` |

### 3.3 资源权限

- Agent 必须以 **root** 运行（操作 ipset/iptables 需要）
- systemd service 已配置 `User=root Group=root`
- 日志目录 `/var/log/wardennet` 需 root 写权限（轮转自动创建）
- Tail 状态文件、快照文件自动创建于 `config.yaml` 所在目录的父级

---

## 4. 日常运维操作

### 4.1 systemd 服务管理

```bash
# 启动 / 停止 / 重启
systemctl start  wardennet-agent
systemctl stop   wardennet-agent
systemctl restart wardennet-agent      # 重启时自动保存快照 → 恢复 TTL

# 状态查看
systemctl status wardennet-agent        # 静态状态 + 最近 10 行日志
systemctl is-active wardennet-agent     # 只返回 active / inactive
systemctl is-enabled wardennet-agent    # 检查开机自启

# 开机自启
systemctl enable  wardennet-agent
systemctl disable wardennet-agent

# 查看最近错误（红色标记）
systemctl --failed | grep wardennet
```

### 4.2 journalctl 日志查询

```bash
# 实时跟踪
journalctl -u wardennet-agent -f

# 今天以来
journalctl -u wardennet-agent --since "today"

# 最近 30 分钟
journalctl -u wardennet-agent --since "30 minutes ago"

# 最近 50 行 + 翻页
journalctl -u wardennet-agent -n 50

# 错误级别过滤
journalctl -u wardennet-agent -p err..alert

# 只看启动相关
journalctl -u wardennet-agent | grep -E "starting|initialized|fully"
```

### 4.3 热重载配置

Agent 每 5 秒自动轮询配置文件变化并热重载。**修改后无需重启**。

```bash
vim /etc/wardennet/config.yaml
# 保存退出即可，5 秒内生效

# 确认重载成功
grep "config watcher" /var/log/wardennet/agent.log
```

> ⚠️ **注意**：`detector.sensitivity`、`detector.mode`、`detector.score_high`、`detector.score_medium`、`detector.score_low`、`detector.weights.*`、`detector.windows[*].size`、`ipset.whitelist` 等关键配置变更均会热重载生效（窗口 size 在新窗口创建时生效，其余在下次评分时生效）；新增 / 删除 `log_sources` 中的日志源需要 **重启 Agent**。

### 4.4 手动管理 IP 黑名单

**推荐方式**：通过 CLI（Agent 感知操作，写入 TTL，自动记录日志）

```bash
# 永久拉黑（使用默认 TTL，默认 1 小时）
wardennet blocklist add 203.0.113.100

# 指定 TTL 拉黑（3600 秒 = 1 小时）
# 注意：CLI 默认使用配置中的 local_block_ttl，如需指定 TTL 请直接走 JSON 协议
#   echo '{"command":"blocklist.add","args":{"ip":"203.0.113.100","ttl":3600}}' | socat - UNIX-CONNECT:/var/run/wardennet.sock
wardennet blocklist add 203.0.113.100

# 强制拉黑白名单中的 IP（默认白名单 IP 不会被拉黑）
wardennet blocklist add 127.0.0.1 -f

# 解除拉黑
wardennet blocklist del 203.0.113.100

# 查看当前黑白名单统计
wardennet blocklist status
```

**直接操作 ipset（不推荐，绕过 Agent 逻辑）**

```bash
ipset add    wardennet_blacklist 203.0.113.100    # 添加
ipset del    wardennet_blacklist 203.0.113.100    # 删除
ipset test   wardennet_blacklist 203.0.113.100    # 查询是否在集合中
ipset flush  wardennet_blacklist                   # 清空（危险）
ipset list   wardennet_blacklist                   # 列出所有条目
```

> ⚠️ 直接操作 ipset **不会写入 TTL 管理器**，Agent 重启后 TTL 计时器不恢复。日常管理请优先使用 CLI。

### 4.4.1 TTL 自动解封（运维验证）

Agent 所有封锁都有自动解封机制，**双通道冗余**（详见 AGENT_MANUAL §9.4）：

| 来源 | 触发方 | TTL 值 | 通道 1（内核） | 通道 2（用户态） |
|------|--------|--------|---------------|----------------|
| 本地 | detector / CLI | `local_block_ttl`（默认 3600s） | ipset `--timeout 3600` | TTL Sweep → onExpire → ipMgr.Unblock |
| 云端 | applyDecisions（含联防快速通道） | `cloud_block_ttl`（默认 7200s） | ipset `--timeout 7200` ← **v0.4.2 新增** | TTL Sweep → onExpire → ipMgr.Unblock |

> **v0.4.2 修复**：之前云端封锁只有 TTL Sweep 单通道（无 kernel timeout）。进程被 kill -9 时快照丢失 → 内核条目永存 → 云端封锁永久化。修复后与本地一致，进程崩溃也能自动解封。

**运维验证命令**：
```bash
# 1. 查看 ipset 条目是否带 timeout（关键！修复后所有条目都应该有）
ipset list wardennet_blacklist -o plain
# 期望输出每个条目类似：1.2.3.4 timeout 3500
#   如果没有 timeout 字段 → 版本低于 v0.4.2 或 applyDecisions 没正确设置 Timeout

# 2. 查看 TTL Sweep 是否在运行
wardennet blocklist status | jq '.ttl_entries'
# 期望：与 blocked_count 近似相等（每次 Block 都会 Add TTL）

# 3. 查看自动解封日志
journalctl -u wardennet-agent -f | grep -E "auto-unblock|ttl expired"
# 期望：每 30s Sweep 一次，过期时打印 "auto-unblock expired" 含 ttl_source=cloud|local

# 4. 手动触发解封测试
wardennet blocklist add 203.0.113.200
sleep 1
wardennet blocklist del 203.0.113.200
ipset test wardennet_blacklist 203.0.113.200
# 期望：203.0.113.200 is NOT in set（CLI del 必须同时删内存+内核）
```

### 4.5 手动管理白名单

白名单通过 YAML 配置管理，**不是 CLI 动态增删**。

```bash
# 编辑配置
vim /etc/wardennet/config.yaml

# 在 ipset.whitelist 下添加
ipset:
  whitelist:
    - 127.0.0.1
    - ::1
    - 192.168.1.0/24       # CIDR 网段
    - 203.0.113.50         # 单个 IP

# 等待 5 秒自动重载，或手动触发（如果 reload CLI 可用）
grep "local whitelist loaded" /var/log/wardennet/agent.log
```

> ⚠️ 白名单 ipset 类型为 `hash:net`，**同时支持精确 IP、CIDR 网段、IPv6 地址**。旧版本如果是 `hash:ip`，Agent 启动时会自动销毁重建。

### 4.6 iptables 规则管理

```bash
# 查看 Agent 注册的规则
iptables -S INPUT | grep wardennet

# 规则详情 + 包计数
iptables -L INPUT -n -v --line-numbers | grep -A 1 wardennet

# 手动添加（一般不需要，Agent 启动时自动执行）
iptables -I INPUT -p tcp -m set --match-set wardennet_blacklist src \
    -j DROP

# 手动删除（如果 Agent 停止后需要清理）
iptables -D INPUT -p tcp -m set --match-set wardennet_blacklist src \
    -j DROP
```

### 4.7 配置备份

```bash
# 备份
cp /etc/wardennet/config.yaml /etc/wardennet/config.yaml.bak.$(date +%Y%m%d-%H%M)

# 一键备份所有运维关键文件
mkdir -p /root/wardennet-backup/$(date +%Y%m%d)
cp /etc/wardennet/config.yaml /root/wardennet-backup/$(date +%Y%m%d)/
cp /etc/wardennet/state.json  /root/wardennet-backup/$(date +%Y%m%d)/ 2>/dev/null
```

---

## 5. CLI 命令速查

Agent 通过 **Unix Socket** 接收 JSON 请求，无任何 TCP 端口监听。

### 5.1 连接方式

```bash
# 方式一：wardennet 内置 CLI（推荐，零依赖）
wardennet status
wardennet blocklist add 1.2.3.4
wardennet blocklist del 1.2.3.4
wardennet blocklist status

# 方式二：socat（备选，需安装 socat 包）
echo '{"command":"status","args":{}}' | socat - UNIX-CONNECT:/var/run/wardennet.sock

# 方式三：Python（无需额外依赖）
python3 -c "
import socket, json
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('/var/run/wardennet.sock')
s.sendall(json.dumps({'command':'status','args':{}}).encode() + b'\n')
print(s.recv(65536).decode())
s.close()
"

# 方式四：bash /dev/tcp（部分系统不支持）
exec 3<>/var/run/wardennet.sock
echo '{"command":"status","args":{}}' >&3
cat <&3
exec 3<&-
```

### 5.2 命令列表

| 命令 | 说明 | 参数 |
|------|------|------|
| `status` | Agent 整体运行状态 | 无 |
| `blocklist.add` | 添加黑名单 | `ip`（必填）, `ttl`（可选，秒）, `force`（可选，bool） |
| `blocklist.del` | 移除黑名单 | `ip`（必填） |
| `blocklist.status` | 黑白名单统计 + TTL | 无 |

### 5.3 命令响应格式

成功：
```json
{"ok":true,"data":{"version":"dev","blocked_count":0}}
```

失败：
```json
{"ok":false,"error":"SKIP: ip in local whitelist"}
```

### 5.4 各命令响应示例

**status**
```bash
# 请求
wardennet status
# （备选：echo '{"command":"status","args":{}}' | socat - UNIX-CONNECT:/var/run/wardennet.sock）

# 响应（JSON 协议原始响应）
{
  "ok": true,
  "data": {
    "version": "dev",
    "timestamp": 1756383600,
    "blocked_count": 1,
    "whitelist_count": 3,
    "ttl_entries": 1,
    "registered_commands": ["blocklist.add","blocklist.del","blocklist.status","status"]
  }
}
```

**blocklist.add**
```bash
# 普通拉黑（IP 在白名单中会被跳过）
wardennet blocklist add 203.0.113.100
# JSON 响应：{"ok":true,"data":{"ip":"203.0.113.100","accepted":true,"ttl":3600,"expires_at":1756387200}}

# 白名单 IP 的强制拉黑
wardennet blocklist add 127.0.0.1 -f
# JSON 响应：{"ok":true,"data":{"ip":"127.0.0.1","accepted":true,...}}

# IP 已在黑名单（幂等跳过）
wardennet blocklist add 203.0.113.100
# JSON 响应：{"ok":true,"message":"already blocked","data":{"ip":"203.0.113.100","accepted":false}}

# 白名单 IP 的普通拉黑（被跳过）
wardennet blocklist add 127.0.0.1
# JSON 响应：{"ok":false,"error":"SKIP: ip in local whitelist","data":{"ip":"127.0.0.1","accepted":false,"reason":"local_whitelist_skip"}}
```

**blocklist.del**
```bash
wardennet blocklist del 203.0.113.100
# JSON 响应：{"ok":true,"data":{"ip":"203.0.113.100"}}
```

**blocklist.status**
```bash
wardennet blocklist status
# JSON 响应：
# {
#   "ok": true,
#   "data": {
#     "timestamp": 1756383600,
#     "blocked_count": 15,
#     "whitelist_count": 3,
#     "ttl_entries": 15,
#     "version": "dev"
#   }
# }
```

### 5.5 常见错误

| 错误信息 | 原因 | 解决方案 |
|----------|------|----------|
| `missing or invalid 'ip' arg` | 未提供 ip 或格式不合法 | 检查 ip 字段是否为有效 IP |
| `SKIP: ip in local whitelist` | IP 在白名单中，默认不拉黑 | 加 `"force":true` 或从白名单移除 |
| `invalid ip: 1.2.3` | IP 格式错误 | 使用 `ip a` 确认正确 IP |
| `connection refused` | Unix Socket 不存在 | Agent 可能未运行，检查 `systemctl status` |
| `command not found: reload` | 当前版本未注册 reload 命令 | 配置已自动 5 秒热重载，无需手动调用 |
| `ipset command failed: set ... doesn't exist` | ipset 集合被误删 | 重启 Agent 自动重建 |

---

## 6. 配置管理

### 6.1 配置文件概览

配置文件路径：`/etc/wardennet/config.yaml`

Agent 所有运行参数通过此文件驱动，**禁止硬编码**。未声明的字段使用代码内置默认值。

### 6.2 完整 YAML 参考（精简版，仅含运维关注字段）

```yaml
agent:
  local_block_ttl: 3600      # 本地拉黑默认 TTL（秒）；3600=1h, 7200=2h, 259200=72h
  cloud_block_ttl: 7200      # 云端下发拉黑 TTL 上限
  cloud_max_ttl:   86400     # 云端下发最大 TTL 上限

log:
  level: info                 # debug / info / warn / error（生产建议 info）
  file: /var/log/wardennet/agent.log   # 空则仅 stdout
  max_size: 100               # 单文件 MB
  max_backups: 7              # 保留文件数
  max_age: 30                 # 保留天数
  compress: true

stats:
  report_interval: 60         # 统计报告间隔（秒）；0=禁用

log_sources:
  nginx_access:
    path: /var/log/nginx/access.log
    parser: nginx_access
  # 可追加：apache_access / tomcat_access / linux_auth / 自定义

detector:
  enabled: true
  mode: block              # block=正常封禁 / report=观察者模式（详见 §6.4）
  sensitivity: medium       # high(2x) / medium(5x) / low(10x)（详见 §6.3）
  score_high: 50           # 触发拉黑
  score_medium: 30          # 告警
  score_low: 10             # 记录
  weights:                  # 仅绝对特征（3 个，不参与基线学习）
    dangerous_pattern: 5
    dangerous_method: 3
    file_upload: 20
  windows:                  # 仅窗口大小（3 档，各维护独立 P95 基线）
    - size: 10
    - size: 30
    - size: 60
  skip_paths:                 # 完全跳过检测的路径
    - /favicon.ico
    - /favicon.png
    - /robots.txt
    - /.well-known/
  # 蜜罐路径（v1.3 新增，可选，默认不启用）——命中即绝对封禁
  # honeypot_paths:
  #   - /admin
  #   - /phpmyadmin
  #   - /.env
  #   - /.git/config
  #   - /traps/                # 前缀匹配：该目录下所有路径都是蜜罐
  known_http_clients:         # 三段式特征列表（见 §6.7）
    local: []
    excludes: []
  sensitive_paths:
    local: []
    excludes: []
  dangerous_patterns:
    local: []
    excludes: []
  # --- Consistency 5 维行为连贯性评分（v1.2，可选覆盖，全部有程序默认）---
  consistency:
    # 工程参数
    ring_capacity: 512          # 每 IP 最多保留历史请求数
    min_samples: 20             # 样本不足不评分
    score_threshold: 4          # >= 此分判 BENIGN
    # 5 维正向信号阈值（通常不需要改）
    prefix_run_len_min: 3       # 前缀连贯：平均连续段长度 ≥
    prefix_dominant_min: 0.50   #    或 dominant 占比 ≥
    novelty_early30_min: 0.70   # 新颖度饱和：前 30% 覆盖 ≥
    late_novelty_rate_max: 0.40 #    且后 30% 新增 ≤
    path_concentrated_threshold: 0.25  # Top5 路径覆盖 ≥
    status_cv_max: 0.6          # 状态同质性变异系数 <
    get_ratio_min: 0.50         # GET 占比范围
    get_ratio_max: 0.99
    post_ratio_min: 0.01
    post_ratio_max: 0.49
    unusual_max: 0.05           # PUT/DELETE/PATCH ≤
    pure_api_get_max: 0.80      # 纯 API GET 客户端豁免
    pure_api_post_min: 0.50     # 纯 API POST 客户端豁免
    # 反信号阈值
    always_error_dynamic_min: 5 # 动态路径反复撞墙 ≥ 次
    always_error_probe_min: 10  # favicon 等公共探测 ≥ 次
    single_path_error_bonus: 3  # 单路径+全错额外扣分
    always_error_score_penalty: 5
    highly_novel_early_max: 0.50 # 发散扫描反信号
    highly_novel_late_min: 0.70
    highly_novel_cover_max: 0.40
    highly_novel_penalty: 3
    # 5 维权重
    weight_prefix: 2
    weight_novelty: 2
    weight_path_conc: 2
    weight_errors: 1
    weight_method: 1

ipset:
  whitelist:                  # 本地白名单（绝对豁免）
    - 127.0.0.1
    - ::1
  blacklist: []               # 预加载黑名单（断网兜底）

unix_socket:
  path: /var/run/wardennet.sock

cloud:
  enabled: false                  # 是否启用云端协同（默认关闭）
  base_url: https://cloud.wardennet.io
  tenant_id: ""                   # 租户 ID，由控制台颁发
  agent_secret: ""                # Agent 鉴权密钥，建议使用环境变量注入
  plugin_path: /usr/lib/wardennet/libcloudplugin.so
```

### 6.3 敏感度档位说明

基线自学习引擎通过 `sensitivity` 档位控制"偏离 P95 多少倍开始触发评分"。这是运维日常最常调整的参数。

| 档位 | 含义 | 偏离倍数 | 适用场景 |
|------|------|---------|---------|
| `high` | 严格检查 | 偏离 P95 2x 即触发 | 金融网站、安全要求极高 |
| `medium` | 平衡（默认） | 偏离 P95 5x 触发 | 大多数网站 |
| `low` | 低误报 | 偏离 P95 10x 触发 | 高流量电商、CDN 后端 |

调整方式：改 YAML 中 `detector.sensitivity` 值，5 秒热重载生效。

### 6.4 观察者模式（Report-Only）

上线初期可以将 `detector.mode` 设为 `report`，Agent 正常评分但不实际封禁：

- 评分、日志、云端上报全部正常
- 不调用 ipset add、不触发 iptables DROP
- 运维可以先跑几天观察基线学习情况，确认无误后改成 `block`
- 切换方式：改 YAML 中 `detector.mode`，5 秒热重载生效

### 6.5 基线自学习机制

Agent 启动时执行 **Preload 全量扫描**（v0.8 升级，v0.10 加反代检测 + 时间窗口过滤）：

```
Preload 流程（v0.10）：
  1. 全量读取 access.log（最多 50 万行，约 1-2 天的中等流量）
  2. 遍历同时完成两件事：
     a. 按 5min 时间桶分组 → 算中位数 → 过滤 >= 50% 中位数的桶（自动排除凌晨极低峰）
     b. 统计 IP 多样性：维护每个公网 IP 的请求计数（跳过 loopback/private IP）
  3. 时间窗口过滤（v0.10 新增，minutes 参数现在真正生效）：
     只保留 maxTS 往前 minutes 分钟内的桶来建基线（默认 10 分钟）
     → 保证基线用的是**最新**数据，而不是文件头部最旧数据
  4. 健康桶的 QPS 值通过 MAD 方法剔除扫描器/爬虫/batch sync 极端桶
     MAD = median(|x - median|)；阈值 = median + 5×MAD
  5. 用干净数据算 P50/P95/P99 → 应用 MIN_BASELINE_QPS 硬保底（永远 ≥ 1.0 req/s）
  6. 设置三档 Baseline + confidence（= 健康桶数 / 总桶数）
  7. IP 多样性指标计算 + 反代不透传检测（v0.10 新增）：
     三个条件满足任一 → 终止 Agent：
       条件 A: UniqueIPs <= 3
       条件 B: UniqueIPs <= 10 且 Top1Ratio >= 90%
       条件 C: UniqueIPs <= 10 且 Top3Ratio >= 98%
     loopback/private IP 已从计数中排除（内部健康检查不干扰）
  8. 输出 PreloadStats → 运维一眼看到基线质量 + IP 多样性
```

运行期间每 10 秒更新一次三档基线：

- 预热期（前 30 分钟）用快速衰减 `new = old × 0.5 + current × 0.5` 快速追平真实流量
- 稳定期用标准衰减 `new = old × 0.8 + current × 0.2` 平滑追踪
- 偏离 P99 > 10x 的极端值不纳入统计（攻击者无法抬高基线）

Preload 日志示例（v0.10 新输出）：

正常多 IP 场景：
```
preload completed source=nginx_access scanned_lines=500000
  time_range="2026-09-08 10:20~2026-09-08 10:30" duration_min=10     ← minutes=10 只取最近 10 分钟
  buckets="2 total, 2 healthy (>= 200 req/5min, median=450)"
  qps_dist="P50=1.50 P95=8.20 P99=12.00"
  qps_outliers_removed=0
  confidence=1.00
  baseline_qps_p95="win10s=8.20 win30s=8.20 win60s=8.20"
  unique_ips=240                           ← v0.10 新增：240 个不同的公网 IP
  top1="203.0.113.42 (356, 3.6%)"          ← v0.10 新增：Top1 IP 占比 3.6%（健康）
  top3_ratio="9.8%"                        ← v0.10 新增：Top3 合计 9.8%（健康）
  elapsed=2.312s
```

反代不透传检测命中（v0.10 会直接终止 Agent）：
```
preload completed source=nginx_access ... unique_ips=3 top1="10.0.0.1 (49820, 99.6%)" top3_ratio="100.0%"
ABORTING: reverse proxy without real IP passthrough detected
  source=nginx_access unique_ips=3
  top1_ip=10.0.0.1 top1_count=49820 top1_ratio=99.6% top3_ratio=100.0%
  reason="all requests from too few distinct IPs — real client IPs are hidden behind a proxy"
  hint="nginx fix: add to http {} block or inside server {}:"
  hint_cmd="  set_real_ip_from 10.0.0.0/8;        # upstream proxy subnet"
  hint_cmd2="  real_ip_header X-Forwarded-For;   # header containing real IPs"
  hint_cmd3="  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;"
[进程退出 exit code 1]
```

基线自动适应：
- 时段流量变化（白天/夜间自然不同，基线自动追踪）
- 双11 大促流量暴涨（预热期快速收敛）
- 高流量电商 vs 低流量博客（各自基线独立学习）
- 共享办公 NAT IP（Per-IP EMA 防止误判）

**基线硬件保护（防止误报 + 保证基线质量的多层防线）**：

| 保护层 | 常量 / 机制 | 默认值 | 含义 |
|--------|------|--------|------|
| **[v0.10 启动前] 反代不透传检测** | `proxySingleIPThreshold=3` `proxyTop1RatioThreshold=0.90` `proxyTop3RatioThreshold=0.98` | — | 所有请求来自 ≤ 3 个 IP 或 Top1 占比 ≥ 90%（UniqueIPs ≤ 10）→ **终止 Agent**，避免封反代 IP 而非真实攻击者 |
| **[v0.10 启动前] 时间窗口过滤** | `minutes` 参数 | 10 分钟 | Preload 只取 maxTS 往前 minutes 分钟的桶建基线 → 保证基线用**最新**数据，旧日志不污染 |
| QPS 地板 | `MIN_BASELINE_QPS` | 1.0 req/s | 凌晨低峰 Preload 后 QPS P95 不会低于此值 |
| 比率地板 | `MIN_BASELINE_RATE_P95` | 0.001 (0.1%) | BotUA / SensPath / 4xx 等 7 个比率型维度的 P95 不会低于此值 |
| deviation cap | `MAX_DEVIATION` | 1000 | 任何维度的偏离倍数 cap 到 1000，防止天文数字污染评分 |
| 运行时硬阈值预筛 | `PRESCAN_MAX_RATE_4xx=0.80` 等 | — | Update 时明显可疑的 IP 直接 skip，不参与基线学习 |
| MAD 极端值剔除 | `k=5` | — | Preload + 运行时双重管线，砍除扫描器/爬虫桶 |

> 凌晨 3-5 点启动 Agent 时，Preload 数据极安静，BotUA 等维度的 P95 可能算出 `1e-17` 这样的极小正数。
> 没有比率地板时，扫描器 BotUA rate = 1.0 会被判定为 `1e17` 倍偏离 → score cap 50 → 误杀。
> 比率地板把 P95 提到 0.001 后，同样场景偏离 = 1000x，仍然被 MAX_DEVIATION cap 到 1000，
> deviationToScore 封顶 100 分——但 legitimateUserContext（正常浏览器占 ≥ 95%）会触发降权，把正常用户从误报里救回来。

### 6.6 常见调参场景

**场景一：高流量电商 / API 服务器**

合法 QPS 高，基线自学习已自动追踪正常流量，如仍有误报：
```yaml
detector:
  sensitivity: low            # 降低敏感度
  score_high: 60              # 同时提高阈值（双重保险）
```

**场景二：CDN / 反向代理后端**

Agent v0.10 新增**启动前反代不透传检测**：如果日志里几乎全是同一个 CDN/反代节点 IP，Agent 会直接终止并要求你修复。

正确做法是**在反代层配置真实 IP 透传**，让 nginx access.log 记录客户端真实 IP 而不是反代节点 IP：
```nginx
# nginx server {} 或 http {} 块中加入：
set_real_ip_from 104.16.0.0/12;         # Cloudflare CDN 网段（示例）
set_real_ip_from 173.245.48.0/20;
set_real_ip_from 190.93.240.0/20;
set_real_ip_from 10.0.0.0/8;            # 内部反代网段
real_ip_header X-Forwarded-For;         # 或 CF-Connecting-IP（Cloudflare 专用）
```

**如果确实无法配置真实 IP 透传**（如某些云 WAF 的限制场景），可以把 CDN IP 段加到白名单兜底。
但注意：这种方式下 Agent 看到的永远是 CDN IP，攻击者也会用 CDN 出口 IP — 白名单只能"放过"合法 CDN 请求，不能识别来自同一 CDN 节点的真实攻击流量。

```yaml
ipset:
  whitelist:
    - 104.16.0.0/12           # Cloudflare CDN 段（示例，仅兜底）
    - 173.245.48.0/20
    - 190.93.240.0/20
```

**场景三：内部系统（运维脚本、curl 调用）**

```yaml
detector:
  known_http_clients:
    excludes: ["curl", "wget"]     # 排除确实合法的 UA
  sensitive_paths:
    excludes: ["actuator", "env"]  # 业务中确实使用的路径
```

### 6.7 三段式特征列表

`known_http_clients` / `sensitive_paths` / `dangerous_patterns` 三个列表支持**双格式 + 云端合并**：

**格式一：简单列表（向后兼容）**
```yaml
known_http_clients: ["okhttp", "python-requests"]
```

**格式二：结构化（推荐）**
```yaml
known_http_clients:
  local: ["custom-client"]       # 本地新增
  excludes: ["internal-probe"]   # 排除业务确实存在的条目
  disable_builtin: false          # 禁用内置默认值（慎用）
  disable_cloud: false            # 禁用云端拉取
```

**合并规则**：`Builtin（代码默认）` + `Local（YAML 追加）` + `Cloud（云端拉取）` → 去重 → 排除 `Excludes` → 最终生效列表

### 6.8 参数变更生效时机

| 参数 | 生效时机 | 是否需要重启 |
|------|----------|-------------|
| `detector.sensitivity`、`detector.mode` | 下次评分计算时 | 否（5 秒自动重载） |
| `detector.score_high` / `score_medium` / `score_low` | 下次评分计算时 | 否 |
| `detector.weights.*` | 下次评分计算时 | 否 |
| `detector.windows[*].size` | 新窗口创建时 | 否 |
| `known_http_clients` / `sensitive_paths` / `dangerous_patterns` | 下次匹配时 | 否 |
| `skip_paths` | 下次请求处理时 | 否 |
| `honeypot_paths`（v1.3） | 下次请求处理时 | 否 |
| `ipset.whitelist` / `ipset.blacklist` | 下次黑白名单同步时 | 否 |
| `log.level` | 下次日志输出时 | 否 |
| `stats.report_interval` | 下次统计循环时 | 否 |
| `log.file` | 下次日志写入时 | 否 |
| `log_sources` 新增 / 删除 | — | **是，需重启** |
| `unix_socket.path` | — | **是，需重启** |

---

## 7. 监控与健康检查

### 7.1 关键日志标记速查

| 关键字 | 级别 | 含义 |
|--------|------|------|
| `wardennet agent starting` | info | Agent 启动 |
| `preloading baseline from log` | info | Preload 开始全量扫描 |
| `preload completed` | info | **Preload 完成，含扫描行数/健康桶数/置信度** |
| `removed extreme QPS buckets via MAD` | warn | v0.8 新增：MAD 剔除扫描器/爬虫极端桶 |
| `agent fully initialized` | info | **全链路就绪，启动成功** |
| `local whitelist loaded` | info | 白名单加载完成 |
| `log tail started` | info | 每个日志源开始采集 |
| `tail heartbeat` | info | v0.8 新增：每 30s 打印 tail 状态（size/offset/gap/dropped） |
| `unix socket server started` | info | CLI 服务就绪 |
| `snapshot restored` | info | 从快照恢复 TTL 成功 |
| `auto blocked by detector` | info | **检测引擎自动拉黑** |
| `high score event detected` | warn | 高风险事件（debug 级别还会输出详情） |
| `auto block failed` | warn | 自动拉黑失败（检查 ipset） |
| `tail backpressure: dropped` | warn | tail channel 背压丢弃事件 |
| `config reload failed` | warn | 配置热重载失败 |
| `iptables ban rule ensured` | info | iptables 规则就绪 |
| `final snapshot saved` | info | 优雅关闭，快照已保存 |
| `agent stopped` | info | Agent 完全退出 |
| `detector score detail` | debug | 每次事件的三档窗口评分详情 |
| `stats report` | info | 定期输出增量统计（窗口=上次 Reset 到现在） |
| `final stats report` | info | Agent 优雅关闭时输出全周期统计 |

### 7.2 实用日志查询

```bash
# 查看最近 1 小时拉黑事件
grep "auto blocked" /var/log/wardennet/agent.log | tail -20

# 提取所有被拉黑的 IP（去重排序）
grep "auto blocked" /var/log/wardennet/agent.log | grep -oP 'ip=\S+' | sort -u

# 查看评分详情（debug 级别下）
grep "detector score detail" /var/log/wardennet/agent.log | tail -5

# 查看高风险事件
grep "high score event" /var/log/wardennet/agent.log

# 查看所有 warn 以上
grep -E "level=(warn|error)" /var/log/wardennet/agent.log

# 实时监控新拉黑
tail -f /var/log/wardennet/agent.log | grep --line-buffered "auto blocked"

# 确认配置已热重载
grep "config reload" /var/log/wardennet/agent.log

# 统计最近 10 分钟拉黑数量
grep "auto blocked" /var/log/wardennet/agent.log | grep "$(date -d '10 minutes ago' '+%H:%M')" -A0 -B0 | wc -l
```

### 7.3 评分详情日志解读（debug 级别）

开启 debug 后，每个达到 score_low(≥10) 阈值的事件输出：

**真实 CC 攻击（三维度协同）**：
```
ip=203.0.113.100 score=50 is_high=true ua="sqlmap/1.5.2"
win10s="win=10s sens=2 score=50(dims=3) [qps=20.0x:30 4xx=15.0x:30 ua=10.0x:20 danger=25 bonus=0]
  cnt[req=50 4xx=10 ua=50 static=0 brow=0]"
```

**正常浏览（QPS 单维度异常，被封顶）**：
```
ip=101.249.203.173 score=18 is_high=false ua="Chrome/136.0.0.0"
win10s="win=10s sens=2 score=18(legmit)(1dim-capped,dims=1) [qps=9.1x:24 4xx=0.5x:0 danger=5 bonus=-27]
  cnt[req=21 4xx=1 brow=21 static=3]"
```

**字段解读（v0.8 格式）**：

| 字段 | 含义 |
|------|------|
| `score=N` | 三档窗口最高分 |
| `is_high=true/false` | 是否达到 score_high 阈值 |
| `sens=N` | 动态敏感度（new IP=2, stable IP=5/10） |
| `legmit` | **v0.8 新标记**：legitimateUserContext 正常用户奖励已生效 |
| `dims=N` | **v0.8 新标记**：活跃的相对维度数（≥1 才有意义） |
| `(1dim-capped)` | **v0.8 新标记**：只有 1 个维度异常，被封顶到 score_medium |
| `qps=9.1x:24` | 格式 = `偏离倍数:贡献分数`（偏离基线 P95 9.1 倍 → 贡献 24 分） |
| `danger=25` | DangerousPattern 命中贡献的绝对分数（不受封顶） |
| `bonus=-27` | legmit 奖励扣分 / 空 Referer 扣分等 |
| `cnt[req=21 ...]` | 该窗口内的原始计数器 |
| `ua=0.0x:0` | 偏离倍数 + 分数：0.0 倍 → 没偏离 → 0 分 |
| `ref=17.7x:12(mitigated)` | 空 Referer 17.7 倍偏离，但因无佐证信号被降级 80% |

**怎么一眼看懂**：

| 日志片段 | 解读 |
|----------|------|
| `(dims=1)` + `(1dim-capped)` | 只有 1 个维度异常，被封顶，**不会封禁** ✅ |
| `(dims=2)` + 有 `danger=25` | 多维度协同，**有真实攻击特征** ⚠️ |
| `(legmit)` + `bonus=-27` | 正常浏览器用户，legmit 奖励扣了 27 分 |
| `score=50(dims=3)` + `is_high=true` | 真攻击，封禁触发 ✅ |

### 7.4 健康检查脚本

```bash
#!/bin/bash
# /usr/local/bin/wardennet-healthcheck.sh

SOCK="/var/run/wardennet.sock"
LOG="/var/log/wardennet/agent.log"
FAIL=0

check() { $2 && echo "✅ $1" || { echo "❌ $1"; FAIL=$((FAIL+1)); }; }

check "systemd 服务运行中"   "systemctl is-active --quiet wardennet-agent"
check "UnixSocket 存在"       "[ -S $SOCK ]"
check "CLI 响应正常"          "wardennet status &>/dev/null"
check "ipset blacklist 存在"  "ipset list wardennet_blacklist &>/dev/null"
check "ipset whitelist 存在"  "ipset list wardennet_whitelist &>/dev/null"
check "iptables DROP 规则"    "iptables -S INPUT | grep -q wardennet"
check "无 error 日志"          "[ \"$(grep -c 'level=error' $LOG 2>/dev/null)\" -eq 0 ]"

RESP=$(wardennet status 2>/dev/null)
echo ""
echo "📊 黑名单: $(echo $RESP | grep -oP 'blocked_count[^,]*') | TTL: $(echo $RESP | grep -oP 'ttl_entries[^,]*')"

exit $FAIL
```

**配合 crontab 每 5 分钟检查**：
```cron
*/5 * * * * /usr/local/bin/wardennet-healthcheck.sh >> /var/log/wardennet/health.log 2>&1
```

**配合 Prometheus / Zabbix**：
让检查脚本在失败时以非零退出码 + 写入 metric 文件，接入监控系统告警。

---

## 8. 故障排查手册

### 8.1 Agent 启动失败

**排查步骤**：

```bash
# Step 1: 查看 systemd 日志
journalctl -u wardennet-agent -n 30 --no-pager

# Step 2: 手动前台运行看报错
/opt/wardennet/wardennet --config /etc/wardennet/config.yaml

# Step 3: 逐项检查
which ipset iptables                         # 依赖是否存在（wardennet CLI 已内置，无需 socat）
ls -la /etc/wardennet/config.yaml           # 配置文件是否可读
cat /etc/wardennet/config.yaml | python3 -c "import yaml,sys; yaml.safe_load(sys.stdin)"  # YAML 语法校验
```

| 错误信息 | 常见原因 | 解决方案 |
|----------|----------|----------|
| `load config failed: ... yaml ...` | YAML 语法错误 | 用 `python3 -c "import yaml; yaml.safe_load(...)"` 校验 |
| `validate: ... invalid ip: ...` | whitelist/blacklist 中有非法 IP | 修正 /etc/wardennet/config.yaml |
| `mkdir socket dir: permission denied` | UnixSocket 目录权限 | Agent 以 root 运行，`/var/run` 应可写 |
| `ipset command failed` | ipset 未安装 | `apt install ipset` 或 `yum install ipset` |
| `iptables not found` | iptables 未安装 | `apt install iptables` |
| `config reload failed` | 配置文件热重载语法错误 | 回到 Step 1 |
| `log file dir: /var/log/wardennet/...` | 日志目录不可写 | `mkdir -p /var/log/wardennet && chown root:root /var/log/wardennet` |

### 8.2 IP 未被真正封禁

**链路检查（从日志 → ipset → iptables 逐层验证）**：

```bash
# Step 1: 日志中是否有拉黑记录
grep "auto blocked" /var/log/wardennet/agent.log | grep "203.0.113.100"

#   没有？→ 看是否在白名单
wardennet blocklist status
ipset test wardennet_whitelist 203.0.113.100

# Step 2: ipset 中是否存在
ipset test wardennet_blacklist 203.0.113.100
# 期望：203.0.113.100 is in set wardennet_blacklist.

#   不在？→ 检查 Step 1 日志，拉黑失败会有 "auto block failed"

# Step 3: iptables 规则是否存在
iptables -S INPUT | grep wardennet
# 期望：-A INPUT ... --match-set wardennet_blacklist src -j DROP

#   规则不在？→ Agent 可能启动失败，检查 systemd 状态

# Step 4: 实际 DROP 是否生效（测试）
# 从另一台机器请求该服务器的 HTTP 端口，应该超时或拒绝

# Step 5: 确认 TTL 是否在倒计时
ipset list wardennet_blacklist | grep 203.0.113.100
```

### 8.3 白名单不生效

```bash
# 1. 确认 ipset whitelist 类型
ipset list wardennet_whitelist | head -5
# 期望：Type: hash:net  （hash:ip 会自动重建）

# 2. 确认条目存在
ipset test wardennet_whitelist 192.168.220.50   # 测试网段内 IP
ipset test wardennet_whitelist 192.168.220.0     # 测试 CIDR 本身

# 3. 如果条目不在 ipset 中
#    → 检查 config.yaml 的 ipset.whitelist 段是否有语法错误
#    → 检查日志是否有 "local whitelist loaded, count=N"
#    → 强制重启 Agent：systemctl restart wardennet-agent
```

### 8.4 检测引擎过于敏感

```bash
# 现象：合法 IP 频繁被误杀

# Step 1: 开启 debug 看评分详情 + 基线学习日志
sed -i 's/level: info/level: debug/' /etc/wardennet/config.yaml
grep "config watcher" /var/log/wardennet/agent.log  # 确认热重载

# Step 2: 定位误杀 IP
grep "auto blocked" /var/log/wardennet/agent.log | head -5

# Step 3: 看该 IP 的评分详情（偏离哪些维度的 P95 基线）
grep "detector score detail" /var/log/wardennet/agent.log | grep "ip=<误杀IP>"

# Step 4: 看基线学习情况
grep "baseline updated" /var/log/wardennet/agent.log | tail -10

# Step 5: 调整配置（按推荐顺序尝试）
#   a. 调低 sensitivity（high → medium → low）
#   b. 调高 score_high 阈值（50 → 60 → 70）
#   c. 检查 legitimateUserContext 降权是否触发（致命攻击特征为零 + 浏览器占比 ≥ 95% 时 4xx/404 分打 1 折；或浏览器占比不足时所有攻击特征计数必须为零）
#   d. 观察基线学习日志，确认基线正在追踪正常流量

# Step 6: 恢复日志级别
sed -i 's/level: debug/level: info/' /etc/wardennet/config.yaml
```

**常见误杀场景**：

| 场景 | 根因 | 解决方案 |
|------|------|----------|
| 高流量电商大促 | 基线尚未完全适应 | 调低 sensitivity，观察 10 分钟基线自动恢复 |
| API 客户端带空 Referer | 空 Referer 偏离基线 | 基线自动追踪合法客户端行为；调低 sensitivity 兜底 |
| Token 过期重试 401 | 401 比率偏离基线 | 401 已自动降权 1/5 + 硬上限，基线学习后自动适应 |
| curl / wget 内部调用 | UA 匹配 Bot 特征 | 在 `known_http_clients.excludes` 中添加 |
| 业务访问敏感路径 | 业务确实需要 `/env` / `/admin` | 在 `sensitive_paths.excludes` 中排除 |
| CDN 健康检查 | CDN 流量模式偏离基线 | CDN IP 段加入白名单 |
| 日志未正确解析 | 路径被错误截断 | 检查 parser 输出是否正确，看日志原始 line |

### 8.5 Unix Socket 无法连接

```bash
ls -la /var/run/wardennet.sock      # 是否存在？
stat /var/run/wardennet.sock        # 权限是否 0600？
systemctl status wardennet-agent    # Agent 是否在运行？
systemctl restart wardennet-agent   # 重启后再试
```

### 8.6 ipset 操作报 "set doesn't exist"

Agent 启动时自动创建两个集合。如果被误删：

```bash
# 手动创建
ipset create wardennet_blacklist hash:ip
ipset create wardennet_whitelist hash:net family inet hashsize 1024 maxelem 65536

# 重启 Agent 补齐 iptables 规则
systemctl restart wardennet-agent
```

### 8.7 日志 tail 中断或重复

```bash
# 现象：Agent 日志出现 "tail dropped" 或事件重复处理

# 1. 检查 tail 状态文件
cat /etc/wardennet/tail_nginx_access_state.json

# 2. 如果怀疑重复，删除状态文件让 Agent 从文件末尾重新 tail
rm /etc/wardennet/tail_*.json
systemctl restart wardennet-agent
# ⚠️ 删除状态文件后，tail 从当前文件末尾开始，之前未处理的日志会丢失
```

### 8.8 云端封锁不自动解封

```bash
# 现象：某个 IP 被云端封锁（联防快速通道或评分触发），长时间不自动解封，
#       但云端 threat_pool 里该 IP 的评分已经下降或 threat_pool_ttl 到期

# 根因分析（v0.4.2 已全部修复，以下为排查项）：

# 检查 1: ipset 条目是否带 timeout
ipset list wardennet_blacklist -o plain | grep <ip>
#   期望：<ip> timeout NNN（N 应 <= 7200）
#   无 timeout 字段 → 版本低于 v0.4.2，云端封锁只有 TTL Sweep 单通道，
#     进程崩溃 + 快照丢失时该条目会永存 → 升级 v0.4.2+

# 检查 2: TTL Manager 是否注册了 SourceCloud 条目
wardennet blocklist status | jq '.ttl_entries'
#   如果 blocked_count > 0 但 ttl_entries 远小于 → 部分封锁没注册 TTL
#   查 applyDecisions 日志有没有 "cloud block ttl register failed"

# 检查 3: Unblock 竞态残留（历史版本可能残留的 blocked 内存 map）
wardennet blocklist status
#   如果 blocked_count > 0 但 ipset list 里找不到 → blocked map 有残留
#   直接用 CLI del 清掉即可（v0.4.2 Unblock 已无条件清内存 map）
wardennet blocklist del <ip>

# 临时紧急：手动解封
wardennet blocklist del <ip>
# 或直接操作 ipset（会跳过 Agent TTL，仅应急用）
ipset del wardennet_blacklist <ip> -exist

# 长期修复：升级 v0.4.2+ 后云端封锁自动具备双通道冗余，
# 进程崩溃、快照丢失、kernel timeout 竞态都有兜底
```

---

## 9. 紧急操作手册

### 9.1 紧急停封所有 IP（保留 Agent 运行）

```bash
# 方法一：清空 ipset（立即生效，秒级）
ipset flush wardennet_blacklist

# 方法二：通过 CLI 逐个删除（大量 IP 时较慢）
# 先导出列表
ipset list wardennet_blacklist | grep -E "^[0-9]" | while read ip; do
    wardennet blocklist del "$ip"
done
```

### 9.2 完全停掉 Agent（连防护一起停）

```bash
systemctl stop wardennet-agent

# ⚠️ 注意：
# stop 后 Agent 会清理 iptables DROP 规则（取决于 systemd ExecStop 是否配置）
# 如果 ExecStop 未清理规则，需要手动删除：
iptables -D INPUT -p tcp -m set --match-set wardennet_blacklist src -j DROP 2>/dev/null
```

### 9.3 单个 IP 紧急解封

```bash
# CLI 方式（推荐，TTL 同步清理）
wardennet blocklist del <IP>

# ipset 直删（不推荐，TTL 管理器不同步）
ipset del wardennet_blacklist <IP>
```

### 9.4 临时关闭检测（不删 ipset）

**推荐方案：观察者模式（温和）**

只禁止实际封禁，评分和日志全部保留，方便事后分析：
```bash
sed -i 's/mode: block/mode: report/' /etc/wardennet/config.yaml
# 5 秒热重载后生效，Agent 正常评分但不调用 ipset add
# 恢复封禁
sed -i 's/mode: report/mode: block/' /etc/wardennet/config.yaml
```

**彻底方案：禁用检测引擎**

```bash
sed -i 's/enabled: true/enabled: false/' /etc/wardennet/config.yaml

# 等待 5 秒热重载后，检测引擎停止评分，但 ipset 中已有黑名单仍继续 DROP
# 如果要连 DROP 也停，还需清空 ipset
ipset flush wardennet_blacklist

# 恢复时
sed -i 's/enabled: false/enabled: true/' /etc/wardennet/config.yaml
```

### 9.5 紧急解除 ipset / iptables 所有防护

```bash
# 1. 停止 Agent
systemctl stop wardennet-agent

# 2. 删除 iptables 中所有 wardennet 规则
iptables -S INPUT | grep wardennet | sed 's/-A/-D/' | while read cmd; do iptables $cmd; done

# 3. 销毁 ipset 集合
ipset destroy wardennet_blacklist 2>/dev/null
ipset destroy wardennet_whitelist 2>/dev/null

# 4. 验证
iptables -S INPUT | grep wardennet   # 应无输出
ipset list | grep wardennet          # 应无输出
```

---

## 10. 快照与数据恢复

### 10.1 快照机制

Agent 每 **60 秒**自动将当前黑名单 + TTL 状态写入快照文件。

- 路径：`/etc/wardennet/state.json`（与 config.yaml 同目录）
- 触发：定时器（60s）、优雅关闭（SIGTERM/SIGINT）

### 10.2 快照文件格式

```bash
cat /etc/wardennet/state.json | python3 -m json.tool

# 示例：
{
  "version": "v1.0",
  "saved_at": 1756383600,
  "ttl": {
    "entries": [
      {"ip": "203.0.113.100", "ttl": 3600, "source": 0, "expires_at": 1756387200, "created_at": 1756383600}
    ]
  }
}
```

### 10.3 恢复流程

Agent 启动时自动加载快照 → 恢复 TTL 计时器。

```bash
# 查看恢复日志
journalctl -u wardennet-agent | grep "snapshot restored"
# 期望：snapshot restored, version=v1.0, ttl_entries=15

# 首次启动无快照
journalctl -u wardennet-agent | grep "snapshot restore skipped"
```

### 10.4 手动重置快照

```bash
# 清空快照，重启后 Agent 不恢复任何历史黑名单
rm -f /etc/wardennet/state.json
systemctl restart wardennet-agent

# 配合清空 ipset（彻底重置）
ipset flush wardennet_blacklist
```

---

## 11. 升级与回滚

### 11.1 在线升级

```bash
# Step 1: 备份当前版本
cp /opt/wardennet/wardennet /opt/wardennet/wardennet.bak.v$(cat /opt/wardennet/version 2>/dev/null || echo "current")

# Step 2: 上传新二进制
scp wardennet_linux root@server:/opt/wardennet/wardennet
chmod +x /opt/wardennet/wardennet

# Step 3: 重启（自动保存旧快照 + 恢复新启动的 TTL）
systemctl restart wardennet-agent

# Step 4: 验证
wardennet status
# 检查 version 字段

journalctl -u wardennet-agent -n 10
# 确认 "agent fully initialized"
```

### 11.2 回滚

```bash
# 升级后发现问题，快速回滚
cp /opt/wardennet/wardennet.bak.vOLD /opt/wardennet/wardennet
systemctl restart wardennet-agent
```

### 11.3 跨大版本升级检查清单

从旧版本升级到新版本时需要关注：

| 检查项 | 命令 |
|--------|------|
| 白名单 ipset 类型 | `ipset list wardennet_whitelist \| head -3` → 应为 `Type: hash:net` |
| 配置 YAML 兼容性 | 对比旧配置与 `wardennet.yaml.example` 的新增字段 |
| 快照格式 | 新版本是否支持旧版本快照 |
| 日志源 parser | 自定义 parser 格式是否兼容 |

---

## 12. 卸载与清理

### 12.1 完整卸载

```bash
# 1. 停止 + 禁用
systemctl stop    wardennet-agent
systemctl disable wardennet-agent

# 2. 删除 systemd 单元
rm -f /etc/systemd/system/wardennet-agent.service
systemctl daemon-reload

# 3. 清理 iptables
iptables -S INPUT | grep wardennet | sed 's/-A/-D/' | while read cmd; do iptables $cmd; done

# 4. 销毁 ipset
ipset destroy wardennet_blacklist
ipset destroy wardennet_whitelist

# 5. 删除文件
rm -rf /opt/wardennet            # 二进制
rm -rf /etc/wardennet            # 配置
rm -rf /var/lib/wardennet        # 快照 / tail 状态
rm -rf /var/log/wardennet        # 日志（可选保留）
rm -f /var/run/wardennet.sock    # UnixSocket

# 6. 验证清理完成
systemctl status wardennet-agent &>/dev/null || echo "✅ 服务已清理"
ipset list 2>/dev/null | grep -q wardennet && echo "⚠️ 残留 ipset" || echo "✅ ipset 已清理"
```

### 12.2 保留数据卸载

```bash
systemctl stop wardennet-agent
rm -f /etc/systemd/system/wardennet-agent.service /opt/wardennet/wardennet
# /etc/wardennet /var/lib/wardennet /var/log/wardennet 保留
```

### 12.3 切换到其他防护方案

```bash
# 先完整卸载 WardenNet，再安装新方案
# 注意：卸载时 iptables/ipset 规则被清理，期间服务器**不受保护**
# 建议先安装好新方案再执行 WardenNet 卸载
```

---

## 13. CloudPlugin 闭源插件运维

CloudPlugin 是 WardenNet 提供的闭源动态链接库（`.so`），负责将 Agent 的本地扫描结果、心跳状态、Diff 规则与 WardenNet 控制台云端进行双向协同。插件以 dlopen 方式按需加载，Agent 在任何异常下都不会因插件问题而终止运行。

### 13.1 插件文件位置

- 默认路径：`/usr/lib/wardennet/libcloudplugin.so`
- 可通过配置项 `cloud.plugin_path` 覆盖自定义路径
- 文件不存在或权限不可读时，Agent 自动进入离线模式

### 13.2 插件加载验证

```bash
journalctl -u wardennet-agent | grep -i plugin
```

| 期望日志 | 含义 |
|----------|------|
| `plugin loaded successfully, version x.y.z` | 插件加载成功，版本号已打印 |
| `plugin not loaded, running in offline mode` | 未启用 `cloud.enabled` 或文件缺失，Agent 正常离线运行 |

### 13.3 插件配置

以下 YAML 字段均位于顶层 `cloud:` 下（见 6.2 节完整配置参考）：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `enabled` | bool | 否 | 插件总开关，默认 `false`。关闭时 Agent 纯本地运行，不加载 .so |
| `base_url` | string | 启用后必填 | WardenNet 控制台 HTTPS 地址，结尾不带 `/` |
| `tenant_id` | string | 启用后必填 | 租户标识，由控制台创建租户时颁发 |
| `agent_secret` | string | 启用后必填 | Agent 鉴权密钥，建议通过环境变量 `WARDENNET_AGENT_SECRET` 注入避免落盘 |
| `plugin_path` | string | 否 | `.so` 文件路径，默认 `/usr/lib/wardennet/libcloudplugin.so` |

### 13.4 插件降级行为表

| 故障场景 | Agent 行为 | 日志关键字 |
|----------|-----------|------------|
| `.so` 文件不存在 | 跳过加载，继续本地运行 | `plugin file not found` |
| `cloud.enabled: false` | 不加载 .so | `cloud plugin disabled by config` |
| dlopen / dlsym 失败 | 打印错误，降级离线模式 | `plugin open failed: ...` |
| 云端鉴权失败（401/403） | 不影响本地扫描，每 60s 重试一次 | `cloudsync auth failed` |
| Diff 拉取失败（网络/5xx） | 使用上一次成功拉取的规则集，本地防护不中断 | `cloudsync diff failed` |

### 13.5 插件更新流程

```bash
# 1. 上传新版本 .so（原子替换，避免 Agent 读到半截文件）
cp libcloudplugin.so.new /usr/lib/wardennet/libcloudplugin.so.tmp
mv -f /usr/lib/wardennet/libcloudplugin.so.tmp /usr/lib/wardennet/libcloudplugin.so
chmod 0644 /usr/lib/wardennet/libcloudplugin.so

# 2. 重启 Agent 触发重新 dlopen
systemctl restart wardennet-agent

# 3. 验证加载
journalctl -u wardennet-agent -n 30 | grep -i plugin
# 期望看到新版本号的 "plugin loaded successfully"
```

### 13.6 云端同步状态检查

```bash
journalctl -u wardennet-agent -f | grep -i cloudsync
```

常见日志字段说明：

| 日志片段 | 含义 |
|----------|------|
| `cloudsync diff pulled, rules=N, version=...` | Diff 规则拉取成功，当前生效版本号 |
| `cloudsync heartbeat sent, uptime=...` | 心跳上报，包含 Agent 运行时长 |
| `cloudsync version mismatch, local=... remote=...` | 本地 Agent 版本落后于控制台推荐版本，建议升级 |

### 13.7 无插件模式

当 `cloud.enabled: false` 或 `.so` 文件缺失时，Agent 以**纯本地模式**运行：

- 本地滑动窗口扫描、ipset/iptables 拦截完全正常
- 不发起任何出站 HTTP/HTTPS 请求
- 所有与云端相关的配置字段可留空
- 适合离线环境、内网隔离服务器或首次部署阶段

---

## 14. 附录

### 附录 A：ipset 命令参考速查

```bash
ipset list                    # 列出所有 ipset 集合
ipset list wardennet_blacklist        # 查看集合详情 + 条目
ipset test wardennet_blacklist <IP>   # 测试 IP 是否在集合中
ipset add  wardennet_blacklist <IP>   # 添加
ipset del  wardennet_blacklist <IP>   # 删除
ipset flush wardennet_blacklist       # 清空
ipset destroy wardennet_blacklist     # 销毁集合
ipset create wardennet_blacklist hash:ip
ipset create wardennet_whitelist hash:net family inet hashsize 1024 maxelem 65536
ipset save wardennet_blacklist        # 导出规则
```

### 附录 B：iptables 命令参考速查

```bash
iptables -L INPUT -n -v       # 查看 INPUT 链（包计数）
iptables -S INPUT             # 查看 INPUT 链规则文本
iptables -I INPUT ... -j DROP   # 插入规则
iptables -D INPUT ... -j DROP   # 删除规则
iptables -C INPUT ... -j DROP   # 检查规则是否存在（返回 0=存在）
```

### 附录 C：防误杀机制一览（v1.2，共 13 层）

| # | 机制 | 保护对象 | 行为 | 引入 |
|---|------|----------|------|------|
| 1 | **单维度封顶** | 单维度异常的正常用户 | 任意单维 ≤ score_high×60%(30)；仅 1 维 ≤ score_medium(30) | v0.8 |
| 2 | **绝对特征叠加** | SQL 注入/文件上传等真实攻击 | DangerousPattern/DangerousMethod/FileUpload 不受封顶 | v0.8 |
| 3 | **置信度打折** | Preload 基线不准时 | conf<0.3 → QPS 分×0.5；conf<0.1 → 永不封禁 | v0.8 |
| 4 | **纯尖峰打折** | 无攻击特征的 QPS 尖峰 | conf≥0.3 + 纯 QPS → QPS 分×0.3 | v0.8 |
| 5 | **MIN_BASELINE_QPS 硬保底** | 凌晨低峰基线污染 | QPS P95 永远 ≥ 1.0 req/s | v0.8 |
| 6 | **Preload MAD 极端值剔除** | 扫描器/爬虫/batch sync 污染 | 极端 QPS 桶从 Preload 样本中删除 | v0.8 |
| 7 | legitimateUserContext 降权 | 正常浏览器用户 | 浏览器占比 ≥ 95% → 4xx/404 打 1 折 | v2.0 |
| 8 | 基线自学习自动适应 | 时段流量、大促、NAT IP | P95 分位数动态学习，预热期快速收敛 | v2.0 |
| 9 | 空 Referer 硬上限 | API 客户端 | 单独触发 ≤ score_high/4(12) | v2.0 |
| 10 | 401 单独降权 + 硬上限 | Token 过期重试 | 401 权重×1/5 + 硬上限 | v2.0 |
| 11 | 已知 HTTP 客户端豁免 | okhttp / axios / curl 等 | 不判定为 Bot UA | v2.0 |
| 12 | 本地 IP 白名单 | 运维 IP、CDN 段 | 命中 → 完全跳过检测 | v2.0 |
| 13 | **Consistency 行为降权 gate** | 合法 API 客户端突发 | Scorer=score_high 但行为形状像正常用户 → 降到 score_medium | v1.2 |

### 附录 D：systemd service 安全加固说明

`wardennet-agent.service` 中配置了：

```ini
NoNewPrivileges=yes      # 禁止进程创建新特权
ProtectSystem=strict     # 只读根文件系统（仅指定目录可写）
ReadWritePaths=/opt/wardennet /var/lib/wardennet /var/log/wardennet
ReadWritePaths+=/var/log/nginx
LimitNOFILE=65536        # 文件描述符上限（处理高并发日志需要）
LimitNPROC=4096          # 进程数上限
```

如需访问其他目录（如其他 nginx 日志路径），追加到 `ReadWritePaths` 即可。

### 附录 E：跨平台开发提示

| 平台 | ipset/iptables | 行为 |
|------|---------------|------|
| Linux（生产） | 真实命令 | 操作内核 ipset 和 iptables |
| Windows / Mac | 无 | 使用内存 Mock Client，CLI/日志正常但无实际封禁 |

---

*文档版本：v2.2*
*适用 Agent 版本：v1.2+*
*更新时间：2026-09-07（v1.2 Consistency 5 维行为连贯性评分 + 参数化配置）*
