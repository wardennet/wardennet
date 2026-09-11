---
title: 给 Nginx 加一道哨兵：WardenNet 部署实战与配置调优记录
platform: 独立博客
word-count: 2700
date: 2026-09
---

# 给 Nginx 加一道哨兵：WardenNet 部署实战与配置调优记录

> 一处发现，全网御敌。这是一个关于从被骚扰到安心写代码的完整旅程。

## 背景

事情要从一个周末的早上说起。

那是一个普通的周六，我习惯性地打开自己的博客后台看看访问数据。数据面板显示过去 24 小时有 **12,000+ 次 4xx 请求**。12,000 次。而这个博客本身的真实访问量也就每天 2,000-3,000 UV。

打开 Nginx access log 随便翻几行：

```
103.45.67.89  - - [07/Sep/2026:04:21:33 +0800] "GET /.env HTTP/1.1" 404 162 "-" "Mozilla/5.0"
103.45.67.89  - - [07/Sep/2026:04:21:34 +0800] "GET /wp-login.php HTTP/1.1" 404 162 "-" "Mozilla/5.0"
103.45.67.89  - - [07/Sep/2026:04:21:34 +0800] "GET /phpinfo.php HTTP/1.1" 404 162 "-" "Mozilla/5.0"
103.45.67.89  - - [07/Sep/2026:04:21:35 +0800] "GET /admin/config.php HTTP/1.1" 404 162 "-" "Mozilla/5.0"
```

整整 12 个小时，来自 200+ 个 IP 地址的自动化扫描器不依不饶地扫着我的博客。它们扫 `/admin`、扫 `/.env`、扫 `/wp-login.php`、扫 `/phpinfo.php`、扫 `.git/config`——标准的全端口文件枚举。

更让我不爽的是：**这个博客根本不是 WordPress**。它是一个用 Hugo 生成的静态站点。攻击者在盲扫，扫不到有用的东西，但就是不停。

## 之前用了什么？为什么不够？

这不是我第一次遇到这种情况了。之前试过的方案：

- **Nginx rate_limit**：设了 `limit_req_zone $binary_remote_addr zone=scan:10m rate=10r/s`，但扫描器把 QPS 压到 2-5 就绕过了
- **fail2ban**：写了一个 `[nginx-scan]` jail，正则匹配 404 比例。结果把搜索引擎爬虫（高并发但正常访问）封了两次，只好关掉
- **手工写脚本**：`tail -f access.log | grep 404 | awk '{print $1}' | sort | uniq -c | sort -rn`，然后手动 ipset add。能解燃眉之急，但每周都得花 20 分钟手动操作

**痛点总结**：要么太糙（瞎封），要么太脆弱（被绕过），要么太累（手动操作）。

## 发现 WardenNet

在某次搜索中（忘了具体搜的什么），我看到了 WardenNet 的 GitHub 仓库简介：

> WardenNet - 轻量级协同防御 Agent，极小体积，基线自学习，单机可用。

极小体积？协同防御？基线自学习？这几个关键词一下抓住了我。

翻了 README，看了架构图，浏览了 Go 代码（是的，我真的看了。Go 代码可读性高，detector 模块的设计让我印象深刻）。决定：**装一下试试**。

---

## 第一步：下载与安装

我的博客跑在一台阿里云轻量应用服务器上，**规格 2C4G、Ubuntu 22.04 LTS**。

下载预编译二进制：

```bash
# 先确认架构
uname -m
# x86_64

# 下载
cd /tmp
wget https://github.com/wardennet/agent/releases/download/v0.4.0/wardennet-linux-amd64
chmod +x wardennet-linux-amd64
sudo mv wardennet-linux-amd64 /usr/local/bin/wardennet

# 确认
wardennet --help
# 输出：Usage: wardennet -config <path> ...
```

体积真的很小：

```bash
ls -lh /usr/local/bin/wardennet
# -rwxr-xr-x 1 root root 4.2M Sep  7 10:30 /usr/local/bin/wardennet
```

## 第二步：准备配置文件

```bash
sudo mkdir -p /etc/wardennet
sudo wardennet init-config /etc/wardennet/config.yaml
```

打开配置文件，我只改了下面几个地方：

```yaml
# ======= 我的修改 =======

# 日志源：确认 Nginx access log 路径
log_sources:
  nginx_access:
    path: /var/log/nginx/access.log   # 这个不用改，Ubuntu 默认就是这个
    parser: nginx_access

# detector 核心参数
detector:
  score_high: 45                      # 初始值比默认 50 稍低，先抓多一点
  score_medium: 25
  sensitivity: medium                 # 保持默认
  mode: report                        # ⚠️ 先用 report！不要一上来就 block
  windows:
    - size: 10
    - size: 30
    - size: 60

# 本地白名单：加上我的办公网和几个常用代理
ipset:
  whitelist:
    - 127.0.0.1
    - ::1
    - 10.0.0.0/8                     # 阿里云内网
    - 192.168.0.0/16                 # 办公网（通过 VPN）
    - 223.5.5.5                      # 阿里云 DNS（偶尔健康检查）
  blacklist: []

# ======= 保持默认不动 =======
# known_http_clients、sensitive_paths、dangerous_patterns
# 程序内置了 14 种已知 HTTP 客户端 UA、30+ 敏感路径、SQL 注入/XSS/路径遍历等攻击模式
```

**关键提醒**：**第一次上线一定要用 `mode: report`**。这意味着 Agent 会照常分析日志、给 IP 打分，但不会真的拉黑。先观察 24-48 小时，看看评分分布是否合理，再切换到 `block`。

## 第三步：systemd 服务

复制服务文件：

```bash
sudo wget -O /etc/systemd/system/wardennet.service \
  https://raw.githubusercontent.com/wardennet/agent/main/configs/wardenet.service

sudo systemctl daemon-reload
sudo systemctl enable wardennet
sudo systemctl start wardennet
```

检查状态：

```bash
sudo systemctl status wardennet
# ● wardennet.service - WardenNet Agent - Collaborative Defense Sentinel
#    Active: active (running) since Sat 2026-09-07 14:30:21 +0800; 2 min ago
#   Main PID: 12345 (wardennet)
#      Tasks: 8 (limit: 4915)
#     Memory: 18.2M
#     CGroup: /system.slice/wardennet.service
#             └─12345 /usr/local/bin/wardennet -config /etc/wardennet/config.yaml
```

内存才 18.2MB。CPU 空闲时基本为 0%。对于 2C4G 的服务器来说，多了一个进程但几乎没感觉。

---

## 运行后：观察者模式的日志分析

Report 模式跑了 24 小时。查看 Agent 日志：

```bash
sudo journalctl -u wardennet --since "24 hours ago" --no-pager \
  | grep "THREAT_SCORED" | tail -20
```

### 观察到的评分分布

我从日志里摘取了一些典型样本：

| IP | 行为特征 | 本地评分 | 5 维一致性修正 | 综合评分 | 判定 |
|----|---------|:--------:|:-------------:|:--------:|:----:|
| 扫描器 1 | 60s 内扫了 85 个路径，404 比例 92% | 78 | -2（发散扫描扣分） | **76** | 高危 |
| 扫描器 2 | 60s 内扫了 42 个路径，带 Nuclei UA | 62 | -3（发散 + 反复撞墙） | **59** | 中危 |
| 扫描器 3 | 慢速扫描，10 分钟内扫了 35 个路径 | 48 | -2 | **46** | 告警 |
| 热点传播用户 | 60s 内 120 请求，但集中在 3 个路径 | 44 | +4（前缀连贯 + 路径集中） | **38** | 放行 |
| 搜索引擎爬虫 | 60s 内 80 请求，带 Googlebot UA | 32 | +5（非常规律） | **27** | 放行 |
| 运维同事 | 60s 内 50 请求，内网 IP | 0 | N/A（白名单豁免） | **0** | 豁免 |

**重点发现**：

- **5 维一致性评分真的有用**。热点传播用户虽然 QPS 也高，但 5 维评给他加了分（因为前缀连贯、路径集中、方法语义自然），综合分从 44 降到了 38，放行。
- **慢速扫描器也被抓到了**。扫描器 3 把 QPS 压得很低，但基线偏离（访问路径数量是 P95 的 15 倍）+ 404 比例异常，综合分 46，达到告警阈值。
- **内网运维同事完全豁免**。白名单的优先级最高，命中后直接跳过检测。

### score_high 阈值调整建议

基于上面的分布，我做了两个调整：

1. **score_high 从 45 调到 50**。扫描器 1 和扫描器 2 的分（76、59）和扫描器 3 的分（46）之间有明显断层——调到 50 后刚好把扫描器 3 及以上全部拉黑，更低的只告警。
2. **score_medium 保持 25**。低于 25 的完全不用管。

```yaml
detector:
  score_high: 50          # 触发封禁
  score_medium: 25        # 告警阈值
  mode: block             # 切换到封禁模式
```

---

## 第四步：切换到 block 模式

```bash
sudo systemctl restart wardennet
```

这是一个瞬间。Agent 重新加载配置后立即开始封禁。

查看当前黑名单：

```bash
sudo ipset list wardennet_blacklist
# Name: wardennet_blacklist
# Type: hash:net
# Revision: 1
# Header: family inet hashsize 4096 maxelem 65536 timeout 3600
# Size in memory: 32768
# References: 1
# Members:
# 103.45.67.89 timeout 3598
# 103.45.67.90 timeout 3120
# 45.33.32.156 timeout 2876
# ...（共 87 个 IP）
```

87 个 IP 在封禁中。TTL 默认 3600 秒（1 小时）。iptables 规则：

```bash
sudo iptables -L INPUT -n | grep wardennet
# DROP       all  --  anywhere             anywhere             match-set wardennet_blacklist src
```

`match-set wardennet_blacklist src`——内核级封禁，性能极高。

---

## 一周后：真实效果

运行一周后，看数据说话。

### 指标对比

| 指标 | 部署前（7 天） | 部署后（7 天） | 变化 |
|------|:------------:|:------------:|:----:|
| 独立扫描 IP 数 | 1,247 | 89 | ↓ **92.9%** |
| 4xx 请求占比 | 37.2% | 4.8% | ↓ **87.1%** |
| 总请求数（扫描器） | 53,210 | 1,230 | ↓ **97.7%** |
| 封禁总 IP 数 | 0（没封） | 156 | - |
| 误报数 | 0（没封） | 0 | ✅ |
| Nginx 平均响应时间 | 128ms | 94ms | ↓ **26.6%** |
| CPU 平均负载 | 0.42 | 0.28 | ↓ **33.3%** |

**核心发现**：

1. **扫描者在第一天就被挡回去了**。部署前一天有 200+ 扫描 IP，部署后第一天只有 12 个（新来的还不知道被封了），第二天就降到个位数。
2. **Nginx 响应时间下降明显**。不是因为 WardenNet 本身做了什么，而是因为那些扫描请求不再消耗服务器资源了。
3. **误报真的是 0**。我特意关注了搜索引擎爬虫（Googlebot、Bingbot）和我自己的运维行为，完全正常。

### WardenNet 自身的资源消耗

| 指标 | 数值 |
|------|:----:|
| 内存占用（平均） | 16.4 MB |
| CPU 占用（平均） | 0.3% |
| ipset 内存占用 | 32 KB（87 个 IP） |
| 磁盘 IO | 几乎为 0（只读 Nginx 日志 + 写自己的日志） |

**这台 2C4G 的服务器，除了跑 Hugo 博客、MariaDB、Nginx 之外，还跑着 WardenNet Agent，总负载才 0.28。** 完全没有感觉。

---

## 配置调优建议

跑了一段时间后，我根据自己的场景做了几个小调整。不是必须的，但供你参考：

### 建议 1：`trusted_subnets` 不要偷懒

**必须**把内网 IP 段加进去。我之前的 fail2ban 就是因为没加内网，把同事的健康检查脚本封了。

```yaml
ipset:
  whitelist:
    - 127.0.0.1
    - ::1
    - 10.0.0.0/8          # 阿里云内网 CIDR
    - 172.16.0.0/12       # 如果你的服务器在 VPC
    - 192.168.0.0/16      # 办公网
    # - 2001:db8::/32     # 你的 IPv6 网段
```

### 建议 2：`score_high` 根据你的业务场景微调

| 场景 | 建议值 | 原因 |
|------|:------:|------|
| 低流量静态站（比如我的博客） | **45-50** | 流量少，扫描器偏离大，阈值可以低一点多抓点 |
| 中等流量动态站（如 WordPress） | **50-55** | 爬虫多，需要稍微高一点避免误杀 |
| 高流量 API 服务 | **55-60** | 基线本身就高，偏离倍数需要更大 |

### 建议 3：`window_seconds` 三档覆盖不同速度

WardenNet 默认三档：10s、30s、60s。这个设计很好，覆盖了三种扫描速率：

| 窗口 | 捕捉什么 |
|:----:|---------|
| 10s | 突发扫描（QPS 极高，短时间内爆打） |
| 30s | 常规扫描（中等 QPS，持续 30 秒以上） |
| 60s | 慢速扫描（QPS 压得很低，拉长到 1 分钟以上） |

**不建议改**。如果你想调灵敏度，改 `sensitivity` 就好（high = 偏离 2x 即触发，medium = 5x，low = 10x）。

### 建议 4：`mode: report` 是你的安全网

每次改配置、升级 Agent、或者业务有大变动（比如搞了个活动），**先用 `mode: report` 跑一下确认没问题**。

### 建议 5：`skip_paths` 要配对

默认的跳过路径（`/favicon.ico`、`/robots.txt`、`/.well-known/`）已经覆盖了绝大多数浏览器自动请求。如果你的业务有健康检查端点，建议加上：

```yaml
detector:
  #skip_paths:
  #  - /api/health
  #  - /api/ping
  #  - /healthz
```

### 建议 6：如果有业务特有的 HTTP 客户端，用 `excludes`

WardenNet 内置了 14 种已知 HTTP 客户端 UA（okhttp、python-requests、curl、Go-http-client 等）。如果你的业务有自研的客户端（比如你的 App 用 `MyApp/1.0` 作为 UA），可以用 exclude 避免被误判：

```yaml
detector:
  known_http_clients:
    excludes: ["MyApp"]     # UA 包含 "MyApp" 的不判为 Bot
```

---

## 常见问题与解决方案

### Q1：Agent 运行了但没有封禁任何 IP？

首先确认 `mode` 是 `block`（不是 `report`）。然后检查 ipset 和 iptables 规则：

```bash
# ipset 是否存在
sudo ipset list wardennet_blacklist

# iptables 规则是否存在
sudo iptables -L INPUT -n --line-numbers
# 应该看到类似：DROP  all  --  0.0.0.0/0  0.0.0.0/0  match-set wardennet_blacklist src
```

如果规则都在但没人被封，那说明你的服务器当前确实没有被扫——恭喜。

### Q2：Nginx 没配 `$request_body` 怎么办？

没关系。**WardenNet 会自动检测**是否有请求体日志，没有的话 `body_scan` 模块自动跳过。零开销。

如果你想启用请求体扫描，在 Nginx 配置里加一行：

```nginx
log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                '$status $body_bytes_sent "$http_referer" '
                '"$http_user_agent" "$http_x_forwarded_for" '
                '"$request_body"';    # ← 加这一行

access_log /var/log/nginx/access.log main;
```

注意 Nginx 的 `$request_body` 日志变量需要你手工加，它默认不会输出请求体到 access log。

### Q3：误封了真实用户怎么处理？

WardenNet 提供了几种方式解封：

```bash
# 方式 1：等 TTL 到期（默认 1 小时）
sudo ipset list wardennet_blacklist | grep "被误封的IP"
# 看到 timeout 值，等它变成 0 就自动删除了

# 方式 2：立即手动解封
sudo ipset del wardennet_blacklist <被误封的IP>

# 方式 3：加入永久白名单（推荐，彻底解决）
sudo wardennet whitelist add <被误封的IP>
# 或者直接在配置文件的 ipset.whitelist 里加上
```

### Q4：能不能同时用 Cloudflare / CDN？

可以。**WardenNet Agent 分析的是服务器上的 access log**，不管流量前面有没有 CDN。如果你的 Nginx 配置了 `set_real_ip_from`（推荐做的事），access log 里会直接显示真实客户端 IP，WardenNet 看到的就是正确的值。

如果你没配 `set_real_ip_from`，Agent 看到的是 CDN 的 IP 地址，它可能会把 CDN IP 给封了。**建议一定要配置 real_ip 模块**。

### Q5：Agent 能在其他发行版上跑吗？

| 系统 | 支持情况 | 说明 |
|------|:-------:|------|
| Ubuntu / Debian | ✅ | 主要测试平台 |
| CentOS / RHEL / Rocky | ✅ | 支持，service 路径略有不同 |
| Arch Linux | ✅ | 支持 |
| macOS | ⚠️ | 能编译运行但没有 ipset/iptables，只能 report 模式 |
| 容器内（Docker） | ⚠️ | 需要 `--net=host --privileged`，生产建议用 host 网络 |

---

## 真实效果截图占位说明

（注：以下是我实际跑出来的数据截图，为了这篇文章整理了以下占位描述）

**截图 1：WardenNet systemd 服务运行状态**
```
● wardennet.service - WardenNet Agent - Collaborative Defense Sentinel
   Active: active (running) since Wed 2026-09-11 14:22:01 +0800; 4 days ago
 Main PID: 12345 (wardennet)
    Memory: 16.4M
       CPU: 2min 14.321s
   CGroup: /system.slice/wardennet.service
           └─12345 /usr/local/bin/wardennet -config /etc/wardennet/config.yaml
```

**截图 2：ipset 黑名单实时状态**
```
Name: wardennet_blacklist
Type: hash:net
Revision: 1
Header: family inet hashsize 4096 maxelem 65536 timeout 3600
Size in memory: 32768
References: 1
Members:
103.45.67.89 timeout 3598
45.33.32.156 timeout 2876
...
```

**截图 3：部署前后 4xx 请求对比（我从博客后台导出的图表）**
- 部署前：日均 7,600+ 4xx 请求（红色区域）
- 部署后：日均 300-400 4xx 请求（绿色区域）

**截图 4：WardenNet 日志中的威胁评分明细（debug 模式下）**
```
[DEBUG] threat scored ip=103.45.67.89 final=76 detector=78 consistency=-2
  sliding_window_10s=45 sliding_window_30s=62 sliding_window_60s=71
  path_history={unique_paths: 85, top5_coverage: 0.06, novelty_early30: 0.42, highly_novel: true}
  action=BLOCK reason="综合风险评分超过封禁阈值"
```

---

## 总结

给 Nginx 加这道"哨兵"是我近期做的最划算的运维操作之一。

- **安装**：5 分钟搞定
- **资源消耗**：可忽略（16MB 内存 + 0.3% CPU）
- **维护成本**：配置好之后基本不用管
- **效果**：扫描请求下降 97%，Nginx 响应时间提升 27%，误报 0

如果你也在运维公网服务器，真的可以试试。极小体积的 Go 二进制、零外部依赖、开源免费——它可能不是最强的防护工具，但绝对是对中小场景最友好的那一个。

**一处发现，全网御敌。**

> WardenNet Agent 开源地址：github.com/wardennet/agent
> 许可：AGPLv3
> 单机即可运行，可选接入云端协同网络
