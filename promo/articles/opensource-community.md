---
title: 从零开始开源一个 Web 安全防护项目：WardenNet 的设计理念与快速上手指南
platform: 开源中国 / 博客园
word-count: 2200
date: 2026-09
---

# 从零开始开源一个 Web 安全防护项目：WardenNet 的设计理念与快速上手指南

> 为什么写这个项目？因为中小站长不该在"裸奔"和"掏腰包"之间二选一。

## 一段独白

我是一名"杂食"开发者，主业在一家互联网公司做后端，副业帮朋友维护着好几个个人站点和小型 SaaS 项目。这些站点不大，流量不高，但有一些共同特点：

- 跑在国内某云的轻量应用服务器上，配置最高 4C8G，有的甚至只有 1C2G
- 每月总预算加起来还不够买一份商业 WAF
- 上面跑着 WordPress、Typecho、自建的 API 服务，技术栈不统一
- 但**它们每天都会被扫**——从 `/wp-login.php` 到 `/.git/config`，从 SQL 注入 payload 到 PHP webshell 上传尝试，无一幸免

有一天我打开其中一个站点的 Nginx access log，统计了一下过去 24 小时的 4xx 请求——**占了总请求的 37%**。这些全是扫描器。它们不消耗太多带宽，不打垮服务器，但就像你家门口徘徊的小偷，明知道你家值钱东西藏在哪，就是一直在那转。

试过的方案我列一下，你肯定也都试过：

| 方案 | 效果 | 痛点 |
|------|------|------|
| **Nginx rate_limit** | 限 QPS | 挡不住慢速扫描；合法爬虫会被误伤 |
| **fail2ban** | 看 access log + 正则 | 规则难写、误报率高；404 扫描这种场景它分不清 |
| **Apache mod_security** | OWASP Core Rule Set | 规则太全 → 误杀自己业务；规则太松 → 形同虚设 |
| **商业 WAF（XX盾）** | 效果好 | 最便宜的也要月付几千；小站点不划算 |
| **自建简易脚本** | grep + ipset | 自己维护、自己修 bug；而且单机阈值能被绕过 |

于是我做了一个决定：**自己写一个。并且开源。**

---

## 为什么要开源？

这个问题我问了自己很久。商业 WAF 的市场那么大，我一个个人开发者凭什么跟大厂竞争？

但我想通了一件事——**中小站长的安全困境，本质上不是"没有 WAF"，而是"没有一个对他们友好的 WAF"**。

商业 WAF 面向的是有运维团队的中大型企业：开箱即用但贵、功能强大但复杂、定制化但需要专业知识。中小站长要的是：

- **5 分钟装好**：不要 Docker 编排、不要 K8s、不要一堆依赖
- **资源占用低**：不能把 1C2G 的机器搞卡
- **误报少**：不然还不如不用
- **透明可控**：我得知道它在干什么，不能是个黑盒

开源意味着：

1. **任何人都能免费使用**——包括那个 1C2G 的个人博客
2. **任何人都能改**——你的业务有特殊路径？改配置就行
3. **任何人都能审计**——安全工具本身不能是安全盲区
4. **社区能帮忙变好**——漏洞修复、新特征库、新部署场景

这就是 WardenNet 的初心：**让每一台 Web 服务器都有一个不花钱的哨兵**。

---

## 设计理念：三个关键词

在动手写第一行 Go 代码之前，我给自己定了三个原则：

### 1. 轻到极致

Agent 用 Go 写，单二进制文件，**编译后极轻量**。为什么选 Go？因为它天生适合这种场景：

- 编译到单文件，零运行时依赖
- goroutine + channel 模型天生适合并发处理日志
- 内存安全、启动快、退出快

对比一下：

| 技术栈 | 部署文件大小 | 依赖 |
|--------|:----------:|------|
| **WardenNet Agent (Go)** | **极轻量** | 仅 ipset/iptables |
| fail2ban (Python) | ~20MB + Python 运行时 | Python 3.x + 多个库 |
| mod_security (C) | ~10MB + Apache 模块 | Apache 编译环境 |
| 商业 WAF 客户端 | 通常 > 50MB | 多组件、多依赖 |

极轻量是什么概念？差不多一张中等大小的 PNG 截图。它跑起来的内存占用通常在 **10-30MB** 之间，对 1C2G 的服务器来说，相当于多开了一个进程。

### 2. 聪明但不复杂

**聪明**体现在决策上——基线自学习、5 维一致性评分、三档滑动窗口、6 层防误报。这些算法让它不需要你手工配置 20 个阈值就能精准识别扫描器。

**不复杂**体现在使用上——YAML 配置文件，核心参数只有 `score_high`、`sensitivity`、`mode` 三个。其余全部用程序内置默认值。

### 3. 单机可用，协同更强

这是最重要的一条，也是 WardenNet 和其他协同防御项目最大的区别。

有些项目设计上就是"必须连云端才能工作"——断网 = 完全停摆。WardenNet 反过来：**单机 Agent 是完整产品，云端协同是可选增值**。

- Agent 启动时自动扫描最近 10 分钟日志建立基线（消除冷启动误判）
- 没有云端连接时，它就是一个纯粹的本地防护工具
- 有云端连接时，它获得全网威胁情报，但**最终封禁决策权永远在本地**

这让它可以从"一台服务器开始用"，随着你的业务增长再逐步接入协同网络。

---

## 3 步快速部署

不说废话，直接上命令。

### 第 1 步：下载或编译 Agent

**方式 A：下载预编译二进制（推荐）**

```bash
# 假设我们已经发布了 Release
wget https://github.com/wardennet/agent/releases/download/v0.4.0/wardennet-linux-amd64
chmod +x wardennet-linux-amd64
sudo mv wardennet-linux-amd64 /usr/local/bin/wardennet
```

**方式 B：从源码编译**

```bash
# 需要 Go 1.21+
git clone https://github.com/wardennet/agent.git
cd agent
go build -o wardennet ./cmd/wardennet
sudo cp wardennet /usr/local/bin/wardennet
```

### 第 2 步：准备配置文件

```bash
sudo mkdir -p /etc/wardennet
sudo wardennet init-config /etc/wardennet/config.yaml
```

打开 `/etc/wardennet/config.yaml`，**只需要修改两处**：

```yaml
# 确认你的 Nginx access log 路径
log_sources:
  nginx_access:
    path: /var/log/nginx/access.log    # ← 改这里
    parser: nginx_access

# 设置你的白名单（可选但推荐）
ipset:
  whitelist:
    - 127.0.0.1
    - 10.0.0.0/8                       # 你的内网
    - 192.168.1.0/24                   # 你的办公网
```

其余配置全部使用默认值即可。程序内置了：

- 14 种已知 HTTP 客户端 UA 白名单（okhttp、python-requests、curl 等）
- 30+ 种敏感路径关键词（admin、.env、.git、wp-login 等）
- SQL 注入/XSS/路径遍历等危险攻击模式的解码检测
- 空 Referer 封顶、401 降权等 8 层防误杀机制

### 第 3 步：用 systemd 管理（推荐）

```bash
sudo cp agent/configs/wardenet.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable wardennet
sudo systemctl start wardennet
```

检查运行状态：

```bash
sudo systemctl status wardennet
# 应该看到 "active (running)"

# 查看实时日志
sudo journalctl -u wardennet -f

# 查看当前黑名单
sudo ipset list wardennet_blacklist
```

如果你暂时不想用 systemd，直接前台运行也行：

```bash
sudo wardennet -config /etc/wardennet/config.yaml
```

---

## systemd 服务配置详解

如果你好奇 systemd 服务文件里写了什么，这里是完整内容（来自 `agent/configs/wardenet.service`）：

```ini
[Unit]
Description=WardenNet Agent - Collaborative Defense Sentinel
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/wardennet -config /etc/wardennet/config.yaml
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal

# 安全加固
NoNewPrivileges=no          # 需要 root 操作 ipset/iptables
ProtectSystem=full          # 只读系统目录
ProtectHome=true
PrivateTmp=true
PrivateDevices=false        # 需要访问 /dev/net/tun

[Install]
WantedBy=multi-user.target
```

几个要点：

- **User=root**：操作 ipset/iptables 需要 root 权限
- **Restart=on-failure + RestartSec=5s**：崩溃后 5 秒自动重启
- **ProtectSystem=full**：只读根文件系统，降低被入侵后的风险

---

## 上线初期：观察者模式

我特别推荐在上线前 **先用 `mode: report` 跑 24-48 小时**：

```yaml
detector:
  mode: report    # 只评分上报，不执行封禁
```

这样 Agent 会照常分析每一条日志、给每个 IP 打分，但不会真的把谁拉黑。24 小时后你可以查看日志里的评分分布，看看：

- score_high（默认 50）这个阈值是否合适？
- 有没有真实用户被意外打了高分？
- 扫描器的分数通常集中在什么区间？

确认没问题后再切换回 `mode: block`。这比一上来就封禁要稳得多。

---

## 真实效果：我自己的站点

我在其中一个个人博客上跑了 WardenNet Agent 一周，以下是从日志里摘的数据：

| 指标 | 数据 |
|------|------|
| 检测到的独立扫描 IP | 347 个 |
| 最常见的扫描路径 | `/.env`、`/wp-login.php`、`/phpinfo.php` |
| 典型扫描 QPS | 2-8（慢速扫描，单机阈值会被绕过） |
| 平均封禁时长 | 1 小时（本地 TTL） |
| 误报数 | 0（这 347 个 IP 全部是真实扫描器，我用 Whois 查过） |

最后一条是最让我满意的——**零误报**。这主要归功于基线自学习 + 5 维一致性评分 + 8 层防误杀的组合拳。

---

## 你可以贡献什么？

WardenNet 的 `agent/` 目录接受开源贡献（AGPLv3）。我们特别欢迎：

- **新的日志解析器**：如果你用的日志格式是自定义的，可以贡献 parser
- **新的特征库**：新的 bot UA、新的敏感路径关键词
- **新的部署场景**：Dockerfile、K8s DaemonSet、Ansible Playbook
- **Bug 反馈和安全审计**：发现问题直接提 Issue

Cloud SaaS 和 Web 前端是闭源的商业组件，不接受外部 PR。如果你需要接入协同网络（全网威胁情报、Dashboard 管理、威胁事件汇总），可以联系我们获取授权。

---

## 最后

如果你是中小站长、个人开发者、DevOps 爱好者——试试 WardenNet。

它可能不是功能最全的防护工具，也不是防御面最广的方案。但它对中小场景的友好度，我敢说在开源项目里几乎没有对手。

**一处发现，全网御敌。** 也许从你的服务器开始，就能加入这张网。

> 项目地址：github.com/wardennet
> Agent 二进制：Go 编译，极轻量
> 许可证：AGPLv3（Agent 部分）
