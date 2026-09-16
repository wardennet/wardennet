# WardenNet

[![Go 1.27+](https://img.shields.io/badge/Go-1.27%2B-blue)](https://go.dev/)
[![License AGPLv3](https://img.shields.io/badge/License-AGPLv3-green)](./LICENSE)
[![Build mode](https://img.shields.io/badge/Build-static-steelblue)](./docs/build.zh.md)
[![GitHub stars](https://img.shields.io/github/stars/wardennet/wardennet?style=social)](https://github.com/wardennet/wardennet)

轻量级协同防御 Agent。在你的服务器上实时分析访问日志，通过滑动窗口 + 基线自学习识别扫描行为，自动将高危 IP 加入内核 ipset -> iptables DROP 链，实现内核级零延迟拦截。

> 当每台服务器都成为哨兵，它们联合起来就是一支军队。

[English README](./README.md) . [快速开始](./docs/quick-start.zh.md) . [架构总览](./docs/architecture.zh.md) . [配置参考](./docs/configuration.zh.md)

---

## 解决什么问题？

如果你运维过公网 Web 服务器，打开 Nginx access log 看一分钟——你会看到来自 20 多个国家的 30 多个 IP 在扫描 /.env、/wp-login.php、/admin/config.php、.git/config。这些自动化枚举机器人静默探测，直到某天找到零日漏洞。

传统防护手段全部失效：

| 方案 | 为什么不行 |
|------|----------|
| fail2ban（正则规则） | 误封搜索引擎爬虫，慢速分布式扫描轻松绕过 |
| Nginx rate_limit（QPS 阈值） | 僵尸网络把 QPS 压到 2-5 就绕过去了 |
| 商业 WAF | 贵、规则静态、不会学习你的流量特征 |
| 手动 ipset add | 每周花 20 分钟重复操作，太累 |

**WardenNet 用三个思路破解这个困境**：滑动窗口 + 基线自学习（不预设阈值）、5 维一致性评分（区分 bot 和真实用户）、可选云端协同（一台服务器发现威胁，全网同步封禁）。

---

## 3 分钟快速试用

不需要编译。下载预打包好的 zip，解压，跑部署脚本，完事。

```bash
# 1. 下载发布包（单个 zip，零外部依赖）
wget https://github.com/user-attachments/files/32177070/wardennet.zip
unzip wardennet.zip

# 2. 一键部署 -- 自动检测 Nginx，生成配置，注册 systemd
sudo bash deploy.sh

# 3. 验证
wardennet status
```

压缩包里只有 4 个文件，没有其他依赖：

| 文件 | 用途 |
|------|------|
| wardennet_linux | Go 静态二进制，约 5.8MB |
| deploy.sh | 自动部署脚本（环境检测 + 配置生成） |
| wardennet.production.yaml | 生产配置模板 |
| AGENT_OPS.md | 运维手册 |

deploy.sh 完成后你会得到：
- systemd 服务 wardennet-agent 以 root 运行
- ipset wardennet_blacklist (hash:ip) + wardennet_whitelist (hash:net)
- iptables DROP 规则已关联黑名单
- CLI 命令 wardennet 全局可用

### 完整验证清单

```bash
# 服务存活
systemctl status wardennet-agent

# Agent 自检
wardennet status

# ipset 集合已创建
ipset list wardennet_blacklist
ipset list wardennet_whitelist

# iptables DROP 规则生效
iptables -S INPUT | grep wardennet
```

### 首次上线建议：观察者模式

新装？先用观察者模式——正常评分和日志，但不封禁。观察 24 小时确认评分合理后再切换：

```bash
# 切到观察者模式
sed -i 's/mode: block/mode: report/' /etc/wardennet/config.yaml

# 24 小时后切回 block
sed -i 's/mode: report/mode: block/' /etc/wardennet/config.yaml
```

Agent 每 5 秒自动热重载配置——不用重启服务。

---

## 从源码编译

想自己编译？任何系统一条命令搞定（CGO_ENABLED=0 产出完全静态二进制）：

```bash
cd agent
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \\
-w\ ./cmd/wardennet
```

完整的构建 + 部署流程、多架构（arm64）、开发模式见 [docs/quick-start.zh.md](./docs/quick-start.zh.md)。

---

## 架构概览

```
logparser -> detector -> ipsetutil -> ttl
     |           |            |
     v           v            v
tail 日志    基线自学习评分    快照持久化
                  |
                  v
           plugin.Plugin 接口
                  |
      libcloudplugin.so（可选用）
```

核心约束：**本仓库代码不直接 import cloudplugin 或发 HTTP 请求**。所有云端能力通过 plugin.Plugin 接口调用，无插件时自动降级为 NoopPlugin。Cloud SaaS 挂了？Agent 继续本地正常运行。

详细模块说明见 [docs/architecture.zh.md](./docs/architecture.zh.md)

---

## 核心特性

| 特性 | 说明 |
|------|------|
| 滑动窗口 + 基线自学习 | 三档独立窗口（10s / 30s / 60s）。评分偏离自动学习的 P95 基线，不预设绝对阈值 |
| 5 维一致性评分 | 前缀连贯度、路径集中度、状态同质性、方法语义、扫描行为——多维度联合判断，单维度封顶 + 置信度打折 |
| 多事件确认 + 新鲜度检查 | 高风险事件 >= 2 次才触发封禁，且攻击输入必须真的在演化。防止单次 token 过期 + 404 误触发 |
| 8 层防误杀 | 空 Referer 硬封顶、401 降权、已知 HTTP 客户端 UA 白名单、状态码关联、精确分段匹配、攻击模式解码、真实用户奖励、本地 IP 白名单 |
| 启动预扫描消除冷启动 | 自动扫描日志尾部最近 10 分钟数据，在真实流量到来前建立 P95 基线 |
| 内核级拦截 | ipset wardennet_blacklist (hash:ip) + iptables -I INPUT -m set --match-set DROP —— 零延迟零 CPU 开销 |
| 多日志源 | Nginx / Apache / Tomcat / Linux Auth（SSH）+ 自定义正则日志源 |
| 可选云端协同 | 编译时整合或 .so 动态加载 CloudPlugin，双层 Diff 同步、威胁评分综合决策、全局威胁情报 |
| 观察者模式 | mode: report 只评分上报，不封禁——适合上线初期安全过渡 |
| 静态单文件产物 | CGO_ENABLED=0 交叉编译，约 5.8MB，任何 Linux 通吃 |

---

## 效果数据

来自一台 2C4G Ubuntu 22.04（Hugo + Nginx）的真实数据：

| 指标 | 部署前（7天） | 部署后（7天） | 变化 |
|------|:-----------:|:-----------:|:----:|
| 独立扫描 IP 数 | 1,247 | 89 | **-92.9%** |
| 4xx 请求占比 | 37.2% | 4.8% | **-87.1%** |
| 扫描请求总数 | 53,210 | 1,230 | **-97.7%** |
| 误报数 | - | 0 | - |
| Nginx 平均响应时间 | 128ms | 94ms | -26.6% |
| WardenNet 内存 | - | 16.4 MB | - |
| WardenNet CPU | - | 0.3% | - |

---

## 项目状态

本仓库为**开源版 WardenNet Agent（部分开源）**。没有 CloudPlugin 时 Agent 完整运行于纯本地模式，所有防护能力不受影响——云端协同是纯可选的增强能力。

| 组件 | 许可 | 说明 |
|------|------|------|
| agent/（Go 核心 + 日志解析 + 检测引擎 + ipset 管理） | AGPLv3 | **本仓库内容** |
| agent/internal/cloudplugin/ | 闭源 | Cloud SaaS 对接实现，不包含在本仓库 |
| Cloud SaaS + Web 前端 | 闭源 | 商业 SaaS 平台，不开源 |

---

## 文档索引

| 文档 | 什么时候看 |
|------|----------|
| [快速开始](./docs/quick-start.zh.md) | 跑通第一个实例 |
| [架构总览](./docs/architecture.zh.md) | 理解各模块怎么协作 |
| [配置参考](./docs/configuration.zh.md) | YAML 所有字段详解 |
| [构建与部署](./docs/build.zh.md) | 编译参数、多架构、systemd |
| [CLI 命令手册](./docs/cli.zh.md) | Unix Socket CLI 全命令 |
| [贡献指南](./docs/contributing.zh.md) | 开发规范、红线、提交流程 |

---

## 系统要求

| 组件 | 最低要求 |
|------|---------|
| OS | Ubuntu 20.04+ / Debian 11+ / CentOS 7+ / RHEL 7+ |
| 运行时 | **不需要 Go**（静态产物）。开发编译需要 Go >= 1.27 |
| ipset | >= 6.x（apt install ipset） |
| iptables | >= 1.8.x |
| 权限 | Agent 需 root 运行（操作 ipset/iptables） |
| 内存 | >= 256 MB |
| 磁盘 | >= 1 GB（日志轮转） |

开发环境（Windows / macOS）：本地内存 Mock，不操作真实 ipset，go run ./cmd/wardennet 即可。

---

## 社区与反馈

- 问题和建议 -> GitHub Issues
- 贡献代码 -> 见 [docs/contributing.zh.md](./docs/contributing.zh.md)
- 欢迎提 PR（请先阅读贡献指南）

---

## License

WardenNet Agent 采用 **AGPLv3** 许可开源，详见 [LICENSE](./LICENSE)。闭源 CloudPlugin 和 Cloud SaaS 不属于本许可范围。
