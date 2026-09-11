# WardenNet Agent

[![Go 1.27+](https://img.shields.io/badge/Go-1.27%2B-blue)](https://go.dev/)
[![License](https://img.shields.io/badge/License-AGPLv3-green)](./LICENSE)
[![Build mode](https://img.shields.io/badge/Build-static-steelblue)](./docs/build.zh.md)

**本地运行的滑动窗口恶意扫描防护引擎 — 在你的服务器上实时分析访问日志，自动将高危 IP 加入内核 ipset → iptables DROP 链，实现内核级零延迟拦截。**

[English README](./README.md) · [快速开始](./docs/quick-start.zh.md) · [架构总览](./docs/architecture.zh.md) · [配置参考](./docs/configuration.zh.md)

---

## 核心特性

- **滑动窗口 + 基线自学习**：三档滑动窗口（10s / 30s / 60s）覆盖瞬时突发与持续扫描；基线引擎自动学习各维度 P95 分布，偏离评分 0-100
- **5 维 Consistency 协同评分**：前缀一致性、路径集中、状态同质性、方法语义、扫描行为多维联合判断，单维度封顶 + 置信度打折 + 硬保底
- **多事件确认机制 + 新鲜度检查**：高风险事件 >= 2 次才触发拉黑，且必须是攻击输入真的在演化（防止单次 token 过期 + 404 误触发）
- **8 层防误杀**：空 Referer 硬上限、401 降权、已知 HTTP 客户端 UA 白名单、状态码关联、精确匹配、攻击模式解码、真实用户奖励、本地 IP 白名单
- **启动预扫描消除冷启动**：自动扫描日志尾部最近 10 分钟数据建立 P95 基线
- **内核级拦截**：`ipset wardennet_blacklist`（hash:ip）+ `iptables -I INPUT -m set --match-set DROP`，零延迟零 CPU 开销
- **多日志源支持**：Nginx / Apache / Tomcat / Linux Auth（SSH）+ 自定义正则日志源
- **云端协同（可选）**：编译时整合或 `.so` 动态加载 `libcloudplugin`，获得双层 Diff 同步、威胁评分综合决策、全局威胁情报
- **观察者模式**：`mode: report` 只评分上报，不封禁，适合上线初期安全过渡
- **静态单文件产物**：`CGO_ENABLED=0` 交叉编译，约 4MB，任何 Linux 通吃

---

## 项目状态

**本仓库为开源版 WardenNet Agent（部分开源）**。

| 组件 | 许可 | 说明 |
|------|------|------|
| `agent/`（Go 核心 + 日志解析 + 检测引擎 + ipset 管理） | AGPLv3 | 本仓库内容 |
| `agent/internal/cloudplugin/` | 闭源 | Cloud SaaS 对接实现，不包含在本仓库 |
| `cloud/`（Cloud SaaS + Web 前端） | 闭源 | 商业 SaaS 平台，不开源 |

没有 CloudPlugin 时 Agent 完整运行于纯本地模式，所有防护能力不受影响。

---

## 快速开始

### 编译（零依赖）

```bash
cd agent
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -o wardennet_linux -trimpath -ldflags="-s -w" ./cmd/wardennet
```

### 三步部署

```bash
# 1. 上传
scp wardennet_linux agent/configs/wardennet.production.yaml \
    agent/configs/wardennet-agent.service agent/deploy.sh \
    root@your-server:/tmp/

# 2. 一键部署
ssh root@your-server 'bash /tmp/deploy.sh'

# 3. 验证
wardennet status
```

### 最小配置

```yaml
log_sources:
  nginx_access:
    path: /var/log/nginx/access.log
    parser: nginx_access

detector:
  enabled: true
  score_high: 50
  sensitivity: medium   # high / medium / low
  mode: block           # block / report
```

完整配置项见 [docs/configuration.zh.md](./docs/configuration.zh.md)

---

## 架构概览

```
logparser -> detector -> ipsetutil -> ttl
     |           |            |
     v           v            v
tail 日志    基线自学习评分   快照持久化
                  |
                  v
           plugin.Plugin 接口
                  |
      libcloudplugin.so（可选用）
```

核心约束：**本仓库代码不直接 import cloudplugin 或发 HTTP 请求**，所有云端能力通过 `plugin.Plugin` 接口调用，无插件时自动降级为 NoopPlugin。

详细模块说明见 [docs/architecture.zh.md](./docs/architecture.zh.md)

---

## 文档索引

| 文档 | 适用场景 |
|------|----------|
| [快速开始](./docs/quick-start.zh.md) | 跑通第一个实例 |
| [架构总览](./docs/architecture.zh.md) | 理解各模块怎么协作 |
| [配置参考](./docs/configuration.zh.md) | YAML 所有字段详解 |
| [构建与部署](./docs/build.zh.md) | 编译参数、多架构、systemd |
| [CLI 命令手册](./docs/cli.zh.md) | Unix Socket CLI 全命令 |
| [贡献指南](./docs/contributing.zh.md) | 开发规范、红线、提交流程 |

---

## 系统要求

| 组件 | 要求 |
|------|------|
| OS | Ubuntu 20.04+ / Debian 11+ / CentOS 7+ / RHEL 7+ |
| Go | 开发编译 >= 1.27；运行时不需要 Go（静态产物） |
| ipset | >= 6.x（apt install ipset） |
| iptables | >= 1.8.x |
| 权限 | Agent 需 root 运行（操作 ipset/iptables） |
| 内存 | >= 256MB |
| 磁盘 | >= 1GB（日志轮转） |

开发环境（Windows / macOS）：本地内存 Mock，不操作真实 ipset，`go run ./cmd/wardennet` 即可。

---

## 社区与反馈

- 问题和建议 -> GitHub Issues
- 贡献代码 -> 见 [docs/contributing.zh.md](./docs/contributing.zh.md)
- 商业合作 -> WardenNet Cloud SaaS（闭源产品）

---

## License

WardenNet Agent 采用 **AGPLv3** 许可开源，详见 [LICENSE](./LICENSE)。闭源 CloudPlugin 和 Cloud SaaS 不属于本许可范围。