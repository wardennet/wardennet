---
title: 深度解析 WardenNet：一个开源协同防御系统的检测机制与评分引擎设计
platform: 掘金 / CSDN
word-count: 2800
date: 2026-09
---

# 深度解析 WardenNet：一个开源协同防御系统的检测机制与评分引擎设计

> 当每一台服务器都成为哨兵，它们联合起来就是一支军队。

如果你的业务跑在公网，打开 Nginx access log 看看——一分钟内会有来自 30+ 国家的 IP 扫描你的 `/admin`、`/.env`、`/wp-login.php`。这些扫描器不攻击你的核心服务，只是默默爬行、探测、收集，直到某天找到一个零日漏洞。

传统的防御手段在面对这种"低烈度、广覆盖"的威胁时束手无策：**单机阈值会被慢速扫描器绕过，商业 WAF 的规则是静态的，开源脚本又会把正常爬虫一起封掉**。

这篇文章将深入解析一个开源项目 **WardenNet** 是如何用"协同防御"的思路破解这个困境的。我会从 Agent 架构、滑动窗口检测、6 层防御体系、5 维一致性评分，讲清楚它的智能多信号融合决策引擎，解释为什么单机可用、为什么云端协同更强。

---

## 一、架构总览：Agent 就是那个极轻量的哨兵

WardenNet 的核心设计思想很朴素：**每一台 Web 服务器旁边放一个轻量级 Agent，它们组成一张协同防御网络**。

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Agent Node  │     │  Agent Node  │     │  Agent Node  │
│  (Server A)  │────▶│  (Server B)  │────▶│  (Server C)  │
└──────┬───────┘     └──────┬───────┘     └──────┬───────┘
       │                     │                     │
       └─────────────────────┼─────────────────────┘
                             ▼
                   ┌─────────────────────┐
                   │   Cloud SaaS        │
                   │  (威胁情报 + 决策)   │
                   └─────────────────────┘
```

Agent 是一个用 Go 写的单二进制程序，**编译后极轻量**，没有外部依赖（iptables 和 ipset 除外）。它的职责非常聚焦：

1. **实时解析** Nginx/Apache/Tomcat 访问日志
2. **滑动窗口统计** 每个 IP 的行为特征
3. **多层评分** 判断是否为威胁
4. **内核级封禁** 把恶意 IP 写进 ipset（名称固定为 `wardenet_blacklist`）

值得强调的是：**即使没有云端连接，Agent 也能独立运行**——它内置了完整的本地检测引擎。云端协同只是给它"加了眼睛"，让它看到全网的威胁信号。

---

## 二、滑动窗口：从"总计数"到"形状感知"

传统防护脚本的典型做法是：统计过去 N 秒内某 IP 的请求总数，超过阈值就拉黑。这个方案有两个致命问题：

- **慢速扫描绕过**：扫描器把 QPS 压到阈值以下，拉长扫描窗口就能绕过
- **误杀真实用户**：突发访问（比如某个博主发了你的链接）会瞬间触发

WardenNet 用**三档独立滑动窗口**解决这个问题：

```yaml
detector:
  windows:
    - size: 10    # 10 秒窗口 → 捕捉突发扫描
    - size: 30    # 30 秒窗口 → 捕捉持续扫描
    - size: 60    # 60 秒窗口 → 捕捉慢速扫描
```

每个窗口独立维护 `request_count`、`4xx_ratio`、`unique_paths` 等计数器。评分不是看绝对值，而是看**偏离基线的倍数**——这就引入了 WardenNet 最精妙的设计之一：**基线自学习（Baseline Self-Learning）**。

Agent 启动时会自动扫描最近 10 分钟的日志尾部，为每个统计维度建立 P95 基线。运行中持续更新基线。评分变成了：

```
deviation_score = 当前值 / P95基线值
```

- `deviation_score = 1`：完全正常
- `deviation_score = 3`：比 95% 的历史请求还高 → 可疑
- `deviation_score = 10`：极端异常 → 高危

这个设计的精妙之处在于：**它不预设一个绝对阈值，而是让服务器自己告诉自己"什么是正常"**。同样是 QPS 500，对一个小博客来说是攻击，对一个电商首页刷新来说可能只是常态。

---

## 三、6 层防御体系：从流量统计到攻击意图

有了原始的偏离分数之后，WardenNet 还要经过 6 层防御机制来"过滤噪声、放大信号"：

| 层级 | 机制 | 解决什么问题 |
|:---:|------|-------------|
| **L1** | 流量异常检测 | QPS 突增、404 扫描比例 |
| **L2** | 攻击特征匹配 | Bot UA、敏感路径（`/.env`、`/admin`）、危险方法（CONNECT/TRACE） |
| **L3** | 协同信号分析 | 多特征关联（既是 Bot UA 又是敏感路径访问） |
| **L4** | 防误报机制 | 空 Referer 硬封顶、401 单独降权、已知 HTTP 客户端白名单 |
| **L5** | 防投毒机制 | 智能去重、QPS 限流、分数门槛（避免攻击者伪造大量假证据稀释评分） |
| **L6** | 快速响应机制 | 本地白名单绝对优先、ForceBlock 管理员强制封禁覆盖白名单 |

这里重点讲 L4 防误报和 L5 防投毒，这是 WardenNet 区别于其他开源脚本的核心差异。

### L4：空 Referer 为什么要封顶？

你可能注意到了：恶意扫描器**绝大多数是空 Referer**（因为它们根本不模拟浏览器跳转）。但正常的 curl、Postman 测试也会是空 Referer。如果简单把"空 Referer + 高 QPS"判为攻击，自己的运维同事就会被封禁。

WardenNet 的解法是**空 Referer 硬封顶**：即使其他维度再高，空 Referer 拿到的最高分数也被限制在 `score_high/4 ~ score_high/2` 之间。这样一来：

- 纯空 Referer 的扫描器很难触达拉黑阈值
- 但如果它同时有敏感路径命中（比如扫了 `/.env`），敏感路径的绝对权重会叠加进来

### L5：防投毒——为什么不能让攻击者伪造假证据？

假设一个攻击者已经被拉黑了，他可以伪造大量来自自己 IP 的"合法请求"证据上报云端——如果云端直接采信，其他节点也会跟着"解封"他。WardenNet 在证据上报前做了三件事：

1. **智能去重**：同一证据不能上报两次
2. **QPS 限流**：单 IP 每分钟上报证据不超过 10 条
3. **分数门槛**：上报的证据必须是 detector 评分 ≥ score_medium 的才有意义

---

## 四、5 维一致性评分：识别"不像人的行为"

滑动窗口和基线自学习能发现"偏离常态"的行为，但还回答不了一个问题：**这个高 QPS 的 IP，到底是个 bot 还是一个"勤奋"的真实用户？**

WardenNet 的答案是 **5 维一致性评分（Consistency Score）**。这个评分不依赖任何 header，只看 access log 必有字段（path、method、status）的排列形状：

| 维度 | 检测什么 | 为什么有用 |
|------|---------|-----------|
| **前缀连贯度** | 请求路径的第一段是否集中（比如都是 `/api/v1/...`） | 真实用户会在一个功能区停留；扫描器乱跳 |
| **新颖度饱和** | 前 30% 请求是否已覆盖大部分路径 | 真实用户探索完就停下；扫描器一直在发现新路径 |
| **路径集中度** | Top 5 路径的访问占比 | 真实用户反复访问几个核心页面；扫描器每次都扫新的 |
| **状态同质性** | 同一路径的状态码变异系数 | 扫描器扫一个不存在的路径会拿到连续 404；真实用户状态码分布更稳定 |
| **方法语义符合度** | GET/POST/PUT/DELETE 的比例 | 浏览器不会发出 DELETE 请求；扫描器可能乱试 |

每个维度命中加 2 分（前缀、新颖度、路径）或 1 分（状态、方法），总分 ≥ 4 判为 BENIGN（良性）。这意味着：

- 一个正常用户即使 QPS 偏高（比如热点内容传播），5 维评分也会拉他一把
- 一个扫描器即使把 QPS 压到基线以下，5 维评分也会暴露他"每条路径只扫一次"的发散型特征

来看看 Go 代码中的评分核心逻辑（简化伪代码）：

```go
// 5 维一致性评分核心逻辑
func scoreConsistency(history []pathRecord) int {
    score := 0
    
    // ① 前缀连贯度
    avgRunLen := calcAveragePrefixRunLength(history)
    dominantRatio := calcDominantPrefixRatio(history)
    if avgRunLen >= 3 || dominantRatio >= 0.50 {
        score += 2   // WeightPrefix
    }
    
    // ② 新颖度饱和
    earlyCoverage := calcEarly30Novelty(history)
    lateNovelty := calcLate30NoveltyRate(history)
    if earlyCoverage >= 0.70 && lateNovelty <= 0.40 {
        score += 2   // WeightNovelty
    }
    
    // ③ 路径集中度
    top5Coverage := calcTop5Coverage(history)
    if top5Coverage >= 0.25 {
        score += 2   // WeightPathConc
    }
    
    // ④ 状态同质性
    avgCV := calcAverageStatusCV(history)
    if avgCV < 0.6 {
        score += 1   // WeightErrors
    }
    
    // ⑤ 方法语义符合度
    getRatio := calcMethodRatio(history, "GET")
    unusualRatio := calcMethodRatio(history, "PUT|DELETE|PATCH")
    if getRatio >= 0.50 && unusualRatio < 0.05 {
        score += 1   // WeightMethod
    }
    
    // 反信号：反复撞墙扣 5 分
    if alwaysSame404OnProbe(history) {
        score -= 5
    }
    
    // 反信号：发散扫描额外扣 3 分
    if isHighlyNovelScanner(history) {
        score -= 3
    }
    
    return score
}
```

这段代码在 `agent/internal/detector/consistency.go` 中，完整实现约 600 行，包含了大量工程细节（ring buffer 存历史、参数化阈值、线程安全的 sync.Mutex）。

---

## 五、智能多信号融合决策引擎

到这里为止，我们讨论的都是**本地评分**。当 Agent 连接到 Cloud SaaS 后，还会收到来自全网的**云端威胁情报评分**（Cloud Score）。

WardenNet 采用自研加权决策模型融合三路信号：

- **Cloud**：全网威胁情报，该 IP 是否在其他节点也被标记为可疑
- **Local**：本地频率评分，该 IP 在当前服务器上的访问偏离程度
- **Detector**：检测器综合评分（含 5 维一致性修正后的最终分）

决策阈值：

- **≥ 80** → 拉黑（写入 `wardenet_blacklist` ipset）
- **≥ 50** → 告警（仅记录日志，不执行封禁）
- **< 50** → 忽略

权重可以由云端热更，但 Agent 端做了安全校验——拒绝极端投毒配置，防止云端被投毒后下发极端参数导致大规模误杀。

这背后的设计哲学是：**云端只下发评分，不下发封禁指令。最终决策权永远在 Agent 手里。** 这样即使 Cloud SaaS 挂了、被攻击了、被投毒了，单个 Agent 也不会成为一颗随时可以引爆的炸弹。

---

## 六、单机可用 vs 云端协同：为什么两者都重要？

**单机 Agent 为什么够用？**

- 基线自学习让它能识别偏离常态的行为，不需要预设规则
- 6 层防误报 + 5 维一致性评分把误报率压到很低
- 极轻量体积 + Go 编写 + 内核级封禁 → 极低资源占用（<1% CPU、几 MB 内存）

部署场景：个人博客、小型 API 服务、对安全要求不高的内网系统——单机 Agent 就能挡住 99% 的自动化扫描。

**云端协同为什么更强？**

- **打散型扫描识别**：扫描器把 QPS 分散到 N 台服务器上，单机看每台都只是"轻微偏离"，但云端聚合后能看到"同一 IP 1 分钟内扫了全网 500 个敏感路径"
- **威胁情报共享**：某台服务器新发现的攻击特征（比如新的 bot UA、新的敏感路径），其他所有节点立刻同步
- **三阶段特征架构**：内置默认值 + 用户 YAML 配置 + 云端威胁情报，动态合并去重

举个具体的例子：假设扫描器 X 同时扫描了 3 台服务器 A、B、C，每台 QPS 只有 30。

| 场景 | A 的评分 | B 的评分 | C 的评分 | 综合决策 |
|------|---------|---------|---------|---------|
| **单机模式** | Local=45, Detector=40 | Local=42, Detector=38 | Local=44, Detector=41 | 全部 < 50，**放过** |
| **云端协同** | Cloud=72, Local=45, Detector=40 → 综合风险≈58 | Cloud=72, Local=42, Detector=38 → 综合风险≈56 | Cloud=72, Local=44, Detector=41 → 综合风险≈57 | 全部 ≥ 50，**告警+拉黑候选** |

云端聚合了全网信号后，扫描器 X 的 Cloud Score 达到 72，即使单机评分只有 40 左右，综合分也能跨过阈值。

---

## 七、配置示例：极简上手

说了这么多原理，实际配置有多简单？下面是一个典型的 YAML 配置，**总共不到 50 行**，其余全部用程序内置默认值：

```yaml
agent:
  local_block_ttl: 3600      # 本地封禁 1 小时
  cloud_max_ttl: 86400       # 云端下发最长封禁 1 天

# 采集 Nginx 日志
log_sources:
  nginx_access:
    path: /var/log/nginx/access.log
    parser: nginx_access

# 基线自学习检测引擎
detector:
  enabled: true
  score_high: 50             # 达到 50 分触发封禁
  sensitivity: medium        # 偏离 5 倍即触发，推荐
  mode: block                # 生产环境用 block；上线初期可用 report（只观察不封禁）
  windows:
    - size: 10               # 三档滑动窗口
    - size: 30
    - size: 60

# 本地白名单
ipset:
  whitelist:
    - 127.0.0.1
    - 10.0.0.0/8             # 内网 CIDR，直接豁免
  blacklist: []               # 留空即可，动态封禁自动写入

# 可选：云端协同
cloud:
  enabled: true
  endpoint: "https://cloud.wardenet.com"
  agent_id: "your-agent-id"
  secret: "your-agent-secret"
```

编译 + 运行：

```bash
cd agent && go build -o wardennet ./cmd/wardennet
sudo cp wardennet /usr/local/bin/wardennet
sudo wardennet -config /etc/wardennet/config.yaml
```

---

## 八、写在最后

WardenNet 做的事情不复杂——它不承诺 DDoS 防御、不处理 SYN/UDP 洪水、不做带宽耗尽。它只聚焦一个场景：**HTTP 层的 Web 攻击防护**，包括目录扫描、漏洞探测、后门爆破、CC 类慢速请求。

但它用一套自洽的工程设计把这件事做到了极致：基线自学习消除了预设阈值，5 维一致性评分过滤了误报，三档滑动窗口覆盖了不同速率的扫描，自研加权决策模型让"本地+云端"协同成为可能而不引入单点风险。

**一处发现，全网御敌。** 这不是一句口号——它是 WardenNet 的核心设计原则。如果你也在运营公网服务器，不妨试试这个极轻量的开源哨兵。

> 开源地址：github.com/wardennet/agent
> Agent 许可：AGPLv3
> 云端 SaaS：闭源商业组件
