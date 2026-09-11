---
marp: true
theme: default
paginate: true
---

<!-- _class: cover -->

# WardenNet 开源分布式Web服务器攻击IP联防平台

## 一处发现，全网御敌

**开源 Agent · 协同防御**

---

# 目录

1. 行业痛点
2. 产品介绍
3. 核心能力
4. 技术架构
5. 部署方式
6. 对比优势
7. 合规说明
8. 发展路线图
9. 开源社区

---

<!-- _class: invert -->

# 行业痛点

- 商业 WAF 昂贵，中小企业无力承担
- 传统开源脚本单机孤岛，无联防
- 攻击者集群打散流量，单机阈值失效

---

# WardenNet 是什么

- 基于 AI 的协同防御网络
- 开源 Agent + 闭源 Cloud SaaS
- 多节点交叉验证置信度

---

# 核心理念 — 协同防御

- 每台服务器都是哨兵
- 一台发现威胁，全网受益
- 置信度分级，防误封传染

---

<!-- _class: invert -->

# 系统架构

- **Agent 节点集群** + Cloud SaaS 中枢
- 虚线表示协同通信（加密双向鉴权）
- CloudPlugin：闭源插件层，负责网络协同

---

# 6 层防御体系

1. **L1 流量异常** — 基础行为检测
2. **L2 攻击特征** — 已知规则匹配
3. **L3 协同信号** — 跨节点情报汇聚
4. **L4 防误报** — 噪声过滤
5. **L5 防投毒** — 恶意情报隔离
6. **L6 快速处置** — 秒级响应

---

<!-- _class: invert -->

# AI 评分引擎

- **5 维一致性评分模型**
- 智能多信号融合决策引擎
  - 云端情报 + 本地行为 + 检测器评分
  - 动态权重分级处置
- 高危 → **BLOCK**
- 中危 → **ALERT**
- 低危 → **IGNORE**

---

# 技术亮点

- **Agent**：轻量 Go 单二进制，零依赖
- **CloudPlugin**：Go .so 插件，闭源网络层
- **智能同步引擎** 增量同步
- **安全双向鉴权**

---

# 3 步部署

```bash
cd agent && go build
cp configs/wardennet.yaml.example config.yaml
sudo wardennet -config config.yaml
```

---

<!-- _class: invert -->

# 对比优势

| 特性 | 商业 WAF | 开源脚本 | WardenNet |
|------|---------|---------|-----------|
| 价格 | 昂贵 | 免费 | 开源免费 |
| 协同防御 | 无 | 单机孤岛 | 多节点联防 |
| AI 评分 | 黑盒 | 无 | 透明可解释 |

---

# 合规说明 — 能力边界

✅ **覆盖场景**：
- 目录扫描、漏洞探测、后门爆破
- 小流量 CC、集群打散型 CC

❌ **不承诺**：
- SYN/UDP 洪水、DDoS 洪水（需云厂商高防）

---

# 发展路线图

- **v0.1 MVP** — Agent 基础检测
- **v0.4 当前** — CloudPlugin 完成，协同闭环
- **未来**：企业功能、私有化部署

---

<!-- _class: invert -->

# 开源社区

- GitHub 开源（占位 URL）
- **Agent**：AGPLv3
- **Cloud SaaS**：闭源

---

# 联系方式

- GitHub：`github.com/wardennet/agent`
- Email：`contact@wardennet.dev`

---

<!-- _class: cover -->

# 感谢聆听

## 一处发现，全网御敌

