## WardenNet 与商业 WAF 的协同关系

### 一、核心结论

> **WardenNet 与商业 WAF 是互补关系，不是替代关系。** WardenNet 填补了商业 WAF 在行为分析、内核级处置和协同防御三个维度的空白。最专业的架构是「商业 WAF + WardenNet Agent」的串联防御体系。

---

### 二、先理解商业 WAF 的工作模式

商业 WAF（Web Application Firewall）本质是一种**反向代理**。流量路径决定了防护逻辑：

```
攻击者 IP → WAF 云端节点 → 你的 Nginx/Apache（源站）
              ↓                  ↓
         7 层内容检查          WardenNet 日志分析
```

| 部署模式 | 流量路径 | WAF 做了什么 | 日志里能看到什么 IP |
|---------|---------|------------|-------------------|
| **串联模式**（主流，如 Cloudflare、阿里云 WAF） | 所有流量先到 WAF 云端 | 在云端返回 403，**阻断非法请求到达源站** | `$remote_addr` 是 WAF 节点 IP，但 WAF 通常会注入 `X-Forwarded-For` / `CF-Connecting-IP` / `True-Client-IP` 等 header 携带真实攻击者 IP |
| **旁路模式**（少见，如镜像流量分析） | 流量直接到源站，WAF 只监控 | 只报警不拦截 | 攻击者真实 IP 直接出现在 `access.log` |

### 三、商业 WAF 的天然盲区

商业 WAF 擅长防御**已知特征的内容攻击**（第 7 层），但对以下场景存在结构性盲区：

| 盲区 | 原因 | WardenNet 如何填补 |
|------|------|-------------------|
| **高频撞库 / 慢速 CC** | WAF 按 QPS 或请求次数收费，若把海量代理 IP 放行，WAF 自身 CPU 和费用都会爆炸；若用全局 QPS 阈值，又会误伤合法业务突发 | WardenNet 部署在源站，**零流量费**。基于基线自学习（P95 偏离倍数），正常业务的 5x QPS 突发不会触发封禁，但扫描器每条路径只扫一次的发散模式会被识别并在**内核级**封禁 |
| **扫描行为检测** | WAF 只能看单次请求的内容，无法关联同一 IP 在 30s 内扫了多少个路径、状态码分布是什么 | WardenNet 三档滑动窗口（10s/30s/60s）+ 8 维相对特征偏差检测（路径分散度、404 比率、空 Referer 比率等），**行为形状识别**而非单次请求特征 |
| **集群打散型 CC** | 1000 台肉鸡每台只来 2-3 个请求，单 IP QPS 根本达不到 WAF 阈值 | WardenNet 云端协同（Cloud SaaS）聚合多节点情报，识别"每台肉鸡只扫一次但集群总数上千"的打散模式 |
| **攻击绕过 WAF** | 部分 WAF 规则可以被 URL 编码、Unicode/Hex 绕过、大小写混写等技巧绕过 | WardenNet 内置**危险攻击模式解码检测**（自动 URL/Unicode/Hex/HTML entity 解码后匹配），命中直接给顶格分 |
| **日志分析的业务层异常** | WAF 不知道你的 `/login` 接口正常用户输错密码是每分钟 2 次，还是每分钟 10 次——它无法建立你的业务基线 | WardenNet 基线自学习引擎**自动学习**各维度 P95 分布（包括密码错误频率、404 比率、路径集中度等），偏离倍数计算而非硬编码阈值 |
| **内核级封禁（ipset/iptables）** | 商业 WAF 封禁在云端，流量还要走 TCP 三次握手才能被返回 403 | WardenNet 在内核层**直接丢弃 SYN 包**，后续扫描流量根本不进你的 Nginx，不占你的带宽和连接数 |

### 四、WAF 串联场景下 WardenNet 是否还有效？

**有效。** WardenNet 已实现真实 IP 提取能力，优先级：

```
CF-Connecting-IP  →  True-Client-IP  →  X-Forwarded-For  →  remote_addr（直连）
     ↑                      ↑                    ↑                ↑
  Cloudflare 专用       部分 SaaS WAF 用      主流行业标准      没有 WAF 的场景
```

Nginx 配置示例（让 WardenNet 在串联 WAF 模式下拿到真实攻击者 IP）：

```nginx
# 在 nginx.conf http 块添加
log_format wardennet '$remote_addr - $remote_user [$time_local] '
                     '"$request" $status $body_bytes_sent '
                     '"$http_referer" "$http_user_agent" '
                     '"$http_x_forwarded_for" "$http_cf_connecting_ip" "$http_true_client_ip"';

access_log /var/log/nginx/access.log wardennet;
```

**但有一个前提：** 你需要在 WAF 控制台开启 "真实 IP header 透传"（Cloudflare 默认开启，阿里云 WAF 需要手动配置）。如果 WAF 把 `X-Forwarded-For` / `CF-Connecting-IP` 等 header strip 掉了，WardenNet 只能看到 WAF 节点 IP，封禁的反而会把 WAF 自己挡在外面。**部署前务必验证 header 是否透传。**

### 五、WardenNet 旁路模式场景

如果你没有用商业 WAF，流量直接到源站——这是 WardenNet 的**原生设计场景**，`$remote_addr` 就是攻击者真实 IP。所有检测机制（基线自学习、三档滑动窗口、危险模式解码、内核级封禁）都能在最干净的环境下工作。

### 六、最佳实践：三层串联防御

```
┌─────────────────────────────────────────────────────────┐
│ 第一层：商业 WAF（云端）                                  │
│ 职责：拦截已知特征的内容攻击（注入/XSS/木马上传）           │
│ 产物：安全基线，消除绝大多数低挂果实扫                     │
│                                                          │
│ ┌───────────────────────────────────────────────────────┐ │
│ │ 第二层：WardenNet Agent（源站内核级）                    │ │
│ │ 职责：基线自学习 + 行为形状识别 + ipset 封禁            │ │
│ │ 填补：WAF 盲区（扫目录、高频撞库、慢速 CC、绕过 WAF 的  │ │
│ │       攻击、404 风暴、后门爆破）                         │ │
│ │ 关键：WardenNet 看到的是「经过 WAF 放行后」的流量——       │ │
│ │       这些流量的「行为形状」更干净，基线学习更准确         │ │
│ │                                                       │ │
│ │ ┌─────────────────────────────────────────────────────┐ │ │
│ │ │ 第三层：WardenNet Cloud SaaS（协同层）                  │ │ │
│ │ │ 职责：多节点情报聚合 + 协同决策 + 全局黑名单同步          │ │ │
│ │ │ 填补：集群打散型 CC（单机看每台肉鸡只来 2 请求，       │ │ │
│ │ │       但云端看总量上千）                                  │ │ │
│ │ └─────────────────────────────────────────────────────┘ │ │
│ └───────────────────────────────────────────────────────┘ │
│                                                          │
│ 内核层：ipset/iptables 直接丢弃已封禁 IP 的 SYN 包         │
└─────────────────────────────────────────────────────────┘
```

### 七、与其他替代方案的对比

| 对比维度 | 商业 WAF | 传统开源脚本（fail2ban 等） | WardenNet |
|---------|---------|--------------------------|-----------|
| 部署位置 | 云端（源站前面） | 源站 | 源站 |
| 检测层 | 第 7 层（内容） | 第 7 层（硬编码规则） | 第 4 + 7 层（行为 + 内容） |
| 封禁位置 | 云端返回 403 | 源站内核 | 源站内核 |
| 检测逻辑 | 规则库 + URL 解码 | 硬编码正则 + 固定阈值 | 基线自学习 P95 偏离 + 危险模式解码 |
| 阈值策略 | 固定（QPS 计费） | 固定（如 60 次/分钟） | 动态基线自动学习 + 灵敏度分档（high/medium/low） |
| 协同能力 | 有（但闭源） | 无（单机孤岛） | 云端协同 Diff 同步 + 多节点交叉验证 |
| 防误杀 | 一般（固定规则无法适配业务） | 差（易封正常 IP） | 8 层防误杀 + Consistency 行为降权 gate |
| 误报控制 | 依赖规则库质量 | 几乎无 | 成熟的降权机制 + 白名单 + 真实 IP 提取 |
| 费用 | 数千～数万/月 | 免费 | Agent 开源免费（单机）+ Cloud SaaS 增值 |
| 资源占用 | 独立硬件/大 VM | 轻量 | 轻量 Go 单二进制 · 内核级封禁 |

### 八、常见误解澄清

**误解 1：用了 Cloudflare 就不需要 WardenNet 了**
→ Cloudflare 防内容攻击（注入/XSS），但扫目录、高频撞库、慢速 CC 这些行为攻击是 Cloudflare 的盲区。Cloudflare 有 Bot Management 但贵，WardenNet 用 P95 偏离检测免费解决。

**误解 2：WAF 串联时 WardenNet 看不到攻击者 IP**
→ WardenNet 实现了真实 IP 提取：CF-Connecting-IP > True-Client-IP > X-Forwarded-For > remote_addr。串联 WAF 时只要 header 透传就能拿到真实 IP。**部署前务必验证 WAF header 配置**。

**误解 3：WardenNet 会和 WAF 打架，重复封禁**
→ 不会。WardenNet 封禁的是「WAF 放行后仍然表现异常」的 IP。WAF 已经拦下来的请求不会出现在 access.log 里，WardenNet 根本看不到它们。

**误解 4：商业 WAF 太贵，但开源脚本够用**
→ 传统开源脚本（fail2ban 等）用的是硬编码阈值（如"60 次/分钟"），正常业务 QPS 突增很容易被封。WardenNet 基线自学习自动适配你的业务水位。

---

### 九、一句话总结

> **商业 WAF 是你的门卫，WardenNet 是你的神经中枢。** WAF 拦的是"一看就不是好人"的内容攻击；WardenNet 分析每个 IP 的**行为形状**，在源站内核层精准封禁那些"动作变形"的攻击者。两者不在一个维度，是黄金搭档。
