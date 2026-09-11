# WardenNet 完整实现逻辑文档

> 生成时间：2026-09-07
> 文档状态：v1.0

## 一、系统总览

WardenNet 是一套**"本地即时拦截 + 云端联防协同"**的网络威胁防御系统，由两个子系统组成：

| 子系统 | 语言 | 职责 |
|--------|------|------|
| **Agent** | Go | 部署在受保护服务器上，实时监控访问日志 → 滑动窗口检测 → 本地即时拉黑 |
| **Cloud** | Python + React | SaaS 云端，聚合多租户威胁情报 → 交叉验证 → 下发威胁评分 |

### 核心架构理念

> **云端只给评分，Agent 做最终决策。**
> 杜绝云端被投毒导致大规模误杀真实用户。

---

## 二、Agent 端实现

### 2.1 启动流程（16 步串联）

入口：`agent/cmd/wardennet/main.go`

```
Step 1   ──► 加载 YAML 配置（config.Loader）
Step 2   ──► 初始化结构化日志器（zap/rotatelogs）
Step 3   ──► 初始化 ipset 管理器
             ├─ Linux：真实 ipset + iptables
             └─ 其他平台：MemClient（Mock）
             ├─ 加载本地白名单
             └─ 预加载本地黑名单（断网兜底）
Step 4   ──► 初始化 TTL 管理器（自动过期）
Step 5   ──► 初始化统计收集器
Step 5.1 ──► 初始化滑动窗口检测引擎（Detector）
Step 5.2 ──► 设置详情日志记录器
Step 5.3 ──► 可选增强模块注入
             ├─ BodyScanner（请求体扫描）
             └─ ResourceBaseline（IDOR 越权检测）
Step 6   ──► 初始化日志解析器 Registry
Step 6.1 ──► 预扫描历史日志建立初始基线（消除冷启动）
Step 7   ──► 注册 CLI 命令（blocklist/status 等）
Step 8   ──► 启动 UnixSocket 服务端（本地命令通道）
Step 9   ──► 初始化快照管理器
Step 10  ──► 尝试从快照恢复（ignore first-start）
Step 11  ──► 加载 Cloud 插件
             ├─ -tags=plugin：编译进主程序
             ├─ 默认构建：plugin.Open(.so) 动态加载
             └─ 加载失败：NoopPlugin（离线模式）
Step 11.1──► 启动 CloudSync 调度引擎
             ├─ Plugin.Init → Auth（指数退避重试）
             ├─ heartbeatLoop（每 5min）
             ├─ diffLoop（每 10min）
             └─ commandLoop（每 2min）
Step 11.2──► 启动 ThreatReporter（威胁事件上报）
Step 12  ──► 启动配置热重载 Watch（5s 轮询）
Step 13  ──► 启动多源日志 tail goroutine
Step 14  ──► 启动事件处理循环（Event → Detector.Process）
Step 15  ──► 启动定期统计报告 goroutine
Step 16  ──► 等待 SIGINT/SIGTERM，优雅关闭
```

### 2.2 日志解析（logparser）

**包路径**: `agent/internal/logparser/`

#### 支持的日志源

| 解析器名称 | 日志类型 | 说明 |
|-----------|---------|------|
| `nginx_access` | Nginx access log | Combined / Custom format |
| `apache_access` | Apache access log | Common / Combined |
| `tomcat_access` | Tomcat access log | pattern 格式 |
| `linux_auth` | /var/log/auth.log | SSH/FTP 登录事件 |
| `custom` | 用户自定义正则 | 支持任意格式，RegexGroups 映射字段 |

#### 核心数据流

```
日志文件 → Tail（逐行读取 + 去重）→ Parser.Parse → logparser.Event → detector.Event
                │
                ├─ 文件位置记录（重启续读）
                ├─ 丢弃计数（统计背压）
                └─ panic recover（单源崩溃不影响其他）
```

#### Event 字段映射

```go
type Event struct {
    SourceIP, EdgeIP, ClientIPFrom  // Cloudflare/代理双 IP 识别
    Method, Path, Status, BytesSent
    UserAgent, Referer
    AuthAction                       // linux_auth 专属
    Body, ContentType, FileName, FileExt, FileMime  // v1.0 新增
    LocalRiskScore                   // detector 回填
    Timestamp
}
```

### 2.3 滑动窗口检测引擎（detector）

**包路径**: `agent/internal/detector/`

#### 三档滑动窗口架构

```
时间轴：  ───────────────────────────────────────────────────►

窗口1:  [========10s========]  高频行为检测（瞬态突发）
窗口2:  [==============30s==============]  中程行为分析
窗口3:  [============================60s============================]  宏观模式识别
```

每个窗口独立维护 per-IP 的计数器：

```go
type WindowCounters struct {
    TotalReq              // 总请求数
    Count4xx, Count401, Count5xx, Count404, AuthFail
    SensitivePathHit      // 敏感路径访问
    DangerousPatternHit   // 危险攻击模式命中（解码后）
    BotUAHit              // 扫描器/爬虫 UA
    EmptyRefererHit       // 空 Referer
    DangerousMethod, HeadMethod
    StaticResHit, NormalBrowserHit
    Distinct4xxPaths      // 不同的 4xx 路径数
    FileUploadBlocked     // 文件上传拦截
}
```

#### 窗口记录触发点

`window.go` 中 `Record()` 方法在 `detector.Process()` 调用链中被触发，执行：

1. 跳过 loopback IP（127.0.0.0/8 + ::1）
2. 跳过 SkipPaths（/favicon.ico, /robots.txt, /.well-known/ 等）
3. 调用 BodyScanner（若注入）处理请求体
4. 更新 ipEntry 的三个窗口计数器
5. 调用 Consistency 行为序列记录（pathHistory ring buffer）

#### ipEntry 数据结构

```go
type ipEntry struct {
    counters [3]WindowCounters   // 三档窗口
    lastSeen int64
    // v1.2 新增：一致性模型所需的路径历史环形缓冲区
    pathHistory []PathNode        // 最近 N 条路径（带 timestamp、status、method）
}
```

### 2.4 打分机制（scorer）

**包路径**: `agent/internal/detector/scorer.go`

#### 核心理念

> **多维度协同，没有任何单一维度能独立触发封禁。**

#### 相对特征 vs 绝对特征

| 类型 | 计算方式 | 示例 |
|------|---------|------|
| **相对特征** | `deviation(当前值, 基线P95)` → `deviationToScore()` | QPS 突发、4xx 比率偏离 |
| **绝对特征** | `命中次数 × 固定权重` | DangerousPattern × 5、FileUpload × 20 |

#### 相对特征评分链路

```go
// 1. 计算偏离倍数
qpsDev = 当前QPS / 基线P95

// 2. 转换为分数（分段函数）
deviationToScore(qpsDev, sensitivity):
  dev ≥ 10  → +ScoreHigh × 0.6
  dev ≥ 5   → +ScoreHigh × 0.4
  dev ≥ 2   → +ScoreHigh × 0.2
  dev ≥ 1.5 → +ScoreHigh × 0.1
  dev < 1.5 → 0

// 3. 基线置信度不足时 QPS 分打 5 折
// 4. 纯 QPS 尖峰且无攻击特征 → QPS 分再打 3 折
//    （有 DangerousPattern/BotUA/DangerousMethod/FileUpload 就不打折）
```

#### 真实用户奖励（扣分项）

```go
bonus = StaticResHit × 3 + ValidReferer
// 纯浏览器 + 静态资源 → 404 额外扣 bonus（50% 比例）
// legitimateUserContext → bonus 再 × 1.5
```

#### legitimateUserContext 判断

```go
// 条件：浏览器纯净度 ≥ 95% + 无致命攻击特征 + 无高偏差
noFatalAttack = (DangerousPatternHit == 0 && DangerousMethod == 0 && FileUploadBlocked == 0)

if bp >= 95%:
    noAttackFeature = (
        BotUARatio ≤ 3% 且 BotUA ≤ 5 &&
        SensPathRatio ≤ 2% 且 SensPath ≤ 3 &&
        AuthFailRatio ≤ 2% 且 AuthFail ≤ 3
    )
else:
    noAttackFeature = (BotUAHit == 0 && SensitivePathHit == 0 && AuthFail == 0)

legitimateUserContext = NormalBrowserHit > 0 && TotalReq >= 3 && noAttackFeature
                      && qpsDev < 40/100/200（sensitivity 决定）
                      && rate4xxDev < threshold
                      && rate404Dev < threshold

// 触发后：rate4xxScore 和 rate404Score 均降为 1/10
```

#### 多维度协同封顶

```go
// 1. 单维度上限：相对维度最多贡献 ScoreHigh × 60%
relCap = ScoreHigh * 0.6

// 2. 统计活跃相对维度数 activeRelDims

// 3. 单维度封顶：仅 1 个活跃相对维度 + 无绝对特征 → 封顶 ScoreMedium
if activeRelDims <= 1 && absScore == 0:
    relScore = min(relScore, ScoreMedium)

// 4. 组合触发提升：BotUA + SensitivePath ≥ 3 → 强制提升 BotUA/SensPath 分数
if BotUAHit > 0 && SensitivePathHit >= 3:
    BotUAScore = max(BotUAScore, relCap × 0.6)
    SensPathScore = max(SensPathScore, relCap × 0.6)

// 5. 最终分数
finalScore = min(relScore + absScore - bonus, ScoreHigh × 2)
```

#### 低置信度永不封禁

```go
if finalScore >= ScoreHigh:
    anyConfident = any(baseline.IsConfident(CONFIDENCE_MIN_FOR_BLOCK) for baseline in baselines)
    if not anyConfident:
        finalScore = ScoreHigh - 1  // 降级，避免基线不可信时误杀
```

#### 分数上限与阈值

```go
ScoreHigh = 50    // 高分阈值（触发封禁候选）
ScoreMedium = 30  // 中等风险阈值
ScoreLow = 10     // 低风险阈值（记录但不告警）

// finalScore = Scorer.ScoreWithDetail() 取三档窗口最高分
```

### 2.5 基线自学习（baseline）

**包路径**: `agent/internal/detector/baseline.go`

#### 三档 Baseline 并行

```
窗口1 (10s)  → Baseline[0]
窗口2 (30s)  → Baseline[1]
窗口3 (60s)  → Baseline[2]
```

#### BaselineDimensions 分位数追踪

```go
type BaselineDimensions struct {
    QPS          Percentile  // P50/P95/P99
    Rate4xx      Percentile
    Rate5xx      Percentile
    Rate404      Percentile
    RateAuthFail Percentile
    RateSensPath Percentile
    RateBotUA    Percentile
    RateEmptyRef Percentile
    RateHeadMethod Percentile
}
```

#### 更新机制

```
后台 goroutine（每 10s）:
  ├─ 遍历 SlidingWindow 的 AllCounters()
  ├─ 计算全局 QPS P95 / 4xx P95 等分位数
  └─ 调用 Baseline.Update(dims) → 滚动更新分位数

置信度计算:
  confidence = min(1.0, sampleCount / REQUIRED_SAMPLES)
  初始 sampleCount=0，Preload 或 5min 运行后自然达标
```

#### 冷启动预扫描（PreloadFromLogFile）

```
启动时预扫描历史日志（最多 50 万行）:
  1. 按 5min 时间桶分组
  2. 过滤健康桶（请求量 ≥ 50% 中位数，排除凌晨低峰）
  3. MAD 方法剔除 QPS 极端桶（扫描器/爬虫/batch sync）
     threshold = median + 5 × MAD
  4. 从健康桶计算 QPS/4xx/404/AuthFail 的 P50/P95/P99
  5. 直接设置三个窗口的 baseline dims + ForceReady()
  6. confidence = 健康桶数 / 总桶数

效果: 消除 5 分钟冷启动期，基线从一开始就处于就绪状态
```

### 2.6 5 维一致性模型（consistency）

**包路径**: `agent/internal/detector/consistency.go`

#### 定位：反误伤防御层

> **如果一个 IP 的行为序列形状明显是正常用户（BENIGN），但 Scorer 因为基线偏差给了高分，把它降权到 ScoreMedium——让多事件确认机制去处理，真正的攻击会持续触发 shouldBlock，合法 API 客户端的突发会被时间窗口稀释。**

#### 五维正向信号

| 维度 | 说明 | 判定方法 |
|------|------|---------|
| **前缀连贯度** | 路径前缀变化平滑 | `pathHistory` 中相邻节点的 path 编辑距离 |
| **新颖度饱和** | 正常用户也会访问多个路径 | 去重后的 distinctPaths 数量处于合理范围 |
| **路径集中度** | 真实扫描器会发散访问 | `distinctPaths / totalRequests` 比率 |
| **状态同质性** | 正常用户状态码均匀分布 | 2xx/4xx/5xx 比率的熵值 |
| **方法语义** | GET 为主，偶尔 POST | 方法分布偏离度 |

#### 反信号（触发后降低 BENIGN 判定）

| 反信号 | 说明 |
|--------|------|
| 反复撞墙 | 短时间内同一 4xx 路径重复出现 |
| 单路径撞墙 | 集中在极少数路径的 4xx |
| 发散扫描 | distinctPaths 远超正常阈值 |

#### 决策逻辑

```go
scRes = window.ComputeConsistency(ip)
if scRes.HasSamples && scRes.IsBenign && finalScore >= ScoreHigh:
    finalScore = ScoreMedium  // 降权
```

#### ConsistencyThresholds 配置（YAML 可配）

```yaml
detector:
  consistency:
    enabled: true
    history_capacity: 50        # 每 IP 保留的路径历史条数
    observe_window_sec: 120     # 一致性分析的时间窗口
    benign_score_threshold: 4   # 累计得分 ≥ 4 判定为 BENIGN
    prefix_coherence_weight: 1.0
    novelty_saturation_weight: 1.0
    path_concentration_weight: 1.0
    status_homogeneity_weight: 1.0
    method_semantics_weight: 1.0
    anti_repeat_wall_penalty: 2.0
    anti_single_path_wall_penalty: 2.0
    anti_divergence_penalty: 2.0
```

### 2.7 多事件确认机制

**包路径**: `agent/internal/detector/detector.go` → `shouldBlock()`

#### 设计思想

> **单一高分不可怕，持续威胁才是真攻击。**

#### 核心流程

```
Detector.Process(ev)
  │
  ├─ 白名单命中 → score=0，跳过
  ├─ loopback IP → score=0，跳过
  ├─ SkipPaths → score=0，跳过
  │
  ├─ Window.Record
  ├─ ResourceBaseline.Check（可选）
  ├─ Scorer.ScoreWithDetail → finalScore
  ├─ Consistency.Compute → BENIGN 降权
  │
  ├─ isHigh = finalScore >= ScoreHigh
  │
  ├─ 如果 isHigh:
  │   │
  │   ├─ Mode == "report" → 不封禁
  │   │
  │   ├─ highConfidence = computeHighConfidence(details)
  │   │   // 致命攻击特征直接封，跳过观察名单：
  │   │   //   DangerousPatternScore > 0
  │   │   //   DangerousMethodScore > 0
  │   │   //   FileUploadBlockedCount > 0
  │   │   //   BotUAScore > 0 且 非 legitimateUserContext
  │   │
  │   └─ shouldBlock(ip, highConfidence, timestamp)
  │       ├─ highConfidence=true → 直接封禁（清除观察记录）
  │       ├─ highConfidence=false → 走观察名单
  │       │   ├─ 首次 → 加入观察名单，count=1 → 不封
  │       │   ├─ 合并窗口内（5s）连续触发 → 只刷新时间，不加计数
  │       │   ├─ 观察窗口过期（30s）→ 重置 count=1
  │       │   └─ count >= 2 → 清除观察记录，本次触发封禁 ✅
  │       └─ ConfirmCount <= 1 → 关闭确认，直接封（向后兼容）
```

### 2.8 BodyScanner（请求体扫描）

**包路径**: `agent/internal/detector/body_scanner.go`

```
扫描类型:
  ├─ JSON/Form 参数解码 → DangerousPattern 匹配（SQLi/XSS/RCE 正则）
  ├─ XXE 检测（DOCTYPE + ENTITY 声明）
  └─ 文件上传拦截
      ├─ 扩展名黑名单（.php, .phtml, .jsp, .asp）
      ├─ MIME type 黑名单
      └─ 双层验证（扩展名 + Content-Type）

权重: FileUpload × 20（权重最高，单次即可触发高分）
```

### 2.9 ResourceBaseline（IDOR/BOLA 越权检测）

**包路径**: `agent/internal/detector/resource_baseline.go`

```
原理: 在配置的时间窗口内，一个 IP 访问同一资源模式的不同 ID 超过 MaxIDs 阈值
配置示例:
  patterns:
    - path_regex: "/api/users/\\d+"
      id_regex: "(\\d+)"
      window_sec: 300
      max_ids: 5
      weight: 30

scoreIDOR = weight × (distinctIDs - maxIDs + 1)
finalScore = min(ScoreHigh, scoreHTTP + scoreIDOR)
```

### 2.10 ipset 黑名单管理

**包路径**: `agent/internal/ipsetutil/manager.go`

#### ipset 集合定义

```
wardenet_blacklist  (hash:net)  // 黑名单（CIDR 支持 IPv4/IPv6）
wardenet_whitelist  (hash:net)  // 白名单（租户自己管理，绝对优先）
```

#### 业务规则优先级

```
本地白名单配置  >  云端租户白名单  >  云端全局黑名单  >  本地黑名单配置
     │                    │                    │                │
     └─ ForceBlock CLI    └─ Agent ApplyCloud  └─ DiffService └─ cfg.IPSet.Blacklist
```

#### Block() 方法链路

```go
Block(ip):
  1. isValidIP(ip)? → ErrInvalidIP
  2. IsLocalWhitelisted(ip)? → ErrWhitelisted（被豁免）
  3. blockInternal(ip)
     ├─ blocked[ip] 已存在？→ ErrAlreadyBlocked（幂等跳过）
     ├─ client.Apply(ADD, wardenet_blacklist, ip/32 or ip/128)
     │   └─ retry 3 times，每次间隔 200ms
     └─ blocked[ip] = struct{}{}
```

#### ApplyCloud() 双层 Diff 应用

```go
ApplyCloud(entries):
  1. 过滤：云端黑名单命中本地白名单 → filtered（反馈给云端）
  2. 两级写入策略：
     ├─ 第一级：批量写入（client.Apply 一次性提交）
     └─ 第二级：批量失败时降级为逐条写入，跳过失败条目
  3. 更新内存 blocked/whitelisted map
```

### 2.11 TTL 过期管理

**包路径**: `agent/internal/ttl/manager.go`

```
Entry:
  IP, Source (Local/Cloud), TTL, ExpiresAt, CreatedAt

TTL 值:
  LocalBlockTTL = 3600s (1h)     // 本地 detector 封禁
  CloudBlockTTL = 7200s (2h)     // 云端下发的 TTL 上限

清理:
  后台 goroutine 每 5s 扫描过期条目
  过期 → ipset DEL + 从 blocked map 移除
```

### 2.12 快照恢复

**包路径**: `agent/internal/snapshot/manager.go`

```
state.json 内容:
  ├─ version
  ├─ ttl.entries: [{ip, source, expires_at, created_at, ttl}]
  └─ detector 基线状态

启动时: LoadAndRestore() → 恢复 TTL + 跳过过期条目
关闭时: Save() → 持久化 TTL

效果: Agent 重启后 TTL 不丢失，已过期的自动清除
```

### 2.13 云端插件架构

**包路径**: `agent/internal/plugin/` + `agent/internal/cloudsync/`

#### Plugin 接口（13 个方法）

```go
type Plugin interface {
    // 生命周期
    Init(agentID, version string) error
    Shutdown() error
    Health() (ok bool, msg string)

    // 鉴权
    Auth(ctx AuthContext) (AuthResult, error)
    Heartbeat() (needDiff bool, err error)

    // 数据上报
    Report(events []ReportEvent) error
    ReportFull(events interface{}) error  // V2 完整上报

    // Diff 同步
    Diff(req DiffRequest) (DiffResult, error)
    FetchFullGlobalSnapshot() (GlobalSnapshot, error)
    FetchTenantSnapshot() (TenantSnapshot, error)

    // 远程指令
    HandleCommand(cmd RemoteCommand) (CommandResult, error)
    FetchPendingCommands() ([]RemoteCommand, error)

    // 特征库
    FetchFeatures(tenantID string, currentVersion int64) (*FeatureResult, error)
}
```

#### 插件加载策略

```
构建方式        插件来源                          无插件时
─────────────────────────────────────────────────────────────
默认构建        libcloudplugin.so (plugin.Open)   NoopPlugin
-tags=plugin    CloudPlugin 编译进主程序           NoopPlugin
静态构建        CGO_ENABLED=0 + -tags=plugin       NoopPlugin

NoopPlugin 行为:
  Diff() → OK=true + 全空（同步 goroutine 认为无变更）
  Report() → 静默丢弃，不阻塞 detector
  Heartbeat() → (false, nil)
```

#### SyncEngine 三层循环

```
heartbeatLoop (每 HeartbeatInterval=5min):
  Plugin.Heartbeat() → needDiff? → 立即触发 Diff 不等下一个周期

diffLoop (每 SyncInterval=10min):
  ┌─ Plugin.Diff(DiffRequest{agentID, tenantID, globalBase, globalSeq, tenantSeq})
  │
  ├─ 全局层:
  │   ├─ NeedBase=true → FetchFullGlobalSnapshot + DecideAll → applyDecisions
  │   └─ IncrList → DecideAll 每个增量 → applyDecisions
  │
  ├─ 租户层:
  │   ├─ FullSync=true → FetchTenantSnapshot + DecideAll + applyDecisions
  │   └─ ThreatScoring → DecideAll → applyDecisions
  │
  ├─ 租户白名单（直接应用，不经过决策）
  │
  └─ 更新 globalBase / globalSeq / tenantSeq 版本号

commandLoop (每 CommandInterval=2min):
  Plugin.FetchPendingCommands() → Plugin.HandleCommand()
```

---

## 三、Cloud 云端 SaaS 实现

### 3.1 数据库模型

**包路径**: `cloud/app/db/models.py`

#### 核心表结构

| 表名 | 作用 | 关键字段 |
|------|------|---------|
| `tenants` | 租户信息 | id, plan(free/paid), reputation_score |
| `agents` | Agent 节点 | agent_id (PK), tenant_id (FK), hostname, secret, last_heartbeat |
| `evidences` | 威胁证据包 | evidence_uuid, agent_id, tenant_id, events(JSON), signature_verified |
| `agent_nonces` | Nonce 防重放 | nonce (PK), agent_id, created_at（60s TTL） |
| `threat_votes` | 租户投票 | (tenant_id, attack_ip) PK, is_paid, vote_weight, source_asn |
| `threats_private` | 私有情报池 | (tenant_id, attack_ip) PK, score, expires_at（24h TTL） |
| `threats_global` | 全局共享池 | attack_ip (PK), aggregate_score, vote_count, expires_at（72h TTL） |
| `whitelist` | 白名单 | id (PK), ip, tenant_id(nullable=全局), is_permanent |
| `blacklist` | 黑名单 | ip (PK), reason, expires_at |
| `commands` | 远程命令 | id (PK), agent_id, status(pending/acked), expires_at |
| `diff_changelog` | Diff 变更日志 | id, scope(global/tenant), tenant_id, version, change_type |
| `diff_meta` | Diff 元数据 | key (global_base/global_incr_counter), value_str/int |
| `features` | 特征库 | key (PK), value, category, enabled |
| `anti_poison_alerts` | 防投毒告警 | id (PK), alert_type, severity, evidence_json |

### 3.2 Agent 鉴权四重校验

**包路径**: `cloud/app/security/auth.py`

#### API 请求签名规则

```
message = nonce + timestamp + agent_id + sha256(body) + events_digest
signature = HMAC-SHA256(secret, message)
```

#### 中间件校验流程

```python
auth_middleware(request):
    # 从 Header 提取
    X-Agent-Id, X-Signature, X-Timestamp, X-Nonce

    agent = agent_repo.get_by_id(X-Agent-Id)

    # 校验 1：Nonce（一次性 + 60s TTL）
    if X-Nonce:
        nonce_service.verify_and_consume(X-Nonce, X-Agent-Id)

    # 校验 2：时间戳（±60s 偏差）
    abs(now - timestamp) <= 60

    # 校验 3：Events Digest（WARDENNET_DIGEST_V1 私有算法）
    events_digest = _compute_events_digest_inner(events)
    hmac.compare_digest(client_digest, events_digest)

    # 校验 4：HMAC 签名
    verify_signature(agent.secret, agent_id, timestamp, signature, nonce, body_hex, events_digest)
```

#### WARDENNET_DIGEST_V1 私有摘要算法

```python
def compute_events_digest(events):
    # 对 ReportEvent.Payload 内层 FinalThreatPayload 对象
    # FinalThreatPayload: {attacker_ip, score, timestamp, ...}
    sorted_events = sorted(events, key=lambda e: (attacker_ip, timestamp))
    parts = [f"{attacker_ip}|{score}|{timestamp}" for each]
    raw = ";".join(parts) + "WARDENNET_DIGEST_V1"  # SALT
    return sha256(raw).hexdigest()
```

### 3.3 威胁评分引擎

**包路径**: `cloud/app/service/threat_engine.py`

#### L1/L2/L3 三级威胁

```
L1: 单 IP 威胁（score >= 30）
L2: 网段威胁（同一 /24 子网内 3+ L1 IP）
L3: 租户级威胁（3+ L2 IP 或任一 score >= 80）
```

#### 评分更新流程

```python
score_evidence(tenant_id, events):
    # 1. 按 src_ip 分组
    ip_events = defaultdict(list)

    # 2. 遍历每个 IP 的事件
    for ip, ev_list in ip_events.items():
        # 白名单跳过
        if whitelist_repo.is_whitelisted(ip, tenant_id): continue

        # 旧分数衰减（24h 半衰期）
        elapsed = time.time() - last_updated
        base_score = exponential_decay(existing.score, elapsed, 24h)

        # 新分数累加
        new_score = min(100, base_score + sum(ev.local_risk_score))

        # 判定等级
        level = "L1" if new_score >= 30 else "NONE"

    # 3. L2 判定（/24 子网聚合）
    subnet_groups = defaultdict(list)
    for L1 IP:
        subnet = ip.split(".")[:3]
        subnet_groups[subnet].append(ip)
    if len(ips_in_subnet) >= 3 → 升级为 L2

    # 4. L3 判定
    if 3+ L2 IP or any score >= 80 → L3
```

### 3.4 双层 Diff 同步（V2 评分而非硬拉黑）

**包路径**: `cloud/app/service/diff_service.py`

#### 请求格式

```python
# Agent 发送
DiffRequest {
    agent_id, tenant_id,
    global_base: "base-20260904",
    global_incr_seq: 42,
    tenant_seq: 17
}
```

#### 响应格式（全局层 + 租户层）

```python
{
  "global": {
    "need_base": false,                    # base 变更 → 全量拉取
    "base_name": "base-20260904",
    "threat_scoring": [                    # V2：威胁评分快照
      {"ip": "1.2.3.4", "score": 85, "vote_count": 3}
    ],
    "incr_list": [                         # 增量列表
      {
        "incr_seq": 43,
        "threat_add": [{"ip": "...", "score": 50}],
        "threat_remove": ["expired_ip"],
        "feature_add": [...],
        "feature_remove": [...]
      }
    ]
  },
  "tenant": {
    "full_sync": false,                    # 强制全量
    "tenant_seq": 18,
    "threat_scoring": [                    # V2：租户私有池
      {"ip": "5.6.7.8", "score": 60, "source": "private"}
    ],
    "whitelist_add": [...],                # 白名单（直接应用）
    "whitelist_remove": [...]
  },
  "server_time": 1788500000
}
```

#### 全局层数据源

```
threats_global 表（多租户交叉验证后的共享情报池）
  ├─ aggregate_score: 0-100
  ├─ vote_count: 独立付费租户数
  └─ expires_at: 72h TTL
```

#### 租户层数据源

```
threats_private 表（当前租户私有）
  ├─ score: 0-100
  └─ expires_at: 24h TTL
```

### 3.5 威胁情报聚合器

**包路径**: `cloud/app/scheduler/threat_aggregator.py`

#### 准入条件（防投毒核心）

```
聚合只从 threat_votes → threats_global:

1. 独立付费租户数 ≥ min_paid_tenants（默认 2）
2. 加权得分 sum(vote_weight) ≥ min_score_sum（默认 2.0）
3. ASN 网络覆盖数 ≥ min_asn_coverage（防止同一 ASN 大量刷票）
4. 单个 IP 投票上限 single_ip_vote_cap（截断）

公式:
  raw_score = min(score_sum / min_score_sum, 3.0) × 33.33
  aggregate_score = round(raw_score, 1)   // 0-100

TTL: threats_global 72h 自动过期
```

### 3.6 双池隔离架构（防投毒）

```
Agent 上报威胁事件
       │
       ▼
threats_private（私有池）
  ├─ 所有租户上报优先进入此处
  ├─ 仅当前租户 Agent 可见
  ├─ 24h TTL 自动过期
  └─ 不参与联防评分
       │
       ▼  多租户交叉验证（Aggregation Job）
       │
threats_global（全局池）
  ├─ 多租户独立投票准入
  ├─ 付费租户可读取
  ├─ 72h TTL 自动过期
  └─ 参与联防评分（跨租户权重）

DiffService.generate_bilateral_diff():
  global.threat_scoring ← threats_global
  tenant.threat_scoring ← threats_private
```

### 3.7 定时调度任务

| 调度器 | 作用 | 间隔 |
|--------|------|------|
| **ThreatAggregator** | 私有池 → 全局池聚合 | 可配（默认 10min） |
| **AnomalyInspector** | 防投毒异常检测 | 可配 |
| **DecayJob** | threat_votes 过期清理（24-72h TTL） | 可配 |
| **AutoAccept** | 低风险申诉自动接受 | 可配 |
| **DiffScheduler** | 变更记录触发版本递增 | 事件驱动 |

---

## 四、Agent 本地综合决策引擎

**包路径**: `agent/internal/cloudsync/decision.go`

### V2 安全防御层核心公式

> **云端只给评分（0-100），Agent 做最终决策。**

```python
composite = cloud_score × 0.4 + local_freq_score × 0.3 + detector_score × 0.3
```

### 决策阈值

```
composite ≥ 80  → BLOCK（写 ipset blacklist）
composite ≥ 50  → ALERT（仅日志，不拉黑）
composite < 50  → IGNORE

local_score 默认值: 50（无本地检测信号时的"中性"占位）
```

### 决策在 Diff 应用链路中的位置

```
SyncEngine.doDiff():
  ├─ Global Snapshot: DecideAll(snap.threat_scoring)
  ├─ Global Incr:     DecideAll(incr.threat_add)
  ├─ Tenant Snapshot: DecideAll(snap.threat_scoring)
  └─ Tenant Diff:     DecideAll(result.tenant.threat_scoring)

DecideAll 输出:
  blocks → applyDecisions → ipsetutil.ApplyCloud(blacklist entries)
  alerts → 仅记录 DEBUG 日志
```

### 白名单绕过机制

```python
# ipsetutil.ApplyCloud 中
for e in entries:
    if e.Set == SetBlacklist and IsLocalWhitelisted(e.IP):
        filtered.append(e)  # 被豁免，反馈给云端
        continue
    toApply.append(e)

# 本地白名单绝对优先，无法被任何云端操作覆盖
# 只有 CLI --force 可以绕过本地白名单
```

---

## 五、完整数据流全景

### 5.1 本地检测链路

```
┌─────────────────────────────────────────────────────────────────┐
│                    日志文件 (access.log)                          │
└──────────────────────────┬──────────────────────────────────────┘
                           │ Tail (逐行 + 位置续读)
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Parser.Parse                                  │
│            nginx_access / custom_regex / ...                     │
└──────────────────────────┬──────────────────────────────────────┘
                           │ logparser.Event
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                  detector.Process(ev)                            │
│  ┌────────────────┐    ┌─────────────────┐                      │
│  │ WhitelistCheck │──▶ │ LoopbackSkip    │                      │
│  └────────────────┘    └────────┬────────┘                      │
│                                 ▼                                │
│  ┌──────────────────────────────────────────────────────────────┐│
│  │             SlidingWindow.Record                             ││
│  │   ├─ 3 档窗口计数器更新 (10s/30s/60s)                         ││
│  │   ├─ BodyScanner (可选: SQLi/XSS/XXE/文件上传)                ││
│  │   └─ Consistency.pathHistory ring buffer                     ││
│  └────────────────────────┬─────────────────────────────────────┘│
│                            ▼                                      │
│  ┌──────────────────────────────────────────────────────────────┐│
│  │   ResourceBaseline.Check (可选: IDOR/BOLA 越权)               ││
│  └────────────────────────┬─────────────────────────────────────┘│
│                            ▼                                      │
│  ┌──────────────────────────────────────────────────────────────┐│
│  │   Scorer.ScoreWithDetail(counters, ipQpsEMA, ipSeenCount)    ││
│  │   ├─ 相对特征: deviation(当前值, 基线P95) → deviationToScore││
│  │   ├─ 绝对特征: hit_count × fixed_weight                      ││
│  │   ├─ 真实用户奖励: static×3 + validReferer                    ││
│  │   ├─ 多维度协同: 单维度封顶 + 组合提升                        ││
│  │   └─ 基线置信度校验                                           ││
│  └────────────────────────┬─────────────────────────────────────┘│
│                            ▼                                      │
│  ┌──────────────────────────────────────────────────────────────┐│
│  │   Consistency.Compute → BENIGN 降权 gate                     ││
│  └────────────────────────┬─────────────────────────────────────┘│
│                            ▼                                      │
│  ┌──────────────────────────────────────────────────────────────┐│
│  │   shouldBlock(ip, highConfidence, timestamp)                 ││
│  │   ├─ 高置信度攻击 → 直接封禁（清除观察记录）                  ││
│  │   └─ 低置信度 → 多事件确认 (30s内2次独立高分 → 封禁)          ││
│  └────────────────────────┬─────────────────────────────────────┘│
│                            ▼                                      │
│  ┌──────────────────────────────────────────────────────────────┐│
│  │   BlockTrigger → ipsetutil.Block() → iptables DROP           ││
│  │   ThreatReportTrigger → threatreporter.Add() → 云端上报      ││
│  └──────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

### 5.2 云端 Diff 同步链路

```
Agent                                              Cloud SaaS
  │                                                    │
  │  Plugin.Diff(DiffRequest)                          │
  │  ├─ agent_id                                       │
  │  ├─ global_base="base-20260904"                    │
  │  ├─ global_incr_seq=42                             │
  │  └─ tenant_seq=17                                  │
  │ ────────────────────────────────────────────────► │
  │                                                    │
  │                                  DiffService.generate_bilateral_diff()
  │                                  ├─ threats_global → global.threat_scoring
  │                                  ├─ threats_private → tenant.threat_scoring
  │                                  ├─ diff_changelog → incr_list
  │                                  └─ whitelist → tenant.whitelist_add/remove
  │  ◄──────────────────────────────────────────────── │
  │  {                                                │
  │    global: {threat_scoring, incr_list},           │
  │    tenant: {threat_scoring, whitelist_add/del}    │
  │  }                                                │
  │                                                    │
  ├─ DecideAll(global.threat_scoring, localScoreFn)   │
  │   composite = cloud×0.4 + local×0.3 + detector×0.3 │
  │   ├─ ≥80 → blocks                                  │
  │   └─ ≥50 → alerts                                  │
  │                                                    │
  ├─ DecideAll(global.incr.threat_add, nil)           │
  │                                                    │
  ├─ DecideAll(tenant.threat_scoring, nil)            │
  │                                                    │
  ├─ ApplyCloud(blocks) → ipsetutil.ApplyCloud()      │
  │   ├─ 过滤本地白名单命中（filtered）                │
  │   ├─ 两级写入：批量 → 逐条降级                     │
  │   └─ 更新 blocked map                              │
  │                                                    │
  └─ 直接应用 whitelist_add/remove                     │
```

---

## 六、防误杀/防投毒安全设计

### 6.1 本地侧（Agent）

| 防御层 | 机制 | 文件 |
|--------|------|------|
| 本地白名单 | 绝对优先，云端无法覆盖 | `ipsetutil/manager.go` |
| SkipPaths | favicon/robots.txt 不检测 | `detector/window.go` |
| Loopback 跳过 | 127.0.0.0/8 + ::1 | `detector/detector.go` |
| 多事件确认 | 低置信度需 2 次独立高分 | `detector/detector.go` → `shouldBlock()` |
| 5 维一致性模型 | BENIGN 行为降权 | `detector/consistency.go` |
| legitimateUserContext | 浏览器 + 无攻击特征 → 4xx/404 降权 | `detector/scorer.go` |
| 单维度封顶 | 仅一个相对维度异常 → 封顶 ScoreMedium | `detector/scorer.go` |
| 基线置信度 | 低置信度基线永不封禁 | `detector/scorer.go` |
| QPS 尖峰打折 | 纯 QPS 尖峰 → 3 折 | `detector/scorer.go` |
| HEAD 请求轻量 | HEAD 单独窗口，不进致命判定 | `detector/scorer.go` |
| 已知 HTTP 客户端 | okhttp/python-requests 不算 BotUA | `detector/featurelist.go` |
| ForceBlock CLI | 强制拉黑需显式 --force | `cli/handler.go` |

### 6.2 云端侧（Cloud SaaS）

| 防御层 | 机制 | 文件 |
|--------|------|------|
| 评分而非硬拉黑 | 云端只给 0-100 分，Agent 做最终决策 | `cloudsync/decision.go` |
| Nonce 防重放 | 60s TTL，一次性消费 | `security/auth.py` |
| Events Digest | WARDENNET_DIGEST_V1 私有算法防篡改 | `security/evidence_digest.py` |
| 双池隔离 | private → global 需多租户交叉验证 | `scheduler/threat_aggregator.py` |
| ASN 覆盖校验 | ≥N 个不同 ASN 网络才能进全局池 | `scheduler/threat_aggregator.py` |
| 投票上限截断 | 单 IP 投票数 cap 防无限堆票 | `scheduler/threat_aggregator.py` |
| 付费租户准入 | 免费租户投票不参与全局池 | `scheduler/threat_aggregator.py` |
| 分数衰减 | 24h 半衰期自动衰减 | `service/threat_engine.py` |
| TTL 自动过期 | private 24h / global 72h | `service/threat_engine.py` |
| 异常行为巡检 | 冷启动 burst / IP overlap / vote cap 告警 | `scheduler/anomaly_inspector.py` |
| HMAC-SHA256 签名 | 四重校验防伪造请求 | `security/auth.py` |
| Agent 时钟漂移 | 云端返回的 timestamp 用于签名计算 | `scheduler/diff_scheduler.py` |

---

## 七、配置体系

### 7.1 三段式特征列表合并

```
程序默认 (DefaultDangerousPatterns)
        ↓ 合并
用户配置 (config.DangerousPatterns.local)
        ↓ 合并 + 排除
云端拉取 (Plugin.FetchFeatures)

支持两种 YAML 格式:
  # 格式一：简单列表（向后兼容）
  dangerous_patterns: ["\\.env", "adminer\\.php"]

  # 格式二：结构化（支持排除项）
  dangerous_patterns:
    local: ["\\.env"]
    excludes: ["internal-api"]      # 排除确实存在的业务路径
    disable_builtin: false           # 禁用内置默认值
    disable_cloud: false             # 禁用云端拉取
```

### 7.2 环境变量可覆盖的关键参数

| 变量 | 作用 | 默认 |
|------|------|------|
| `THREAT_MIN_PAID_TENANTS` | 全局池准入最低付费租户数 | 2 |
| `THREAT_MIN_SCORE_SUM` | 全局池准入最低加权得分 | 2.0 |
| `THREAT_COLD_START_DAYS` | 冷启动期天数 | 3 |
| `THREAT_COLD_START_FACTOR` | 冷启动期权重因子 | 0.5 |
| `THREAT_VOTE_TTL` | 投票 TTL（秒） | 86400 |
| `THREAT_VOTE_CAP` | 单 IP 投票上限 | 50 |
| `THREAT_MIN_ASN_COVERAGE` | 最低 ASN 网络覆盖数 | 2 |
| `ANOMALY_COLD_START_BURST_IP` | 冷启动 burst IP 阈值 | 10 |
| `ANOMALY_COLD_START_WINDOW` | 冷启动 burst 观测窗口 | 300 |
| `ANOMALY_IP_OVERLAP_MIN` | IP overlap 最小租户数 | 3 |
| `ANOMALY_IP_OVERLAP_RATIO` | IP overlap 比率阈值 | 0.5 |
| `ANOMALY_VOTE_CAP_RATIO` | vote cap 触发比率 | 0.8 |

---

## 八、关键数字常量汇总

### 8.1 Agent 端

| 参数 | 默认值 | 含义 |
|------|--------|------|
| ScoreHigh | 50 | 本地拉黑候选阈值 |
| ScoreMedium | 30 | 中等风险观察阈值 |
| ScoreLow | 10 | 记录阈值（低于此不进统计） |
| 三档窗口 | 10s / 30s / 60s | 高频/中程/宏观 |
| Baseline 更新间隔 | 10s | 后台 goroutine |
| 观察窗口 ObserveWindowSec | 30s | shouldBlock 确认时间窗 |
| 合并窗口 MergeWindowSec | 5s | 同一次事件内连续触发合并 |
| 确认次数 ConfirmCount | 2 | 低置信度需触发次数 |
| QPS 偏离分段 | 1.5 / 2 / 5 / 10 | deviationToScore 分段点 |
| 单维度上限 | ScoreHigh × 60% | 相对维度封顶 |
| FinalScore 上限 | ScoreHigh × 2 | 防溢出 |
| LocalBlockTTL | 3600s (1h) | 本地封禁默认 TTL |
| CloudBlockTTL | 7200s (2h) | 云端下发 TTL 上限 |
| ipset 重试次数 | 3 次 | 每次间隔 200ms |
| Diff 拉取间隔 | 600s (10min) | SyncEngine 默认 |
| Heartbeat 间隔 | 300s (5min) | |
| Command 轮询间隔 | 120s (2min) | |

### 8.2 Cloud 端

| 参数 | 默认值 | 含义 |
|------|--------|------|
| L1 阈值 | 30 | 单 IP 威胁等级 |
| L2 IP 数 | 3 | /24 子网聚合 |
| L3 高威胁阈值 | 80 | 租户级触发 |
| 分数半衰期 | 24h | exponential_decay |
| Nonce TTL | 60s | 防重放 |
| 时间戳容差 | 60s | ±60s |
| 私有池 TTL | 24h | threats_private |
| 全局池 TTL | 72h | threats_global |
| 全局池最低付费租户 | 2 | 多租户交叉验证 |
| DecideAll block 阈值 | 80 | composite ≥ 80 拉黑 |
| DecideAll alert 阈值 | 50 | 50-80 告警不拉黑 |

---

## 九、构建方式

### 9.1 build-all.ps1 支持的构建模式

```powershell
# 默认：动态加载 libcloudplugin.so（需要同版本 Go 编译的 so）
go build -o wardennet

# 静态 + 集成 CloudPlugin（单二进制，零 glibc 依赖）
go build -tags=plugin -o wardennet   # CloudPlugin 编译进主程序
CGO_ENABLED=0 go build -tags=plugin  # 纯静态

# 动态加载 so
go build -tags=so -o wardennet

# 离线模式（无云端依赖）
go build -o wardennet   # NoopPlugin
```

---

## 附录：术语表

| 术语 | 全称 | 含义 |
|------|------|------|
| ipset | IP Set | Linux 内核的高效 IP 集合匹配机制 |
| iptables | IP Tables | Linux 内核防火墙规则框架 |
| QPS | Queries Per Second | 每秒请求数 |
| MAD | Median Absolute Deviation | 中位数绝对偏差，用于检测极端值 |
| P50/P95/P99 | Percentile | 分位数统计 |
| HMAC | Hash-based Message Authentication Code | 基于哈希的消息认证码 |
| Nonce | Number Used Once | 一次性随机数，防重放攻击 |
| Diff | Delta/Incremental Framework | 增量同步框架 |
| TTL | Time To Live | 生存时间，到期自动过期 |
| IDOR | Insecure Direct Object Reference | 不安全的直接对象引用（越权漏洞） |
| BOLA | Broken Object Level Authorization | 对象级授权失效（越权漏洞） |
| XXE | XML External Entity | XML 外部实体注入攻击 |
| ASN | Autonomous System Number | 自治系统号，用于网络归属识别 |
| WARDENNET_DIGEST_V1 | WardenNet 私有摘要算法 V1 | 防事件篡改的私有算法 |
| BENIGN | 良性（一致性模型判定） | 行为序列正常，降权处理 |
| ForceBlock | 强制拉黑 | CLI `--force` 跳过白名单豁免 |
| Preload | 预扫描 | 启动时扫历史日志建基线，消除冷启动 |
| Baseline | 基线 | 正常流量的分位数范围，检测偏离 |
| Observations | 观察名单 | shouldBlock 多事件确认用的中间状态 |
