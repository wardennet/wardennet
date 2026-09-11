# WardenNet Agent 架构总览

> 配套文档：[README](../README.zh.md) · [快速开始](./quick-start.zh.md) · [配置参考](./configuration.zh.md)

---

## 目录

1. [设计原则](#1-设计原则)
2. [系统分层](#2-系统分层)
3. [启动流程](#3-启动流程)
4. [数据流架构](#4-数据流架构)
5. [模块详解](#5-模块详解)
6. [Plugin 接口契约](#6-plugin-接口契约)
7. [特征值与规则表](#7-特征值与规则表)
8. [核心数据结构](#8-核心数据结构)

---

## 1. 设计原则

| 原则 | 说明 |
|------|------|
| **零外部网络依赖** | 所有检测逻辑本地运行，无插件时不发任何网络请求 |
| **编译期静态** | `CGO_ENABLED=0` 静态编译，单文件，产物约 4MB |
| **接口隔离** | 模块通过 Go interface 解耦，Windows 上自动切换为内存 Mock |
| **优雅降级** | 任何组件失败都不影响核心检测链路；无插件 = NoopPlugin |
| **安全优先** | Unix Socket 权限 0600；iptables 规则幂等；白名单绝对优先 |
| **数据最小化** | Linux Auth 默认不上报；云端威胁评分只给分不给 IP 来源详情 |

---

## 2. 系统分层

```
+--------------------------------------------------------------+
|   用户态进程 (root, systemd 托管)                              |
|                                                              |
|   +------+   +------+   +------+   +------+   +------+      |
|   | CLI  |   |Config |   |Logger|   |Stats |   |Plugin|      |
|   ++-----+   ++-----+   ++-----+   ++-----+   ++-----+      |
|    |           |          |          |          |              |
|    v           v          v          v          v              |
|   +---------------------------------------------------+      |
|   |                main.go (编排层)                    |      |
|   |  adapter.go (接口桥接) + platform_linux.go (平台初始化)  |      |
|   +------+------+------+------+------+------+--------+      |
|          |      |      |      |      |      |                |
|          v      v      v      v      v      v                |
|   +-----+  +----+  +---+  +----+  +---+  +----+             |
|   |LogPr|  |Det |  |IPS |  |TTL |  |Snap|  |Clou|  ← 核心   |
|   |   sr|  |ector|  |etU |  |    |  |shot|  |dsyn|     模块  |
|   +-----+  +----+  +----+  +----+  +----+  +----+             |
+--------------------------------------------------------------+
                              |
                              v
+--------------------------------------------------------------+
|   内核态 (Linux kernel)                                       |
|   +--------------------------------------------------------+|
|   | ipset: wardennet_blacklist (hash:ip)                    ||
|   | ipset: wardennet_whitelist (hash:net, CIDR + IPv6)      ||
|   | iptables -I INPUT -m set --match-set blacklist DROP     ||
|   | iptables -I INPUT -s 127.0.0.1/32 ! -i lo -j RETURN    ||
|   +--------------------------------------------------------+|
+--------------------------------------------------------------+
```

---

## 3. 启动流程

```
main()
  |-- config.Load()              # YAML + 内置默认值合并
  |-- logger.New()               # 初始化 lumberjack 轮转
  |-- plugin.Loader.Load()       # 尝试加载 libcloudplugin.so（失败则 NoopPlugin）
  |-- logsources.Init()          # 创建 tail goroutine 读取各日志文件
  |-- detector.New()             # 创建检测器 + 滑动窗口 + 基线预扫描(10min)
  |-- ipsetutil.Manager.New()    # Linux 上初始化 ipset + iptables 规则
  |-- ttl.Manager.New()          # TTL 过期管理 + 快照恢复
  |-- snapshot.Manager.New()     # 快照持久化 goroutine
  |-- cloudsync.New()            # Plugin != nil 时启动心跳 + Diff
  |-- unixsocket.NewServer()     # 启动 /var/run/wardennet.sock
  |-- pidlock.Acquire()          # Flock 确保单实例
  |-- block on signal            # SIGINT/SIGTERM -> graceful Stop
```

---

## 4. 数据流架构

### 4.1 日志 → 检测 → 拦截

```
tail goroutine
    |   (每 N 秒轮询文件 size/mtime)
    v
parser.Registry.Parse(line)     # nginx_access / apache_access / ...
    |   (输出 Event{IP, Time, Method, Path, Status, ...})
    v
detector.Detect(event)
    |-- 滑动窗口打分 (score 0-100)
    |-- 基线自学习 P95 偏差
    |-- 5 维 Consistency 协同评分
    |-- 防误杀 8 层过滤
    |-- 多事件确认 + 新鲜度检查
    v
ipsetutil.Manager.Block(ip)     # ipset add + iptables 已存在则幂等
    |
    v
ttl.Manager.Add(ip, ttl, source)  # 倒计时过期自动 remove
```

### 4.2 云端协同（可选）

```
plugin.Plugin                     # libcloudplugin.so
    |-- Init(ctx)
    |-- Auth(AuthContext) -> AgentID
    |
    |-- HeartbeatLoop:
    |     |-- Diff(DiffRequest) -> DiffResult
    |     |     |-- threats_global (全局共享池评分)
    |     |     |-- threats_private (租户私有池评分)
    |     |     |-- cloud_feature (特征列表更新)
    |     |     |-- DecisionWeights (0.4/0.3/0.3 默认权重)
    |     |
    |     |-- DecideAll(score_map, detector_local) -> decision per IP
    |     |     cloud_score * 0.4 + local_freq * 0.3 + detector * 0.3
    |     |     >= 80 -> block, >= 50 -> alert
    |
    |-- ThreatEventReport(detection_alert / block_action)
    |-- CommandPollAndAck(ping / reload / ...)
```

**硬约束**：`cloudsync` 包**不**持有 HTTP 客户端、HMAC 签名、云端凭证——这些全在 `internal/cloudplugin/`（闭源）。开源代码能做的只有调 `plugin.Plugin` 接口。

---

## 5. 模块详解

### 5.1 logparser — 日志采集与解析

| 文件 | 说明 |
|------|------|
| `parser.go` | `Parser` 接口 + `Registry` 注册表（按 key 注册） |
| `tail.go` | 文件 tail 轮询，带 size/mtime 检查 + 30s 心跳；支持 seek 续读 |
| `nginx.go` | Nginx combined + common + main 格式 |
| `apache.go` | Apache combined + common |
| `tomcat.go` | Tomcat access log |
| `linux_auth.go` | SSH 登录审计（默认不上报云端） |
| `portscan.go` | SYN/RST 模式识别 |
| `custom.go` | 用户自定义 regex + 分组映射 |

核心接口：

```go
type Parser interface {
    Parse(line string) (*Event, error)
    Name() string
}
```

### 5.2 detector — 检测引擎

内部又分 7 个子文件：

| 文件 | 职责 |
|------|------|
| `detector.go` | `Detector` 接口总装；静态白名单检查；BlockTrigger 回调；多事件观察名单 + 新鲜度快照 |
| `window.go` | 三档滑动窗口 (10/30/60s)；各维度 max 阈值 |
| `scorer.go` | 11 维特征值打分；空 Referer 硬上限；401 降权；真实用户奖励 |
| `consistency.go` | 5 维一致性协同评分；prefix_coherence / path_concentration / status_homogeneity / method_semantics / scanner_behavior |
| `baseline.go` | 基线自学习引擎；P95 分位数；MAD 极端值剔除 + P99 * factor 双通道；硬阈值预筛（isLikelyAttacker） |
| `resource_baseline.go` | 资源消耗基线（CPU / 内存 / FD 数） |
| `decode.go` | URL / Unicode / Hex / HTML Entity / 双重编码解码攻击模式匹配 |
| `detail.go` | 打分详情日志（debug 输出） |
| `featurelist.go` | 三段式特征列表合并（Builtin + Local + Cloud）+ Excludes 机制 |

多事件确认机制（**防误杀核心**）：

```go
const (
    ObserveWindowSec = 30   // 观察窗口：30 秒内
    MergeWindowSec    = 5    // 合并窗口：5 秒内重复事件算 1 次
    ConfirmCount      = 2    // 需要 >= 2 次独立高分事件
)
```

**新鲜度检查**（v1.4 新增）：只有 12 个攻击输入计数（status anomalies, attack features, scanner behaviors 等）里**至少一个真的增长**，才给 count +1。防止正常用户 token 过期 + 浏览器 404 在窗口里反复触发 is_high 导致误封。

### 5.3 ipsetutil — IP 集合管理

| 文件 | 说明 |
|------|------|
| `client.go` | `Client` 接口抽象：`Add / Del / Test` |
| `client_linux.go` | `os/exec` 调用 `ipset` 命令 |
| `client_mem.go` | 内存 Mock（Windows 开发 + 单元测试） |
| `client_nonlinux.go` | 非 Linux 平台 fallback |
| `iptables.go` | `iptables -I INPUT -m set --match-set` 注入 DROP 规则；幂等检查 |
| `manager.go` | `Manager` 聚合：黑名单 + 白名单 + ApplyCloud + ForceBlock |

关键设计：

- **白名单绝对优先**：`Contains(ip) == true` → 跳过所有检测与拉黑
- **双 ipset**：
  - `wardennet_blacklist` — `hash:ip`，精确 IP
  - `wardennet_whitelist` — `hash:net`，支持 CIDR + IPv6
- **ForceBlock**：CLI `--force` 绕过白名单，硬封锁

### 5.4 ttl — TTL 过期管理

倒计时过期自动 `ipset del`：

```go
type Entry struct {
    IP        string
    Source    Source       // Local / Cloud
    ExpiresAt time.Time
    TTL       int          // 秒
}
```

- `local_block_ttl` — 本地拉黑默认 3600s（1h）
- `cloud_block_ttl` — 云端下发上限默认 7200s（2h）
- 每分钟扫描过期条目删除

### 5.5 cloudsync — 云端同步调度（开源侧）

**重要**：本包**只做调度，不持有 HTTP / HMAC / 凭证**。

```go
type SyncEngine struct {
    p          plugin.Plugin    // 闭源实现
    ipMgr      *ipsetutil.Manager
    cfg        config.CloudSection
    globalBase string           // base-YYYYMMDD
    globalSeq  int64            // 全局增量序号
    tenantSeq  int64            // 租户序号
}
```

工作循环（每 60s）：

```
Heartbeat (插件实现) -> Diff (双层增量) -> DecideAll (综合决策) -> ApplyCloud (ipset 应用)
```

**综合决策引擎**：

```
composite = cloud_score * 0.4 + local_freq_score * 0.3 + detector_score * 0.3
  >= 80  -> block
  >= 50  -> alert
  <  50  -> ignore
```

云端可热更权重，但三项之和必须在 [0.5, 1.5] 内才接受（防投毒）。

### 5.6 plugin — 插件接口（架构契约）

完整接口见 `internal/plugin/plugin.go`，核心 13 个方法：

| 生命周期 | 方法 |
|---------|------|
| 加载 | `Init(ctx)` |
| 销毁 | `Shutdown()` |
| 鉴权 | `Auth(AuthContext) -> AuthResult` |
| 能力 | `Health() -> Ready` |
| 心跳 | `Heartbeat()` |
| Diff 同步 | `Diff(DiffRequest) -> DiffResult` |
| 全量快照 | `FetchFullGlobalSnapshot / FetchTenantSnapshot` |
| 威胁上报 | `ReportEvent / ReportThreat` |
| 远程指令 | `CommandPoll / CommandAck` |

**两种集成方式**：

1. **默认** `go build ./cmd/wardennet` — 运行时 `plugin.Open("libcloudplugin.so")` 动态加载
2. **编译时整合** `go build -tags=plugin ./cmd/wardennet` — CloudPlugin 源码直接编进主程序，产物 `wardennet_linux_static`（推荐部署）

### 5.7 其他模块

| 模块 | 职责 |
|------|------|
| `cli` | 命令注册表 + Handler（blocklist.add / blocklist.del / blocklist.status / status / reload） |
| `unixsocket` | `/var/run/wardennet.sock` JSON 协议（0600 权限） |
| `config` | YAML 加载 + 默认值合并 + FlexibleFeatureList 双格式 |
| `logger` | lumberjack 轮转 + debug/info/warn/error 等级 |
| `stats` | 统计收集 + 定时报告（IP 段分布、top blocked 等） |
| `features` | 三段式特征列表管理器（Builtin + Local + Cloud） |
| `pidlock` | `syscall.Flock` + PID 文件，单实例互斥 |
| `snapshot` | TTL + 黑名单快照序列化 / 恢复 |
| `portscan` | SYN/RST 端口扫描检测（pcap + 纯 socket 两种实现） |

---

## 6. Plugin 接口契约

> 这是商业 CloudPlugin 闭源实现的接口文档。开源侧禁止绕过此接口直接依赖闭源包。

### 6.1 Plugin 接口

```go
type Plugin interface {
    // 生命周期
    Init(ctx context.Context) error
    Shutdown() error

    // 鉴权
    Auth(AuthContext) AuthResult

    // 能力状态
    Health() bool

    // 同步调度
    Heartbeat()
    Diff(DiffRequest) DiffResult
    FetchFullGlobalSnapshot(ctx context.Context) (SnapshotResult, error)
    FetchTenantSnapshot(ctx context.Context) (SnapshotResult, error)

    // 上报
    ReportEvent(ReportEvent) error
    ReportThreat(ThreatReport) error

    // 远程指令
    CommandPoll(ctx context.Context) ([]Command, error)
    CommandAck(commandID string, result string) error
}
```

### 6.2 数据载体

- `ThreatScore{IP, Score(0-100), VoteCount, Source}` — 云端下发的威胁评分（只给分，不直接拉黑）
- `DiffResult{Global, Tenant}` — 双层增量结果
- `DecisionWeightsConfig{Cloud, Local, Detector}` — 云端可热更权重

### 6.3 NoopPlugin

开源侧实现，无插件时自动启用。所有方法空实现，Agent 退化纯本地。

---

## 7. 特征值与规则表

### 7.1 检测评分权重（默认）

| 维度 | 类型 | 权重 | 说明 |
|------|------|------|------|
| dangerous_pattern | 绝对 | 5 | URL/Unicode/Hex/HTML Entity 解码后匹配攻击模式 |
| dangerous_method | 绝对 | 3 | PUT/DELETE/TRACE/CONNECT 等 |
| file_upload | 绝对 | 20 | 大文件上传或常见上传路径 |
| 其余 8 维 | P95 相对 | 自适应 | engine 自动学习各维度分布 |

### 7.2 防误杀硬阈值

| 规则 | 值 | 说明 |
|------|----|------|
| 空 Referer 硬上限 | `score_high / 4` | 即 12.5（score_high=50） |
| 401 单独权重 | 1/5 | + `score_high / 4` 硬上限 |
| 基线预筛 isLikelyAttacker | Rate4xx>0.80 / Rate404>0.80 / RateBotUA>0.90 / DangerousPatternHit>=3 / PathTraversalHit>=3 | 命中则不进基线 |
| Cluster Consensus Fast Path | VoteCount>=20 && Score>=90 | 全局池绕过加权直接 block |

### 7.3 三段式特征列表合并

```
最终 = DefaultBuiltins + CloudFetch 结果 + LocalConfig
      - Excludes 用户排除
      - disable_builtin=true 跳过 DefaultBuiltins
      - disable_cloud=true    跳过云端拉取
```

---

## 8. 核心数据结构

### Event（日志解析输出）

```go
type Event struct {
    IP            string
    Time          time.Time
    RequestMethod string
    RequestPath   string
    Status        int
    Bytes         int64
    Referer       string
    UA            string
    Source        string    // nginx_access / apache_access / ...
    LocalRiskScore float64   // detector 回填
}
```

### ThreatScore（云端下发）

```go
type ThreatScore struct {
    IP        string  `json:"ip"`
    Score     float64 `json:"score"`       // 0-100
    VoteCount int     `json:"vote_count"`  // 全局池有值
    Source    string  `json:"source"`      // global / private
}
```

### DiffResult（双层增量）

```go
type DiffResult struct {
    Global struct {
        NeedBase      bool
        BaseName      string
        ThreatScoring []ThreatScore      // 全局共享池
        IncrList      []GlobalIncr       // 增量序号链
    }
    Tenant struct {
        FullSync      bool
        TenantSeq     int64
        ThreatScoring []ThreatScore      // 租户私有池
        WhiteAdd      []string           // 新增白名单
        WhiteDel      []string           // 删除白名单
    }
}
```