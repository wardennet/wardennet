# WardenNet Agent Code Wiki

> 版本：v0.10 | 最后更新：2026-09-08 | 模块：`agent/` | 变更：**Preload 反代不透传检测 + minutes 参数生效**（三条件判定 IP 多样性 / 时间窗口过滤旧日志）、多维度协同评分引擎（单维度封顶/置信度打折/硬保底）、Preload 全量扫描+MAD 极端值剔除、Tail Seek 修复+30s 心跳、DetectorSection 结构体精简（Mode=block|report/Sensitivity=string/ScoreMedium/ScoreLow/Weights）、Baseline 加 confidence/动态衰减/MIN_BASELINE_QPS、基线抗投毒 P0 方案（硬阈值预筛 isLikelyAttacker + 运行时 MAD 双重管线）

---

## 目录

1. [项目概览](#1-项目概览)
2. [技术栈与依赖](#2-技术栈与依赖)
3. [目录结构](#3-目录结构)
4. [启动流程](#4-启动流程)
5. [数据流架构](#5-数据流架构)
6. [模块详解](#6-模块详解)
   - 6.1 [logparser - 日志解析](#61-logparser---日志解析)
   - 6.2 [detector - 检测引擎](#62-detector---检测引擎)
   - 6.3 [scorer - 打分器](#63-scorer---打分器)
   - 6.4 [ipsetutil - IP 集合管理](#64-ipsetutil---ip-集合管理)
   - 6.5 [ttl - TTL 过期管理](#65-ttl---ttl-过期管理)
   - 6.6 [snapshot - 快照持久化](#66-snapshot---快照持久化)
   - 6.7 [stats - 统计收集](#67-stats---统计收集)
   - 6.8 [cli - 命令行接口](#68-cli---命令行接口)
   - 6.9 [unixsocket - Unix Socket 服务](#69-unixsocket---unix-socket-服务)
   - 6.10 [config - 配置管理](#610-config---配置管理)
   - 6.11 [logger - 日志](#611-logger---日志)
   - 6.12 [plugin - 插件系统](#612-plugin---插件系统)
   - 6.13 [cloudsync - 云端同步调度](#613-cloudsync---云端同步调度)
7. [核心数据结构](#7-核心数据结构)
8. [接口依赖关系图](#8-接口依赖关系图)
9. [平台适配](#9-平台适配)
10. [特征值与规则表](#10-特征值与规则表)
11. [扩展点与待开发接口](#11-扩展点与待开发接口)

---

## 1. 项目概览

WardenNet Agent 是部署在受保护服务器上的本地安全代理，核心功能：

- **日志采集**：实时 tail Nginx / Apache / Tomcat / Linux Auth 日志
- **攻击检测**：基于三档滑动窗口 + 基线自学习（P95 分位数偏差评分）的动态检测引擎
- **自动防护**：检测到高危攻击时自动通过 ipset + iptables 封禁 IP
- **状态持久化**：快照机制确保重启后黑名单不丢失
- **可观测性**：统计报告 + 评分详情日志，支持持续调优

### 设计原则

| 原则 | 说明 |
|---|---|
| **零外部网络依赖** | 所有检测逻辑本地运行，不依赖云端 |
| **编译期配置** | 静态编译，产物单文件，无 Go 运行时依赖 |
| **接口隔离** | 各模块通过接口解耦，便于单元测试和 Mock |
| **优雅降级** | 任何组件失败都不影响核心检测链路 |
| **安全优先** | Unix Socket 权限收紧到 0600，iptables 规则幂等 |

---

## 2. 技术栈与依赖

### 语言与运行时

| 项目 | 版本 | 说明 |
|---|---|---|
| Go | 1.27+ | 主开发语言 |
| 编译模式 | CGO_ENABLED=0 | 静态编译，无 cgo 依赖 |

### 第三方库

| 库 | 版本 | 用途 |
|---|---|---|
| `gopkg.in/yaml.v3` | v3.0.1 | YAML 配置解析 |
| `gopkg.in/natefinch/lumberjack.v2` | v2.2.1 | 日志文件自动轮转 |

### 系统依赖

| 组件 | 版本要求 | 用途 |
|---|---|---|
| ipset | >= 6.x | IP 集合管理（内核级） |
| iptables | >= 1.8.x | 防火墙规则注入 |
| Linux kernel | >= 3.12 | 底层 ipset/iptables 支持 |

---

## 3. 目录结构

```
agent/
├── cmd/
│   └── wardennet/
│       ├── main.go              # 主入口：串联全链路
│       ├── adapter.go           # 接口适配器（ipset/ttl/快照）
│       ├── platform_linux.go    # Linux 平台初始化（iptables）
│       └── platform_nonlinux.go # 非 Linux 占位实现
│
├── internal/
│   ├── logparser/               # 日志采集与解析
│   │   ├── parser.go            # 解析器接口 + Registry
│   │   ├── tail.go              # 文件 tail 续读（轮询模式）
│   │   ├── nginx.go             # Nginx access log 解析
│   │   ├── apache.go            # Apache access log 解析
│   │   ├── tomcat.go            # Tomcat access log 解析
│   │   ├── linux_auth.go        # Linux /var/log/auth.log 解析
│   │   └── parsers_test.go      # 解析器表驱动测试
│   │
│   ├── detector/                # 滑动窗口检测引擎
│   │   ├── detector.go          # Detector 集成：Window + Scorer + Whitelist + Baseline
│   │   ├── window.go            # IP 维度统计窗口（含特征值表）
│   │   ├── baseline.go          # 基线自学习引擎：P95 分位数统计、指数衰减、偏差评分
│   │   ├── scorer.go            # 基线偏差 + 绝对特征固定权重打分器
│   │   ├── detail.go            # 评分详情结构 ScoreDetail + DetailLogger 回调
│   │   ├── decode.go            # 路径解码（URL/Unicode/Hex/HTML entity）+ 危险模式匹配
│   │   ├── featurelist.go       # 三段式特征列表引擎：ResolveFeatureList、CloudFeatureFetcher
│   │
│   ├── ipsetutil/               # IP 集合管理
│   │   ├── manager.go           # 黑白名单业务状态机
│   │   ├── client.go            # Client 接口定义
│   │   ├── client_linux.go      # Linux 真实 ipset 调用
│   │   ├── client_mem.go        # 内存 Mock Client（测试用）
│   │   ├── client_nonlinux.go   # 非 Linux 占位实现
│   │   └── iptables.go          # iptables 规则管理
│   │
│   ├── ttl/                     # TTL 过期管理
│   │   └── manager.go           # 本地/云端 TTL 条目 + 自动清理
│   │
│   ├── snapshot/                # 状态快照
│   │   └── manager.go           # 定期快照 + 启动恢复
│   │
│   ├── stats/                   # 统计收集
│   │   └── collector.go         # 事件聚合 + 报告生成
│   │
│   ├── cli/                     # CLI 命令
│   │   ├── command.go           # 命令常量 + Registry
│   │   └── handler.go           # blocklist/status 命令实现
│   │
│   ├── unixsocket/              # Unix Socket 服务
│   │   └── server.go            # 本地命令通信服务端
│   │
│   ├── config/                  # 配置管理
│   │   ├── config.go            # 配置结构定义
│   │   └── loader.go            # YAML 加载 + 热重载
│   │
│   ├── logger/                  # 日志
│   │   └── logger.go            # 结构化日志（lumberjack 轮转）
│   │
│   └── plugin/                  # 插件系统
│       └── loader.go            # 插件加载器（stlplugin.Open + Lookup('NewPlugin')）
│
│   ├── cloudsync/               # 云端同步调度
│   │   ├── engine.go            # SyncEngine：heartbeatLoop / diffLoop / commandLoop / featureLoop
│   │   ├── diff.go              # 双层 Diff：global + tenant → ipMgr.ApplyCloud
│   │   └── types.go             # CloudSection 配置 + 版本追踪（globalBase/globalSeq/tenantSeq）
│   │
│   ├── threatreporter/          # 威胁上报
│   │   └── reporter.go          # 本地高危事件 → 云端上报（事件流水）
│
│   ├── libcloudplugin/          # 🔒 CloudPlugin 动态库（closed source，.gitignored）
│   │   └── libcloudplugin.so    # 编译期 .so，通过 plugin.Loader 加载
│
├── configs/                     # 配置文件
│   ├── wardennet-agent.service  # systemd service 文件
│   ├── wardennet.production.yaml # 生产环境配置
│   └── wardennet.yaml.example   # 配置模板
│
├── docs/                        # 文档
│   └── AGENT_MANUAL.md          # 部署运维手册
│
├── scripts/                     # 辅助脚本
│   └── wardennet_cli.py         # Python CLI 客户端
│
├── deploy.sh                    # 一键部署脚本
├── go.mod                       # Go 模块定义
└── go.sum                       # 依赖校验
```

---

## 4. 启动流程

`main.go` 中的初始化顺序（共 19 步）：

```
┌─────────────────────────────────────────────────────────────────┐
│                     main() 启动流程                              │
│                                                                  │
│  1. 加载配置 (config.Loader)                                     │
│     └── 解析 config.yaml → cfg.Config                           │
│                                                                  │
│  2. 初始化日志器 (logger.Logger)                                  │
│     └── lumberjack 轮转 / 级别过滤                              │
│                                                                  │
│  3. 初始化 ipset 管理器 (ipsetutil.Manager)                      │
│     ├── Linux: 真实 ipset + iptables 规则                        │
│     └── 非 Linux: 内存 Mock                                      │
│     └── 加载本地白名单 + 黑名单预填                              │
│                                                                  │
│  4. 初始化 TTL 管理器 (ttl.Manager)                              │
│     └── 后台清理协程（30s 周期）                                 │
│                                                                  │
│  5. 初始化统计收集器 (stats.Collector)                            │
│     └── 采样率 100:1                                             │
│                                                                  │
│  6. 初始化检测引擎 (detector.LocalDetector)                      │
│     ├── 三档窗口 (10s/30s/60s)                                   │
│     ├── 三档基线 (Baseline) 初始化                                │
│     ├── 静态白名单检查                                          │
│     ├── 注册 BlockTrigger（高危自动拉黑）                        │
│     └── 设置 DetailLogger（评分详情回调）                        │
│                                                                  │
│  6.1 预扫描历史日志预计算基线（v0.10 加反代检测 + 时间窗口过滤）    │
│      ├── 遍历所有 log_sources                                   │
│      ├── 全量读取 access.log（最多 50 万行）                     │
│      ├── 同时完成：按 5min 时间桶分组 + IP 多样性统计             │
│      ├── [v0.10] 时间窗口过滤：只保留 maxTS 往前 minutes 分钟的桶  │
│      ├── 健康桶 QPS 值通过 MAD 方法剔除扫描器/爬虫极端桶         │
│      ├── 用干净数据算 P50/P95/P99 → 应用 MIN_BASELINE_QPS 硬保底 │
│      ├── 设置三档 Baseline + confidence + ForceReady()           │
│      ├── [v0.10] IP 多样性 → isReverseProxySuspicious() 三条件判定│
│      │          命中 → main.go 输出 Error + nginx 修复指令 + os.Exit(1) │
│      └── 返回 PreloadStats（含 UniqueIPs/Top1Ratio/ReverseProxyDetected）│
│                                                                  │
│  7. 注册日志解析器 (logparser.Registry)                          │
│     └── nginx / apache / tomcat / linux_auth                     │
│                                                                  │
│  8. 注册 CLI 命令 (cli.Registry)                                 │
│     └── status / blocklist.add / blocklist.del / ...             │
│                                                                  │
│  9. 启动 Unix Socket 服务 (unixsocket.Server)                    │
│     └── 桥接 cli.Registry → unixsocket.Registry                 │
│                                                                  │
│  10. 初始化快照管理器 (snapshot.Manager)                         │
│      └── 从 state.json 恢复 TTL + ipset 状态                     │
│                                                                  │
│  11. 加载插件 (plugin.Loader)                                    │
│      └── 无插件时降级为 NoopPlugin                               │
│                                                                  │
│  12. 创建 CloudSync 引擎 (cloudsync.NewSyncEngine)               │
│      ├── 持有 plugin.Plugin + ipsetutil.Manager                  │
│      ├── 四条后台协程：heartbeatLoop / diffLoop /                │
│      │   commandLoop / featureLoop                              │
│      └── NoopPlugin → 所有循环跳过（优雅降级）                   │
│                                                                  │
│  13. 启动威胁上报 (threatreporter.Reporter)                      │
│      └── 本地高危事件流水 → 云端                                  │
│                                                                  │
│  14. 启动配置热重载 (config.Watcher)                              │
│      └── 5s 间隔检测配置文件变更                                 │
│                                                                  │
│  15. 启动日志 tail 消费                                          │
│      ├── 为每个 log_source 创建独立 Tail                          │
│      └── 发送事件到 eventCh (1024 buffer)                        │
│                                                                  │
│  16. 启动事件处理循环                                            │
│      └── eventCh → convertLogEvent() → det.Process()             │
│                                                                  │
│  17. 启动定期统计报告 (60s 周期)                                  │
│      └── statsCollector.GenerateReport() → 日志输出              │
│                                                                  │
│  18. 等待退出信号                                                │
│      └── SIGINT/SIGTERM → 优雅关闭 → 保存快照 → 清理 iptables    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 5. 数据流架构

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Nginx Log   │     │  Apache Log  │     │  Tomcat Log  │     │  Auth Log    │
└──────┬───────┘     └──────┬───────┘     └──────┬───────┘     └──────┬───────┘
       │                    │                    │                    │
       ▼                    ▼                    ▼                    ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                    logparser (Tail + Parser Registry)                        │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │  Tail.Run() 轮询 (1s) → Parser.Parse() → Event → eventCh (1024 buffer) │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────┬───────────────────────────────────────┘
                                       │
                                       ▼
                            convertLogEvent()
                                       │
                                       ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                   detector (LocalDetector + 3-Sliding Windows)               │
│                                                                              │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐                              │
│  │ 10s Window │  │ 30s Window │  │ 60s Window │  ← 并行统计，取最高分        │
│  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘                              │
│        │               │               │                                      │
│        └───────────────┼───────────────┘                                      │
│                        ▼                                                      │
│              Scorer.ScoreWithDetail(counters, ipQpsEMA, ipSeenCount)         │
│              ┌────────────────────────────────────┐                           │
│              │  基线偏差评分（相对特征）：          │                           │
│              │  QPS/4xx/5xx/404/AuthFail/SensPath │                           │
│              │  /BotUA/EmptyRef → deviationToScore │                           │
│              │  (动态敏感度：seenCount 驱动)        │                           │
│              │                                     │                           │
│              │  固定权重评分（绝对特征）：           │                           │
│              │  DangerousPattern/Method/FileUpload │                           │
│              │  × 权重 + 单次上限                 │                           │
│              │                                     │                           │
│              │  防误杀（保留 8 层）：                │                           │
│              │  legitimateUserContext 降权         │                           │
│              │  concentrated4xx 降权              │                           │
│              │  空 Referer 协同置信度              │                           │
│              │  ...                                │                           │
│              └────────────┬───────────────────────┘                           │
│                           │                                                   │
│                  score >= score_high (50)?                                    │
│                    │            │                                              │
│                   YES          NO                                             │
│                    │            │                                              │
│                    ▼            ▼                                              │
│           BlockTrigger     仅记录评分详情                                     │
│           (auto block)     (DetailLogger)                                     │
└──────────────────────────┬───────────────────────────────────────────────────┘
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
    ┌──────────────────┐      ┌──────────────────┐
    │  ipsetutil.Mgr   │      │   ttl.Manager    │
    │  ┌────────────┐  │      │  ┌────────────┐  │
    │  │ ipset add  │  │      │  │ TTL 条目   │  │
    │  │ iptables   │  │      │  │ 自动过期   │  │
    │  │  DROP 规则 │  │      │  └────────────┘  │
    │  └────────────┘  │      └──────────────────┘
    └──────────────────┘
                           │
                           ▼ (定期/关闭时)
    ┌────────────────────────────────────────────────────────────┐
    │                  snapshot.Manager                          │
    │                  state.json (JSON)                         │
    │                  ┌──────────────────────────────────────┐  │
    │                  │  ipset: {blacklist: [...], ...}     │  │
    │                  │  ttl: {entries: [...]}               │  │
    │                  └──────────────────────────────────────┘  │
    └────────────────────────────────────────────────────────────┘
```

---

## 6. 模块详解

### 6.1 logparser - 日志解析

**文件**：`internal/logparser/`

#### 职责
- 实时 tail 多个日志文件（Nginx/Apache/Tomcat/Linux Auth）
- 解析原始日志行为统一的 `Event` 结构
- 检测日志轮转（基于 inode 变化）
- 断点续读（重启后不丢日志）

#### 核心接口

```go
// Parser 解析器接口
type Parser interface {
    Name() string
    Parse(line string) (Event, error)
}

// Event 统一事件结构
type Event struct {
    Timestamp      time.Time
    SourceIP       string
    Source         string    // "nginx_access" / "apache_access" / ...
    RawLine        string
    Method         string
    Path           string
    Status         int
    UserAgent      string
    Referer        string
    AuthAction     string
    LocalRiskScore int       // detector 填充
    AllowUpload    bool
    // ...
}
```

#### 内置解析器

| 解析器 | 文件 | 正则匹配 |
|---|---|---|
| `nginx_access` | `nginx.go` | CLF/Combined Log Format |
| `apache_access` | `apache.go` | 同 Nginx（共享 CLF 格式） |
| `tomcat_access` | `tomcat.go` | `%h %l %u %t "%r" %s %b` + 可选 UA/Referer |
| `linux_auth` | `linux_auth.go` | `/var/log/auth.log` 的 Failed/Accepted password |

#### Tail 续读机制（v0.8 静默断流修复）

```go
// Tail 日志文件续读器
type Tail struct {
    path        string          // 日志文件路径
    parser      Parser          // 解析器
    offset      int64          // 当前读取位置
    inode       uint64          // 上次文件 inode（检测轮转）
    pollInterval time.Duration // 轮询间隔（默认 1s）
    statePath   string          // 断点状态文件
    dropCount   atomic.Int64   // 丢弃计数（背压控制）
    logFn       func(level, fmt string, args ...any) // v0.8 新增：心跳日志输出
}

// 关键方法
func (t *Tail) Run(ctx context.Context, ch chan<- Event) error
func (t *Tail) DroppedCount() int64
```

#### v0.8 静默断流修复

```
Bug 根因：
  bufio.Reader 预读机制会偷偷把 fd 位置推到 state.Offset 之后。
  每次 poll 新建 bufio.Reader 时，从错误的 fd 位置开始读 → 漏读。
  时间一长 offset 虽然追上了 size，但每次都 early return → 静默！

修复方案：
  1. Seek 修复：每次 readNewLocked 开头强制 Seek(state.Offset, SEEK_START)
     → 无论 bufio.Reader 怎么乱动 fd 位置，都从正确位置开始
  2. 30s 心跳：每 30s 打印一条 tail heartbeat 日志
     → 包含 size / offset / gap / inode / dropped
     → gap 持续增长 → tail 漏读；gap < 0 → truncate/rotate 没检测到
  3. panic recover：main.go tail goroutine 加 defer recover
     → goroutine 崩溃不再静默退出
```

#### 背压策略
- Channel 满时非阻塞发送，丢弃事件而非阻塞
- 每 100 条丢弃打印一次 warn 日志
- 统计报告中输出 `tail_dropped` 指标

---

### 6.2 detector - 检测引擎

**文件**：`internal/detector/`

#### 职责
- 三档滑动窗口（10s/30s/60s）并行统计
- **基线自学习偏差评分引擎**（Baseline 自动学习 P95 分布，评分基于偏离程度）
- 绝对特征固定权重（DangerousPattern / Method / FileUpload）
- **三段式特征列表引擎**：Builtin + Local(YAML) + Cloud → 去重 → Excludes
- **Consistency 5 维行为连贯性评分**（v1.2）：零业务依赖，基于 path 序列形状判断是否 BENIGN，作为 Scorer 之后的降权 gate
- 9 层防误杀 + 3 层自学习自动适应（见下）
- 白名单豁免（命中白名单 IP 直接跳过）
- 高危事件自动触发 BlockTrigger
- 每 10s 后台更新三档基线（baselineUpdateLoop）

#### 9 层防误杀 + 3 层自学习自动适应

**核心防误杀防御（9 层）**：

| 防御层 | 机制 | 说明 |
|--------|------|------|
| 1 | 空 Referer 佐证信号 + 硬上限 | 空 Referer 单独触发时降级 80% + 硬上限 score_high/4 |
| 2 | 已知 HTTP 客户端 UA 白名单 | okhttp/python-requests 等不判定为 Bot |
| 3 | 敏感路径状态码关联 | 仅统计 status >= 400 的敏感路径命中 |
| 4 | 路径段精确匹配 | env 不匹配 env.js，admin 不匹配 admin.js |
| 5 | 危险攻击模式解码检测 | URL/Unicode/Hex/HTML entity 解码后匹配攻击模式 |
| 6 | legitimateUserContext 降权 | 致命攻击特征为零 + 浏览器占比 ≥ 95% 时按比例容忍噪音（BotUA≤3%且≤5次/SensPath≤2%且≤3次/AuthFail≤2%且≤3次）→ 4xx/404_ratio 降权 90%（× 0.1）；浏览器占比不足时保持严格（所有攻击特征计数必须为零） |
| 7 | 404 路径前缀归一化 | 同前缀 404 合并为 distinct base，Count404 = base 数量而非原始次数 |
| 8 | 4xx 路径集中度降权（concentrated4xx） | 4xx 集中在 ≤2 条归一化路径 + 非浏览器 + 非 Bot → 4xx 降权 50%（× 0.5） |
| 9 | Consistency 行为降权 gate（v1.2 新增） | Scorer 给了 score_high 但 IP 的行为序列形状明显是正常用户（ConsistencyScore ≥ ScoreThreshold=4，样本 ≥ 20）→ 强制降权到 score_medium，让多事件确认机制处理 |

**自学习自动适应（3 层，基线引擎内置）**：

| 自适应层 | 机制 | 说明 |
|----------|------|------|
| A | 基线自学习自动适应 | P95 分位数动态学习正常流量分布，权重隐含在基线中 |
| B | 动态敏感度（seenCount 驱动） | IP 首次出现时敏感度低（避免误杀新用户），seenCount 增长后敏感度自动提升 |
| C | Per-IP EMA 适应共享 IP | 同一出口 IP 下多用户场景，qpsEMA 平滑处理避免突发波动 |

#### 核心文件

| 文件 | 功能 |
|------|------|
| `detector.go` | Detector 集成：Window + Scorer + Whitelist + Baseline 三档 + Consistency 降权 gate |
| `window.go` | 滑动窗口实现、特征值检测方法、ipEntry 含 pathHistory ring buffer |
| `baseline.go` | **基线自学习引擎**（v0.9 升级抗投毒）：Percentile 算法、BaselineDimensions、Update/IsReady/ForceReady/Get、`isLikelyAttacker` 硬阈值预筛、`removeOutliersMAD`+`trimExtremes` 双重极端值剔除管线、deviation/deviationToScore/ratio/getEffectiveSensitivity 辅助函数 |
| `scorer.go` | 基线偏差 + 绝对特征固定权重打分器 |
| `consistency.go` | **Consistency 5 维行为连贯性评分**（v1.2）：ConsistencyThresholds 参数结构、Default/Merge、pathRing ring buffer、5 维评分 + 反信号、ComputeConsistency |
| `detail.go` | 评分详情结构 ScoreDetail + ScoreDetailString |
| `decode.go` | 路径解码（URL/Unicode/Hex/HTML entity）+ 危险模式匹配 |
| `featurelist.go` | **三段式特征列表引擎**：ResolveFeatureList、CloudFeatureFetcher 接口 |

#### 核心结构

```go
// LocalDetector 本地检测器
type LocalDetector struct {
    windows       [3]*ipWindow     // 三档窗口
    baselines     [3]*Baseline     // 三档基线（10s/30s/60s）
    scorer        *Scorer          // 打分器
    whitelist     WhitelistChecker
    blockTrigger  func(Event) bool  // 高危自动拉黑回调
    detailLogger  DetailLogger     // 评分详情回调
    baselineStop  chan struct{}    // 基线更新循环停止信号
    baselineOnce  sync.Once        // baselineUpdateLoop 只启动一次
}

// 核心方法
func (d *LocalDetector) Process(ev Event) Event
func (d *LocalDetector) RegisterBlockTrigger(fn func(Event) bool)
func (d *LocalDetector) SetDetailLogger(l DetailLogger)
func (d *LocalDetector) PreloadFromLogFile(path, parser string, minutes int) (PreloadStats, error) // 启动预扫描（v0.10: minutes 生效 + 时间窗口过滤 + IP 多样性统计 + 反代检测）
func (d *LocalDetector) baselineUpdateLoop()                                 // 每 10s 更新三档基线
```

#### ipWindow - 滑动窗口实现

```go
// ipEntry 单个 IP 的三档时间窗口 + Per-IP 动态状态 + Consistency 历史
type ipEntry struct {
    mu              sync.Mutex
    last            int64                        // 上次写入 Unix 秒（TTL 淘汰）
    window          [3]*ipWindow                 // 三档窗口
    fourOhFourBases map[string]int64             // 404 路径归一化：base → 最新时间戳
    fourXXBases     map[string]int64             // 4xx 路径集中度追踪：所有 4xx 归一化路径 → 时间戳
    qpsEMA          float64                      // Per-IP QPS 指数移动平均（平滑突发）
    seenCount       int                          // 该 IP 被处理的事件数（驱动动态敏感度）
    pathHistory     *pathRing                    // v1.2: Consistency 历史请求 ring buffer（512/IP 默认）
}

// ipWindow 单个 IP 的一档窗口
type ipWindow struct {
    mu       sync.Mutex
    buckets  [6]*bucket   // 环形桶（覆盖 60s）
    lastSeen time.Time
}

// bucket 单个时间桶（10s 粒度）
type bucket struct {
    totalReq, count4xx, count5xx int64
    count404, authFail           int64
    sensitivePathHit             int64
    botUAHit                     int64
    emptyRefererHit              int64
    dangerousMethod              int64
    staticResHit                 int64
    hasStaticRes                 bool
}
```

#### Baseline - 基线自学习引擎（v0.8 升级）

```go
// BaselineDimensions 基线追踪的 8 个相对维度（全部 P50/P95/P99）
type BaselineDimensions struct {
    QPS          Percentile
    Count4xx     Percentile
    Count5xx     Percentile
    Count404     Percentile
    AuthFail     Percentile
    Sensitive    Percentile
    BotUA        Percentile
    EmptyReferer Percentile
}

// Baseline 单档基线引擎（v0.8 升级：加 confidence + MIN_BASELINE_QPS + 动态衰减）
type Baseline struct {
    mu       sync.RWMutex
    dims     BaselineDimensions  // 8 个维度的 P50/P95/P99
    windowSec int                // 对应窗口时长 (10/30/60)
    decayFactor float64          // 当前衰减系数（0.5=预热期快速收敛，0.8=稳定期）
    lastUpdated time.Time
    startAt     time.Time
    sampleCount int
    confidence  float64          // Preload 时设置的基线置信度 (0~1)，GetWithConfidence 读取
}

// === 核心常量 ===
const (
    MIN_BASELINE_QPS        = 1.0   // QPS P95 硬保底：永远不低于 1.0 req/s（防止凌晨低峰基线污染）
    MIN_BASELINE_RATE_P95   = 0.001 // 比率型维度 P95 硬保底：永远不低于 0.1%（防止低峰 Preload 时 deviation 爆炸）
    MAX_DEVIATION           = 1000.0 // deviation 结果 cap 上限（防止天文数字污染评分/日志）
    QUICK_DECAY_FACTOR      = 0.5   // 预热期（前 30min）衰减系数：基线快速追平真实流量
    NORMAL_DECAY_FACTOR     = 0.8   // 稳定期衰减系数：平滑追踪长期趋势
    WARMUP_DURATION         = 30min // 预热期时长
    CONFIDENCE_MIN_FOR_SCORE = 0.3  // confidence < 此值时 QPS 偏离分打 5 折
    CONFIDENCE_MIN_FOR_BLOCK = 0.1  // 三档全 < 此值时永不封禁

    // ---------- v0.9 新增：基线抗投毒硬阈值预筛 ----------
    // Update() 收集样本前先过滤"明显可疑"的 IP，宁肯多过滤也不让攻击者污染基线。
    // 正常业务几乎不会被误伤：扫描器特征是 100% 4xx + 100% BotUA，
    // 搜索引擎/CDN 爬虫 BotUA 很高但 404 rate 不会到 80%。
    PRESCAN_MAX_RATE_4xx         = 0.80 // 4xx rate > 80% 直接 skip
    PRESCAN_MAX_RATE_404         = 0.80 // 404 rate > 80% 直接 skip
    PRESCAN_MAX_RATE_BOT_UA      = 0.90 // BotUA rate > 90% 直接 skip
    PRESCAN_MIN_DANGEROUS_HITS   = 3    // DangerousPattern 命中 ≥ 3 次直接 skip
    PRESCAN_MIN_TRAVERSAL_HITS   = 3    // 路径穿越命中 ≥ 3 次直接 skip
)

// === 核心方法 ===
func (b *Baseline) Update(counters map[string]WindowCounters)
    // 1. 过滤 TotalReq < minSamples 的 IP
    // 2. [v0.9 G1] isLikelyAttacker(c) 硬阈值预筛 → Rate4xx>0.80 / Rate404>0.80 / RateBotUA>0.90 / DangerousPattern≥3 / PathTraversal≥3 → skip
    // 3. [v0.9 G2] 双重极端值剔除：removeOutliersMAD(k=5) → trimExtremes(factor=10)
    // 4. 计算分位数 → floorRatePercentile 硬保底 → 动态衰减融合

// === isLikelyAttacker [v0.9 G1] ===
func isLikelyAttacker(c WindowCounters) bool
    // 硬阈值预筛：满足任一条件返回 true（该 IP 不参与基线学习）
    // 设计目标：宽松阈值（0.80/0.90）防误伤，专门拦截扫描器/攻击者的极端行为模式
    //   - 正常用户 4xx rate 通常 < 20%，搜索引擎 BotUA 高但 404 不会到 80%
    //   - 扫描器（libredtail/nmap/sqlmap）会同时满足 4xx=100% + BotUA=100%

// === MAD + trimExtremes 双重管线 [v0.9 G2] ===
func removeOutliersMAD(values []float64, k float64) []float64    // MAD 对极端值鲁棒，能砍 P99 本身就是极端值的场景
func trimExtremes(values []float64, factor float64) []float64    // 原 P99×factor 保险，砍掉 MAD 没覆盖到的天文值

// MAD 工作原理：median → median(|x-median|) → threshold=median+k*MAD → 超过的删
// k=5 对应 ~3σ 保守值，已被 Preload 阶段验证有效
// v0.9 之前只在 Preload 用 MAD，v0.9 升级为运行时 Update 也用 MAD + trimExtremes 双重
func (b *Baseline) Get(dim BaselineDim) float64          // 获取某维度 P95
func (b *Baseline) GetWithConfidence(dim BaselineDim) (p95 float64, conf float64) // v0.8 新增：同时返回置信度
func (b *Baseline) Confidence() float64                   // v0.8 新增
func (b *Baseline) IsConfident(min float64) bool          // v0.8 新增
func (b *Baseline) SetConfidence(c float64)               // Preload 完成后设置
func (b *Baseline) IsReady() bool
func (b *Baseline) ForceReady()

// === MAD 极端值剔除（Preload 阶段用）===
func removeOutliersMAD(values []float64, k float64) []float64
    // MAD = median(|x - median|)
    // 阈值 = median + k × MAD；超过的视为极端值删除
    // k=5 对应正态分布 ~3σ 原则，但 MAD 本身对极端值鲁棒
    // 用于 Preload 阶段剔除扫描器/爬虫/batch sync 桶，防止 P95 被极端桶拉高

// === PreloadStats（PreloadFromLogFile 返回）===
// v0.10 新增 IP 多样性 / 反代检测字段
type PreloadStats struct {
    Source, Path    string
    ScannedLines    int
    TimeStart, TimeEnd string    // "2006-01-02 15:04"
    DurationMin     int
    TotalBuckets     int        // 5min 桶总数（v0.10 经过时间窗口过滤后）
    HealthyBuckets   int        // 健康桶数（>= 50% 中位数）
    HealthyReqMin    float64    // 健康桶阈值（req/5min）
    MedianReq        float64
    QPSP50, QPSP95, QPSP99 float64
    QPSSamples       int
    Confidence       float64    // = HealthyBuckets / TotalBuckets
    Duration         string
    BaselineQPS      [3]float64
    QPSOutliersRemoved int      // MAD 方法剔除的 QPS 极端桶数

    // ---------- v0.10 新增：IP 多样性 / 反代检测 ----------
    UniqueIPs            int     // 去重后的不同公网 IP 数（排除 loopback/private）
    Top1IP               string  // 请求最多的 IP
    Top1Count            int64   // Top1 IP 的请求数
    Top1Ratio            float64 // Top1 IP 占总请求比例 0~1
    Top3Ratio            float64 // Top3 IP 合计占比 0~1
    ReverseProxyDetected bool    // 是否触发反代不透传检测（满足 A/B/C 任一）
}
```

#### Baseline 防污染设计（v0.8 → v0.9 升级）

```
问题：Preload 读取的历史日志中如果有扫描器/batch sync，会把 P95 QPS 拉到离谱。
     实际案例：正常网站 P50=1.4 req/s，扫描器桶 P95=71 req/s（50x 污染）。
v0.8 问题：运行时 Update 只有 trimExtremes(P99×10) 一道防线，
           遇到集群并发扫描时所有 IP 的 4xx rate=1.0，
           P99=1.0, threshold=10.0，一个都砍不掉 → 基线被集体抬高。

=== 六层防护（v0.9 完整）===

[运行时 Update 管线]
  minSamples 过滤 (TotalReq < 5 skip)
    │
    ▼
  [G1 预筛] isLikelyAttacker(c) → 满足任一直接 skip：
    ├─ Rate4xx > 0.80   (80%+ 4xx → 扫描器特征)
    ├─ Rate404 > 0.80   (80%+ 404 → 枚举探测特征)
    ├─ RateBotUA > 0.90 (90%+ Bot UA → 自动化工具)
    ├─ DangerousPatternHit ≥ 3
    └─ PathTraversalHit ≥ 3
    │  ← 命中任一 → 彻底不参与基线学习
    ▼
  [G2 Step 1] removeOutliersMAD(k=5)
    │  MAD = median(|x - median|)，本身对极端值鲁棒
    │  能砍 P99 本身就是极端值的场景（集群扫描时中位数被抬高）
    ▼
  [G2 Step 2] trimExtremes(factor=10)
    │  P99×10 保险，砍掉 MAD 没覆盖到的天文值
    ▼
  计算分位数 → floorRatePercentile 硬保底 → 动态衰减融合

[静态硬件保护]
  MIN_BASELINE_QPS = 1.0        → QPS P95 永远不低于 1.0 req/s
  MIN_BASELINE_RATE_P95 = 0.001 → 比率型维度 P95 永远不低于 0.1%
  MAX_DEVIATION = 1000.0        → deviation cap

[评分时保护]
  confidence < 0.3 → QPS 偏离分 × 0.5
  confidence < 0.1 → score_high 强制降到 49（永不封禁）

=== 实战效果（43.142.87.72 漏报复盘）===
v0.8 行为：集群扫描时 5 个 IP 同时 4xx=100%
  → P99=1.0, threshold=10.0 → 一个都砍不掉
  → 基线 Rate4xx P95 被抬高到 ~0.95
  → 43.142.87.72 的 Rate4xx=0.93 → deviation=0.98x → 偏离度 0 → 没得分 → is_high=false → 漏报

v0.9 行为：
  → G1 预筛：5 个扫描 IP 全部满足 Rate4xx=1.0>0.80 → 全部 skip
  → 基线只从正常 IP 学习，Rate4xx P95 保持健康值
  → 43.142.87.72 因自己 4xx=1.0 也被 G1 预筛 skip（不污染基线）
  → 其他 IP 的偏离度评分不受污染
```

#### 辅助函数
func floorRatePercentile(p Percentile) Percentile         // 比率型维度 P95 硬保底 MIN_BASELINE_RATE_P95(0.001)
func getEffectiveSensitivity(seenCount int, baseSensitivity int) int
```

#### 404 路径归一化

`fourOhFourBases` map 在 `Record()` 404 时填充，在 `Counters()` 时遍历统计 distinct base 数量作为 `Count404`。

```
normalize404Path 规则：
  去 query → 去末尾 / → 小写 → 变量段(UUID/≥4位数字/≥24位hex)替换为 {id} → 取前 4 段

效果：
  /tdsc/gdfa/edit/nullapi/v1/xm/enum/{a,b,c,...} → 同 base → Count404 只计 1
  /admin, /.env, /phpmyadmin → 不同 base → Count404 各计 1
```

#### 4xx 路径集中度降权（concentrated4xx，v1.1）

`fourXXBases` map 在 `Record()` 中对所有 4xx（400/401/403/404/499）填充归一化路径（复用 `normalize404Path` 函数），在 `Counters()` 中计算每个窗口内 distinct 数量，输出到 `WindowCounters.Distinct4xxPaths`。

Scorer 判定条件（与 legitimateUserContext 互斥）：

```
concentrated4xx = Distinct4xxPaths ∈ [1, 2]  AND
                  NormalBrowserHit == 0       AND   ← 不影响 legitimateUserContext（要求 > 0）
                  BotUAHit == 0               AND   ← 不豁免扫描器伪装
                  over4xx > 0
```

满足时 4xx 维度得分降权 50%（× 0.5）。

```
场景：Apache-HttpClient × 30 次 400 on /oauth/token
  Distinct4xxPaths = 1, NormalBrowserHit = 0, BotUAHit = 0
  → concentrated4xx = true
  → 4xx pts × 0.5 → score=37 < 50 ✓

反绕过：扫描器扫 10 个不同路径 → Distinct4xxPaths=10 > 2 → 不触发
```

#### Consistency 5 维行为连贯性评分（v1.2 新增）

**解决什么问题**：合法 API 客户端突发 QPS（如批量同步 30 req/s），Scorer 会因基线偏离给 score_high。但这种突发在**行为形状**上仍是合法的（路径连贯、状态稳定），与扫描器每条路径只扫一次的发散模式有本质区别。

**零业务依赖**：只用 access.log 必有字段的排列模式——path、method、status，不看 header、不看 query、不看业务路径语义。

```go
// ConsistencyThresholds 所有阈值/权重集中在此，YAML 可覆盖
type ConsistencyThresholds struct {
    RingCapacity int     // 每 IP ring buffer 容量，默认 512
    MinSamples   int     // 样本不足不评分，默认 20
    ScoreThreshold int   // >= 此分判 BENIGN，默认 4

    // 5 维正向信号阈值（通用统计形状，不随业务规模变）
    PrefixRunLenMin     float64  // 前缀连贯：平均连续段长度 ≥ 3
    PrefixDominantMin   float64  //    或 dominant 前缀占比 ≥ 50%
    NoveltyEarly30Min   float64  // 新颖度饱和：前 30% 请求覆盖 ≥ 70% 的不同路径
    LateNoveltyRateMax  float64  //    且后 30% 新增路径率 ≤ 40%
    PathConcentratedThreshold float64  // Top5 路径覆盖 ≥ 25%
    StatusCVMax         float64  // 同路径状态码变异系数 < 0.6
    GetRatioMin/Max     float64  // GET 占比 [50%, 99%]
    PostRatioMin/Max    float64  // POST 占比 [1%, 49%]
    UnusualMax          float64  // PUT/DELETE/PATCH ≤ 5%
    PureAPIGetMax       float64  // 纯 API GET 客户端豁免阈值
    PureAPIPostMin      float64  // 纯 API POST 客户端豁免阈值

    // 反信号（加分项）
    AlwaysErrorDynamicMin   int  // 动态路径反复撞墙 ≥ 5 次全错 → -5
    AlwaysErrorProbeMin     int  // favicon/robots 等公共探测 ≥ 10 次 → -5
    SinglePathErrorBonus    int  // 单路径 + 全错 → 额外 -3
    AlwaysErrorScorePenalty int
    HighlyNovelEarlyMax    float64 // 发散扫描反信号：早 30% < 50%
    HighlyNovelLateMin     float64 //    且 晚 30% 新增 > 70%
    HighlyNovelCoverMax    float64 //    且 Top5 覆盖 < 40% → -3
    HighlyNovelPenalty     int

    // 5 维权重
    WeightPrefix   int  // +2
    WeightNovelty  int  // +2
    WeightPathConc int  // +2
    WeightErrors   int  // +1
    WeightMethod   int  // +1
}

// pathRing per-IP 历史请求 ring buffer（capacity 默认 512）
type pathRing struct { buf []pathRecord; head int; full bool; total int; capacity int }

// ConsistencyScoreResult 评分结果
type ConsistencyScoreResult struct {
    Score        int   // 原始分（含反信号扣分）
    IsBenign     bool  // Score >= ScoreThreshold (默认 4)
    HasSamples   bool  // total >= MinSamples (默认 20)
    Total        int
    UniquePaths  int
    // 5 维命中标志 + 实测值（用于日志诊断）
    PrefixCoherent, NoveltyConverged, PathConcentrated, ErrorsStable, MethodNatural bool
    AlwaysSameError bool
    AvgRunLen, SegDominant, NoveltyEarly30, LateNoveltyRate, Top5Cover, AvgStatusCV float64
    GetRatio, PostRatio, UnusualRatio float64
}
```

**集成位置**：`LocalDetector.Process` 中 Scorer 之后、`shouldBlock` 之前

```
Scorer → finalScore >= ScoreHigh ?
           ├─ NO → 正常放行
           └─ YES → Consistency gate:
                      ├─ HasSamples && IsBenign → finalScore 降到 ScoreMedium（让多事件确认处理）
                      └─ else → 维持 ScoreHigh → 继续 shouldBlock
```

**为什么 5 维够**：

| 维度 | 真人/合法客户端 | 扫描器 |
|------|----------------|--------|
| 前缀连贯 | 连续请求 `/api/*`，avgRunLen ≥ 3 | 每条路径切换前缀，avgRunLen ≈ 1 |
| 新颖度饱和 | 前 30% 已覆盖 70%+ 路径，后面走已知路径 | 一路扫一路新，后 30% 新增 ≥ 70% |
| 路径集中 | Top5 覆盖 ≥ 25% | 每条路径 1-2 次，Top5 < 25% |
| 状态同质 | 同路径返回稳定状态（200 系列） | 发散路径各撞一次 404/403 |
| 方法语义 | GET/POST 为主，PUT/DELETE 极少 | 混合方法或全 GET 探测 |

**内存**：ring buffer 512 条/IP，每条 ~64 字节；500 活跃 IP ≈ 16 MB。

**与 Baseline 的关系**：两者互补，不替代。Baseline 学"数值偏离"（QPS P95 = 3.2 req/s），Consistency 看"形状模式"（行为路径序列像不像真人）。

#### 工作流程

```
Process(ev Event)
    │
    ├── 1. 白名单检查 → 命中则直接返回 score=0
    │
    ├── 2. 更新三档窗口计数 + Per-IP 动态状态
    │      ├── 10s 窗口 (buckets[0])
    │      ├── 30s 窗口 (buckets[0:3])
    │      └── 60s 窗口 (buckets[0:6])
    │      └── ipEntry.qpsEMA 更新（指数平滑）
    │      └── ipEntry.seenCount++
    │      └── ipEntry.pathHistory.append()  ← v1.2: 写入 Consistency ring
    │
    ├── 3. 获取三档窗口 counters + 查询三档 Baseline P95
    │
    ├── 4. Scorer.ScoreWithDetail(counters, ipQpsEMA, ipSeenCount) → ScoreResult
    │      ├── 基线偏差评分（8 维相对特征 × deviationToScore × 动态敏感度）
    │      ├── 固定权重评分（3 维绝对特征 × 权重 + 单次上限）
    │      ├── 应用防误杀机制（前 8 层）
    │      └── 返回最高窗口分 + 详情
    │
    ├── 5. Consistency 降权 gate（v1.2 新增）
    │      ├── ComputeConsistency(ev.SourceIP) → ConsistencyScoreResult
    │      ├── HasSamples && IsBenign && finalScore >= ScoreHigh?
    │      │   └── YES → finalScore = ScoreMedium（降权让多事件确认处理）
    │      └── NO → 维持原分
    │
    ├── 6. DetailLogger.LogDetail(ev, details, score, isHigh)
    │      ├── 写入 stats.Collector
    │      └── Debug 日志记录
    │
    └── 7. score >= score_high ?
           ├── YES → shouldBlock(ev) → blockTrigger(ev) 自动拉黑
           └── NO  → 返回带 score 的 Event

baselineUpdateLoop（每 10s 后台协程）
    ├── 遍历所有活跃 ipEntry → 聚合全局 counters
    ├── baseline[0/1/2].Update(globalCounters)  [v0.9: 内含 G1 预筛 + G2 MAD+trimExtremes 双重管线]
    └── 三档 Baseline P95 滚动更新
```

---

### 6.3 scorer - 打分器

**文件**：`internal/detector/scorer.go`

#### 职责
根据窗口计数器 + 基线 P95 偏差 + 绝对特征固定权重计算风险分

#### 设计洞察

> 权重隐含在 P95：基线引擎通过 P95 分位数自动学习正常流量分布。某个维度的 P95 值本身就反映了"正常情况下这个值应该是多少"，因此偏离程度（deviation）天然就是"异常程度"。不再需要为每个维度手动设置 MaxReq/Max4xx/Max404Ratio 等固定阈值和对应的权重系数。

#### ScoreWithDetail 签名

```go
func (s *Scorer) ScoreWithDetail(
    counters     [3]WindowCounters,  // 三档窗口计数器
    ipQpsEMA     float64,             // Per-IP QPS 指数移动平均
    ipSeenCount  int,                 // 该 IP 累计处理事件数（驱动动态敏感度）
) ScoreResult
```

#### 打分公式（v0.8 多维度协同升级）

```
窗口得分 = 相对特征评分 + 绝对特征评分 × 单维度封顶规则 + 置信度打折 - 防误杀降权

=== 相对特征评分（8 维基线偏差）===
  for each relative dimension d:
    p95, conf = baselines[w].GetWithConfidence(d)     // v0.8 同时读置信度
    value     = counters[d] / windowSec
    dev       = value / p95 (cap 1000)
    pts       = deviationToScore(dev, sensitivity)

=== 单维度封顶（核心 v0.8 新增）===
  相对特征总分 = Σ 各维 pts
  如果 活跃的相对维度数 == 1：
      相对特征总分 cap 到 score_medium(30)     // 单维度异常永远不封
  否则：
      每个维度的 pts cap 到 score_high × 60%(30)  // 任意单维都不超过 30

=== 绝对特征评分（3 维固定权重，不受封顶限制）===
  DangerousPattern = min(counters.DangerousPatternHit × weight, singleEventCap=25)
  DangerousMethod  = min(counters.DangerousMethod × weight,    singleEventCap=25)
  FileUpload       = min(counters.FileUploadHit × weight,       singleEventCap=25)

=== 置信度打折（v0.8 新增）===
  baselineConf = min(三档窗口 confidence)
  if baselineConf < 0.3:
      相对特征总分 ×= 0.5    // 基线不准 → 保守处理
  
  if baselineConf >= 0.3 && 活跃相对维度数 >= 1 && 无绝对特征命中:
      相对特征总分 ×= 0.3    // 纯 QPS 尖峰 + 无攻击特征 → 保守处理

=== 硬保底永不封禁（v0.8 新增）===
  if baselineConf < 0.1:
      score_high_actual = score_medium + 1  // 49
      → 绝对不可能达到真正的 score_high

=== 最终分 ===
  总分 = min(相对特征分 + 绝对特征分 - 防误杀降权, score_high)
  取 max(三档窗口)
```

#### deviation 与 deviationToScore

```go
// deviation: value 相对基线 Percentile.P95 的偏离倍数
// p.P95 <= 0 → 返回 0（避免除零）
// 结果 cap 到 MAX_DEVIATION(1000)，防止 baseline P95 极小时除法爆炸
func deviation(value float64, p Percentile) float64

// deviationToScore: 偏离倍数 → 分数（线性映射 + cap 100）
// sensitivity ∈ [1,2,3] 对应 threshold = [2,5,10]
// dev < threshold → 0 分（未超出偏离阈值）
// dev ≥ threshold → excess × 10，上限 100
func deviationToScore(dev float64, sensitivity int) int

// getEffectiveSensitivity: IP 首次出现时敏感度低（避免误杀新用户），
// seenCount 增长后敏感度自动返回 baseSensitivity
func getEffectiveSensitivity(seenCount int, baseSensitivity int) int
    // seenCount < 10  → base × 0.3
    // seenCount < 50  → base × 0.6
    // seenCount < 200 → base × 0.9
    // else            → base
```

#### v0.8 多维度协同 vs 旧版对比

```
案例 1：正常浏览（QPS 单维度异常，legmit 已生效）
  旧版：qpsDeviation=13.4 → qpsScore=83 → score=56(cap 50) → 封禁 ❌
  新版：qpsDeviation=13.4 → qpsScore=83 → 单维 cap 30 + confidence 打折 → score=15 → 放行 ✅

案例 2：真实 CC 攻击（QPS 高 + 4xx 高 + BotUA）
  旧版：直接触发
  新版：多维度协同 → 无单维封顶 → 总分=30+30+20=80 → cap 50 → 封禁 ✅

案例 3：SQL 注入（QPS 正常 + danger=25）
  旧版：danger=25 → score=25 → 观察
  新版：danger=25 → 不受封顶限制 → score=25（如果 QPS 也高则叠加到 50+ → 封禁）✅
```
```

#### 基线硬件保护常量

Baseline 引擎内置多层硬件保护，防止 Preload 低峰数据、运行时集群扫描或极端样本导致基线值扭曲。v0.9 新增运行时硬阈值预筛 + MAD 双重管线。所有常量定义在 `baseline.go` 包级。

**[v0.9 新增] 运行时 Update 管线 — 样本收集前预筛**

| 常量 | 值 | 保护维度 | 触发条件 | 效果 |
|------|-----|----------|----------|------|
| `PRESCAN_MAX_RATE_4xx` | 0.80 | 比率型 | 某 IP 的 4xx rate > 80% | 该 IP 直接 skip，不参与基线学习 |
| `PRESCAN_MAX_RATE_404` | 0.80 | 比率型 | 某 IP 的 404 rate > 80% | 同上 |
| `PRESCAN_MAX_RATE_BOT_UA` | 0.90 | 比率型 | 某 IP 的 BotUA rate > 90% | 同上 |
| `PRESCAN_MIN_DANGEROUS_HITS` | 3 | 计数型 | DangerousPattern 命中 ≥ 3 次 | 同上 |
| `PRESCAN_MIN_TRAVERSAL_HITS` | 3 | 计数型 | PathTraversalHit ≥ 3 次 | 同上 |

**[v0.9 新增] 运行时极端值剔除 — 双重管线**

| 函数 | 位置 | 说明 |
|------|------|------|
| `removeOutliersMAD(values, k=5)` | `trimExtremes` 之前 | MAD 对极端值鲁棒，能砍 P99 本身就是极端值的场景（如集群扫描） |
| `trimExtremes(values, factor=10)` | MAD 之后 | 原 P99×10 保险，砍掉 MAD 没覆盖到的天文值 |

**[原有 v0.8] 静态硬件保护**

| 常量 | 值 | 保护维度 | 触发条件 | 效果 |
|------|-----|----------|----------|------|
| `MIN_BASELINE_QPS` | 1.0 | QPS (req/s) | 凌晨 Preload 后 QPS P95 < 1.0 | QPS P95/P99/P50 提到地板 |
| **`MIN_BASELINE_RATE_P95`** | **0.001** | 比率型维度 | Preload 后任意 rate P95 < 0.1% | rate P95 提到 0.001，P99 提到 0.003，P50 提到 0.0003 |
| **`MAX_DEVIATION`** | **1000.0** | 所有 deviation 计算 | 任意维度 deviation > 1000 | deviation 结果 cap 到 1000，防止天文数字污染评分和日志 |

**多层保护位置**：
1. **运行时 Update（v0.9）**：`isLikelyAttacker` 预筛 → `removeOutliersMAD(k=5)` → `trimExtremes(10)` → 算分位数
2. `computePercentiles` 输出后 → `floorRatePercentile` 对所有 rate 维度夹地板
3. `decayPercentile` 衰减融合后 → 再次 `floorRatePercentile`（防止旧基线小 + 新基线小 → 衰减后掉下去）
4. `deviation` 函数内部 → 结果 cap 到 `MAX_DEVIATION`（防御性兜底）

**[v0.10 新增] 启动前反代不透传检测（Preload 阶段执行）**

Preload 扫描同时统计 IP 多样性，检测是否存在"所有请求来自极少 IP"的反代不透传场景。
三条件满足任一 → Agent 终止并输出 nginx `set_real_ip_from` 修复指令。

| 常量 | 值 | 含义 |
|------|-----|------|
| `proxyMinUniqueIPsForSafe` | 11 | UniqueIPs > 10 时直接安全（正常站点不太可能有 11+ 个反代节点） |
| `proxySingleIPThreshold` | 3 | 条件 A: UniqueIPs ≤ 3 即反代（典型单反代 / 双反代场景） |
| `proxyTop1RatioThreshold` | 0.90 | 条件 B: UniqueIPs ≤ 10 且 Top1Ratio ≥ 90% |
| `proxyTop3RatioThreshold` | 0.98 | 条件 C: UniqueIPs ≤ 10 且 Top3Ratio ≥ 98% |

判定函数：`isReverseProxySuspicious(uniqueIPs int, top1Ratio, top3Ratio float64) bool`
实现位置：`detector.go`（与 `PreloadFromLogFile` 配套）
IP 多样性统计位置：`fillIPDiversityStats` 方法（Loopback/private IP 已排除）

**[v0.10 新增] Preload 时间窗口过滤**

`PreloadFromLogFile` 的 `minutes` 参数现在真正生效：
- minutes <= 0 时使用 `preloadDefaultMinutes`（10）
- 扫描完 access.log 后，只保留 `maxTS - minutes*60` 之后的 5min 桶来建基线
- 避免用文件头部的**旧日志**建基线，保证基线反映当前时刻的流量分布

常量：`preloadDefaultMinutes = 10`（默认 10 分钟回溯窗口）

#### 佐证信号判断逻辑（空 Referer 协同置信度保留）

```go
hasCorroborating := (dev4xx > 1 || dev5xx > 1 ||
    devFail > 1 || dev404 > 1 || devSens > 1 ||
    dangerPatternPts > 0 || devBotUA > 1 || dangerMethodPts > 0)

if devEmptyReferer > 1 {
    if hasCorroborating {
        emptyRefPts = deviationToScore(devEmptyReferer, sensitivity)
        detail.EmptyRefererMitigated = false
    } else {
        emptyRefPts = deviationToScore(devEmptyReferer, sensitivity) / 5  // 降级 80%
        detail.EmptyRefererMitigated = true
    }
    maxPts := score_high / 4
    if emptyRefPts > maxPts { emptyRefPts = maxPts }
}
```

#### ScoreResult 结构

```go
type ScoreResult struct {
    FinalScore int            // 最终分数
    Details    [3]ScoreDetail // 三档窗口详情
}

type ScoreDetail struct {
    WindowIndex, WindowSec, TotalScore int
    // 基线偏差得分（相对特征）
    QPSDeviation          float64   // 当前 QPS / P95 QPS（偏离倍数）
    QPSScore              int
    Status4xxDeviation    float64
    Status4xxScore        int
    Status5xxDeviation    float64
    Status5xxScore        int
    AuthFailDeviation     float64
    AuthFailScore         int
    Status404Deviation    float64
    Status404Score        int
    SensitivePathDeviation float64
    SensitivePathScore    int
    BotUADeviation        float64
    BotUAScore            int
    EmptyRefererDeviation float64
    EmptyRefererScore     int
    EmptyRefererMitigated bool     // 空 Referer 是否因无佐证信号而降级
    EmptyRefererSynergy404 bool    // 空 Referer × 404 协同置信度触发
    // 绝对特征固定权重得分
    DangerousPatternScore int
    DangerousMethodScore  int
    FileUploadScore       int
    // 动态敏感度
    EffectiveSensitivity  float64  // 本窗口实际使用的敏感度
    // 基线就绪状态
    BaselineReady         bool     // 对应窗口基线是否已就绪
    // 原始计数
    TotalReq, Count4xx, Count401, Count5xx, Count404 int64
    AuthFail, SensitivePathHit, DangerousPatternHit  int64
    BotUAHit, EmptyRefererHit, DangerousMethod      int64
    StaticResHit                                     int64
}
```

---

### 6.4 ipsetutil - IP 集合管理

**文件**：`internal/ipsetutil/`

#### 职责
- 封装 ipset 命令行调用（Linux 真实模式）
- 管理本地白名单（精确匹配 + CIDR）
- 幂等黑名单操作（已存在则跳过）
- 自动重试（ipset 调用失败时）

#### 核心接口

```go
// Client ipset 底层抽象（便于 Mock）
type Client interface {
    CreateSet(name string) error
    AddIP(set, ip string) error
    DelIP(set, ip string) error
    ListIPs(set string) ([]string, error)
    DestroySet(name string) error
}

// Manager 业务状态机
type Manager struct {
    client    Client
    retry     int
    delay     time.Duration
    localWL   map[string]struct{}   // 白名单精确匹配
    localWLCIDR []*net.IPNet       // 白名单 CIDR
    blocked   map[string]struct{}   // 已在黑名单
}

// 核心方法
func (m *Manager) Block(ip string) (accepted bool, err error)
func (m *Manager) Unblock(ip string) error
func (m *Manager) IsLocalWhitelisted(ip string) bool
func (m *Manager) SyncLocalWhitelist(items []string) error
func (m *Manager) Snapshot() (snapshot.IPSetSnapshot, error)
```

#### 平台适配

| 文件 | 说明 |
|---|---|
| `client_linux.go` | 真实 Linux ipset 调用 |
| `client_mem.go` | 内存 Mock（单元测试 / 非 Linux 开发） |
| `client_nonlinux.go` | 非 Linux 占位 |

#### iptables 规则

```go
// 自动注入的 iptables 规则
iptables -I INPUT -p tcp -m set --match-set wardennet_blacklist src 
         -m multiport --dports 80,443 -j DROP

// 支持的端口（可配置）
DefaultBanPorts = []int{80, 443}
```

---

### 6.5 ttl - TTL 过期管理

**文件**：`internal/ttl/manager.go`

#### 职责
- 管理每条黑名单 IP 的生存时间
- 后台定期清理过期条目（并删除 ipset）
- 区分本地 block vs 云端下发 block 的 TTL

#### 配置

```go
type Config struct {
    LocalBlockTTL  int  // 本地 block 默认 TTL（秒），默认 3600
    CloudBlockTTL  int  // 云端 block TTL 上限
    CloudMaxTTL    int  // 云端最大 TTL
    SweepInterval  int  // 后台清理周期（秒），默认 30
}
```

#### 核心结构

```go
type Entry struct {
    IP        string
    Source    Source  // SourceLocal (0) | SourceCloud (1)
    ExpiresAt int64   // Unix 秒
    CreatedAt int64
    TTL       int     // 原始 TTL（审计用）
}

type Manager struct {
    cfg      Config
    entries  map[string]*Entry
    callback ExpireCallback  // 过期回调（删除 ipset）
}

// 核心方法
func (m *Manager) Add(ip string, ttl int, source Source) (int, error)
func (m *Manager) Remove(ip string) *Entry
func (m *Manager) Count() int
func (m *Manager) SnapshotTTL() (snapshot.TTLSnapshot, error)
```

---

### 6.6 snapshot - 快照持久化

**文件**：`internal/snapshot/manager.go`

#### 职责
- 定期（默认 60s）将 ipset + TTL 状态落盘为 JSON
- 启动时从快照恢复，确保重启不丢黑名单
- 预留心跳状态机接口（Phase 2 用）

#### 快照格式

```json
{
  "version": "v1",
  "timestamp": 1756383600,
  "ipset": {
    "blacklist": ["1.2.3.4", "5.6.7.8"],
    "whitelist": ["10.0.0.0/8"]
  },
  "ttl": {
    "entries": [
      {"ip": "1.2.3.4", "source": 0, "expires_at": 1756387200, "created_at": 1756383600, "ttl": 3600}
    ]
  }
}
```

#### 核心接口

```go
type IPSetProvider interface {
    Snapshot() (IPSetSnapshot, error)
    RestoreIPSet(snap IPSetSnapshot) error
}

type TTLProvider interface {
    SnapshotTTL() (TTLSnapshot, error)
    RestoreTTL(snap TTLSnapshot) (int, error)
}

type Manager struct {
    filePath  string
    interval  time.Duration
    providers []interface{}  // IPSetProvider / TTLProvider
}
```

---

### 6.7 stats - 统计收集

**文件**：`internal/stats/collector.go`

#### 职责
- 聚合检测引擎事件数据
- 生成统计报告（总量/分布/Top IP）
- 支持采样率（降低内存开销）

#### 核心结构

```go
type Collector struct {
    mu           sync.Mutex
    sampleRate   int
    totalEvents  int64
    totalIPs     map[string]struct{}
    // 风险分级计数
    highScoreCount, mediumCount, lowScoreCount int64
    // 维度命中率
    sensitivePathHits, botUAHits, emptyRefererHits int64
    dangerousMethodHits, authFailHits              int64
    // 状态码分布
    status2xx, status3xx, status4xx, status5xx int64
    // Top 10 拉黑 IP
    blockedIPs   map[string]*BlockedIP
}

// 核心方法
func (c *Collector) Record(ev EventRecord)
func (c *Collector) GenerateReport() DetectorReport
func (c *Collector) Reset()
```

#### 报告结构

```go
type DetectorReport struct {
    TotalEvents, TotalIPs int64
    HighScoreCount, MediumCount, LowScoreCount int64
    SensitivePathHits, BotUAHits, EmptyRefererHits int64
    Status2xx, Status4xx, Status5xx int64
    TopBlocked []BlockedIP
    WindowSec  int
}
```

---

### 6.8 cli - 命令行接口

**文件**：`internal/cli/`

#### 职责
- 定义 Agent 本地管理命令接口
- 实现 blocklist / status / reload 命令处理器

#### 命令列表

| 命令 | 说明 | 参数 |
|---|---|---|
| `status` | Agent 状态 | 无 |
| `blocklist.add` | 添加黑名单 IP | `ip`(必填), `ttl`(可选), `force`(可选) |
| `blocklist.del` | 移除黑名单 IP | `ip`(必填) |
| `blocklist.status` | 黑白名单统计 | 无 |
| `reload` | 热重载配置 | 无 |

#### 核心结构

```go
type Request struct {
    Command string                 `json:"command"`
    Args    map[string]interface{} `json:"args,omitempty"`
}

type Response struct {
    Ok      bool        `json:"ok"`
    Error   string      `json:"error,omitempty"`
    Data    interface{} `json:"data,omitempty"`
    Message string      `json:"message,omitempty"`
}

// Handler 命令处理函数
type Handler func(req Request) Response

// Registry 命令注册表
type Registry struct {
    mu       sync.RWMutex
    handlers map[string]Handler
}
```

#### 白名单豁免逻辑
```go
// blocklist.add 命中白名单时返回 skip 错误
if !force && h.IPSet.IsLocalWhitelisted(ip) {
    return Response{Ok: false, Error: "SKIP: ip in local whitelist", ...}
}
```

---

### 6.9 unixsocket - Unix Socket 服务

**文件**：`internal/unixsocket/server.go`

#### 职责
- 提供本地 CLI 通信的 Unix Socket 服务端
- 权限收紧到 0600（仅本机 root 可访问）
- 桥接 cli.Registry 命令到 Unix Socket

#### 核心结构

```go
type Server struct {
    path    string
    reg     *Registry
    listener net.Listener
    stop    chan struct{}
}

func NewServer(path string, reg *Registry) *Server
func (s *Server) Start() error
func (s *Server) Stop()
```

#### 协议格式

```json
// 请求
{"command": "blocklist.add", "args": {"ip": "1.2.3.4"}}

// 响应
{"ok": true, "data": {"ip": "1.2.3.4", "accepted": true, "ttl": 3600}}
```

---

### 6.10 config - 配置管理

**文件**：`internal/config/`

#### 职责
- YAML 配置文件加载
- 配置热重载（5s 间隔检测）
- 配置结构定义

#### 核心配置结构

```go
type Config struct {
    Agent      AgentConfig      // 基础参数
    Log        LogConfig        // 日志配置
    LogSources map[string]LogSource  // 日志源配置
    Detector   DetectorConfig   // 检测引擎配置（基线自学习，仅 7 参数）
    IPSet      IPSetConfig      // IP 集合配置
    UnixSocket UnixSocketConfig // Unix Socket 路径
}

// DetectorSection 基线自学习模式下的检测器配置（仅 7 参数，v0.8 再精简）
type DetectorSection struct {
    Enabled     bool              `yaml:"enabled"`      // 总开关（默认 true）
    Mode        string            `yaml:"mode"`         // block(默认) = 正常封禁；report = 观察者模式（只评分不封禁）
    ScoreHigh   int               `yaml:"score_high"`   // 触发拉黑阈值（默认 50）
    ScoreMedium int               `yaml:"score_medium"` // 中等风险阈值（默认 30），观察名单
    ScoreLow    int               `yaml:"score_low"`    // 低风险记录阈值（默认 10），低于此分不进 debug 日志
    Sensitivity string            `yaml:"sensitivity"`  // high(2x触发) / medium(5x触发,默认) / low(10x触发)
    Weights     ScoreWeights      `yaml:"weights"`      // 3 个绝对特征固定权重（不参与基线学习）
    Windows     [3]DetectorWindow  `yaml:"windows"`      // 三档窗口配置（固定 3 档，各仅 size 字段）

    // 以下为三段式特征列表（见 §6.10）
    KnownHTTPClients  FlexibleFeatureList `yaml:"known_http_clients"`
    SensitivePaths    FlexibleFeatureList `yaml:"sensitive_paths"`
    DangerousPatterns FlexibleFeatureList `yaml:"dangerous_patterns"`

    SkipPaths []string      `yaml:"skip_paths"`  // 跳过路径列表，完全不参与检测
    BodyScan  BodyScanCfg   `yaml:"body_scan"`   // 请求体扫描（默认关闭）
    ResourceBaseline ResourceBaselineCfg `yaml:"resource_baseline"` // IDOR/BOLA（默认关闭）
}

// ScoreWeights 仅 3 个绝对特征权重（不依赖基线、不参与多维度协同封顶）
type ScoreWeights struct {
    DangerousPattern int `yaml:"dangerous_pattern"` // 危险攻击模式（解码后匹配，默认 5）
    DangerousMethod  int `yaml:"dangerous_method"`  // 危险 HTTP 方法（CONNECT/TRACE 等，默认 3）
    FileUpload       int `yaml:"file_upload"`       // 文件上传风险权重（默认 20）
}

// DetectorWindow 窗口配置（仅保留 Size，删除所有 Max* 固定阈值）
type DetectorWindow struct {
    Size int `yaml:"size"`  // 窗口时长（秒），默认 [10, 30, 60]
}
```

> **v0.8 配置再精简**：
> - Mode 从 "enforce"/"report-only" 改为 "block"(默认)/"report"
> - Sensitivity 从 float64 默认 1.0 改为 string (high/medium/low)
> - AbsoluteWeightsCfg 重命名为 ScoreWeights，yaml tag 从 absolute_weights 改为 weights
> - FileUpload 默认权重从 3 改为 20（危险文件上传应更敏感）
> - 新增 ScoreMedium、ScoreLow 阈值
> - Windows 类型从 []WindowCfg 改为 [3]DetectorWindow（固定 3 档）
>
> **v0.7 配置简化**：从 v0.6 的 45 个配置参数精简到 7 个。删除了所有 Max* 固定阈值、夜间模式（NightModeCfg 整个结构体）。这些"权重"现在隐含在 Baseline P95 中，自动学习。

#### 热重载

```go
// 每 5s 检测配置文件变更
func (l *Loader) Watch(interval time.Duration, onErr func(error)) func()
```

---

### 6.11 logger - 日志

**文件**：`internal/logger/logger.go`

#### 职责
- 结构化日志（key=value 格式）
- 文件轮转（lumberjack）
- 日志级别过滤

#### 日志级别

| 级别 | 用途 | 示例 |
|---|---|---|
| `debug` | 详细调试信息 | detector 评分详情、三档窗口计数器 |
| `info` | 正常运行事件 | 启动/停止、自动拉黑、定期统计报告 |
| `warn` | 异常但可恢复 | ipset 操作失败、配置重载失败 |
| `error` | 严重错误 | 无法创建 Unix Socket、配置解析失败 |

---

### 6.12 plugin - 插件系统

**文件**：`internal/plugin/loader.go`

#### 职责
- 真实 .so 动态库加载实现：`stlplugin.Open(path)` + `Lookup('NewPlugin')`
- 无 .so 时零开销降级为 `NoopPlugin`（所有方法空实现，Interface 满足）
- 为 CloudSync / ThreatReporter 等云端能力提供底层 transport 接口

#### 核心接口

```go
type Plugin interface {
    Name() string
    Init(ctx context.Context) error
    OnEvent(ev logparser.Event)
    Close() error
}
```

---

### 6.13 cloudsync - 云端同步调度

**文件**：`internal/cloudsync/`

#### 职责
- 调度四条后台协程完成 Agent ↔ Cloud 双向同步
- 基于版本号（globalBase / globalSeq / tenantSeq）实现增量 Diff
- 驱动 `ipsetutil.Manager.ApplyCloud()` 落地云端黑名单/白名单变更
- `NoopPlugin` 时所有循环跳过，零开销降级

#### 核心结构

```go
type SyncEngine struct {
    p       plugin.Plugin           // CloudPlugin 实例（或 NoopPlugin）
    ipMgr   *ipsetutil.Manager      // 本地 ipset 状态机
    cfg     CloudSection            // 云端配置（tenant_id / endpoint / heartbeat）
    lg      *logger.Logger

    // 版本追踪
    globalBase   int64              // 全局基线版本（need_base 触发 FetchFullGlobalSnapshot）
    globalSeq    int64              // 全局最新序列号（diffLoop 比对用）
    tenantSeq    int64              // 租户维度最新序列号

    // 内部状态
    needDiff     chan struct{}      // heartbeat → diffLoop 触发信号
    fullSync     bool               // full_sync 标志 → FetchTenantSnapshot
}
```

#### 四条后台循环

| 循环 | 触发 | 行为 |
|------|------|------|
| `heartbeatLoop` | 固定间隔（默认 30s） | 向云端发心跳，带回服务端 diff-ready 信号 → `needDiff` channel |
| `diffLoop` | 监听 `needDiff` | **双层 Diff**：global 层 + tenant 层 → 计算差集 → `ipMgr.ApplyCloud()` |
| `commandLoop` | 云端推送 | 处理服务端下发的实时命令（手动拉黑/解封/强制全量同步） |
| `featureLoop` | 后台定时 | 拉取云端特征值/特征列表 → 驱动三段式合并引擎 Cloud 分支 |

#### Diff 应用规则

```
Diff 结果分类                     → 应用路径
─────────────────────────────────────────────────────
云端 blacklist 增量               → ipMgr.ApplyCloud(blacklist)
云端 whitelist 增量               → ipMgr.ApplyCloud(whitelist)
need_base == true                 → FetchFullGlobalSnapshot（全量基线重拉）
full_sync == true                 → FetchTenantSnapshot（租户全量覆盖）
```

#### 优雅降级

```
plugin.Loader 返回 NoopPlugin：
  SyncEngine 四循环全部 return
  ipMgr 维持本地状态不变
  检测链路零影响（核心原则）
```

---

## 7. 核心数据结构

### Event 流转

```
logparser.Event          ← 解析器输出
    │  convertLogEvent()
    ▼
detector.Event           ← 检测引擎输入
    │  det.Process()
    ▼
detector.Event (filled)  ← 含 LocalRiskScore
    │  DetailLogger.LogDetail()
    ▼
stats.EventRecord        ← 统计收集器输入
```

### 关键字段映射

| 字段 | logparser.Event | detector.Event | stats.EventRecord |
|---|---|---|---|
| 时间戳 | `Timestamp (time.Time)` | `Timestamp (int64)` | `Timestamp (int64)` |
| IP | `SourceIP` | `SourceIP` | `SourceIP` |
| 分数 | (0) | `LocalRiskScore` | `Score` |
| 状态码 | `Status` | `Status` | - |

---

## 8. 接口依赖关系图

```
┌─────────────────────────────────────────────────────────────┐
│                         cmd/wardennet/main.go               │
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐    │
│  │   config    │  │   logger    │  │      plugin      │    │
│  └──────┬──────┘  └──────┬──────┘  └────────┬────────┘    │
│         │                │                  │               │
│         ▼                ▼          ┌───────┴───────┐      │
│  ┌─────────────────────────────────┼───────────────┼─┐    │
│  │              logparser          │               │ │    │
│  │  (Tail + Parser)                │               │ │    │
│  └───────────────────────┬─────────┘               │ │    │
│                          │ eventCh                   │ │    │
│                          ▼ convertLogEvent()         │ │    │
│  ┌─────────────────────────────────────────────────┼─┼─┐  │
│  │              detector (LocalDetector)           │ │  │  │
│  │  ┌──────────────┐  ┌──────────┐  ┌─────────────┐│ │  │  │
│  │  │  ipWindow ×3 │  │  Scorer   │  │  Whitelist  ││ │  │  │
│  │  └──────┬───────┘  └────┬─────┘  └──────┬──────┘│ │  │  │
│  │         │  counters     │ score          │ skip?│ │  │  │
│  │         └────────┬──────┘               ┌─┘    │ │  │  │
│  │                  │                      │       │ │  │  │
│  │         BlockTrigger (score >= 50)      │       │ │  │  │
│  │                  │                      │       │ │  │  │
│  │  DetailLogger    ▼                      │       │ │  │  │
│  │  ┌──────────────┐                      │       │ │  │  │
│  │  │ stats.Collector│                      │       │ │  │  │
│  │  └──────────────┘                      │       │ │  │  │
│  └────────┬───────────────────────────────┘       │ │  │  │
│           │ auto block                             │ │  │  │
│           ▼                                        │ │  │  │
│  ┌─────────────────────────────────────────────────┼─┼──┼┐  │
│  │              ipsetutil.Manager             ←─────┘ │  │  │
│  │  ┌──────────────┐  ┌──────────────────────────┐  │  │  │
│  │  │  Client      │  │  iptables rules           │  │  │  │
│  │  └──────────────┘  └──────────────────────────┘  │  │  │
│  └─────────────────────────────────────────────────┼──┼──┘  │
│                          │ Block()/Unblock()        │       │
│                          ▼                          │       │
│  ┌─────────────────────────────────────────────────┐       │
│  │              ttl.Manager                            │   │
│  └───────────────────────┬─────────────────────────────┘   │
│                          │ Snapshot()                       │
│                          ▼                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              snapshot.Manager                       │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              cli.Registry + unixsocket.Server        │   │
│  │  status / blocklist.add / blocklist.del / reload     │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  cloudsync.SyncEngine（v0.6 新增）                   │   │
│  │  ├── plugin.Plugin（transport）  ← plugin.Loader     │   │
│  │  ├── ipsetutil.Manager.ApplyCloud（落地）            │   │
│  │  └── 4 loops: heartbeat / diff / command / feature │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  启动 → 运行 → 优雅关闭：保存快照 + 清理 iptables           │
└─────────────────────────────────────────────────────────────┘
```

---

## 9. 平台适配

### 构建标签（Build Tags）

| 标签 | 文件 | 说明 |
|---|---|---|
| `linux` | `client_linux.go` | 真实 ipset 调用 |
| `linux` | `platform_linux.go` | 初始化 iptables 规则 |
| `!linux` | `client_nonlinux.go` | 非 Linux 占位 |
| `!linux` | `platform_nonlinux.go` | 非 Linux 占位 |

### 平台行为差异

| 功能 | Linux | 非 Linux |
|---|---|---|
| ipset 操作 | 真实命令行调用 | 内存 Mock |
| iptables 规则 | 自动注入 DROP | 不操作 |
| 黑名单持久化 | ipset 内核 + JSON 快照 | 仅 JSON 快照 |
| Unix Socket | `/var/run/wardennet.sock` | 同 Linux |

---

## 10. 特征值与规则表

### 敏感路径关键词（24 个，支持路径段精确匹配）

```go
// 不含 "/" 的关键词 → 路径段精确匹配（env ≠ env.js, admin ≠ admin.js）
// 含 "/" 的关键词 → 子串匹配
// 匹配前自动去除查询字符串 (? 后面的部分)
var sensitivePaths = []string{
    // 中间件/框架探测
    "actuator", "druid", "hystrix", "nacos", "sentinel",
    // 配置文件泄露
    ".env", ".git", "phpinfo", "swagger",
    // Swagger UI 探测
    "swagger-ui", "swagger-resources",
    // 路径穿越
    "../../", "..\\", "%2e%2e", "etc/passwd",
    // 管理后台
    "admin", "console", "manager", "phpmyadmin", "wp-admin",
    // 备份扫描
    "backup", "env",
}
```

**匹配规则示例**：

| 路径 | 关键词 | 匹配方式 | 命中 |
|------|--------|---------|------|
| `/tdsc/js/env.js` | `env` | 段"env.js"≠"env" | ❌ |
| `/api/env?user=1` | `env` | 段"env"="env"（查询串已去除） | ✅ |
| `/.env` | `.env` | 段".env"=".env" | ✅ |
| `/admin.js` | `admin` | 段"admin.js"≠"admin" | ❌ |
| `/api/admin/users` | `admin` | 段"admin"="admin" | ✅ |
| `/etc/passwd` | `etc/passwd` | 子串匹配 | ✅ |

**注意**：敏感路径命中仅在 **status >= 400** 时计入计数（window.go Record 阶段过滤）。

### Bot UA 关键词（19 个）+ 已知 HTTP 客户端豁免（14 个）

```go
// botUserAgents 扫描器/攻击工具关键词
var botUserAgents = []string{
    // 扫描器
    "nikto", "sqlmap", "nmap", "masscan",
    "dirbuster", "gobuster", "wfuzz", "hydra",
    "metasploit", "burpsuite",
    // 测绘工具
    "zgrab", "censys", "shodan", "zoomeye",
}

// knownHTTPClients 合法 HTTP 客户端（不判定为 Bot）
var knownHTTPClients = []string{
    "okhttp",             // Square's OkHttp (Android/Java)
    "apache-httpclient",  // Apache HttpClient (Java)
    "resttemplate",       // Spring RestTemplate (Java)
    "webclient",          // Spring WebClient (Java)
    "httpclient",         // Generic HTTP client
    "java/",              // Generic Java HTTP
    "python-requests",    // Python requests library
    "httpx",              // Python httpx library
    "aiohttp",            // Python async HTTP
    "go-http-client",     // Go net/http
    "axios",              // JavaScript axios
    "fetch",              // JavaScript fetch
    "postman",            // Postman API testing
    "insomnia",           // Insomnia API testing
}
```

**UA 检测逻辑**：先检查 `knownHTTPClients` → 命中则直接返回 `false`；再检查 `botUserAgents` → 命中返回 `true`；空 UA 返回 `true`。

### 静态资源扩展名（12 个）

```go
var staticResourceExt = []string{
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".eot",
}
```

### 危险 HTTP 方法（6 个）

```go
var dangerousHTTPMethods = map[string]bool{
    "CONNECT": true,  // 代理穿透
    "TRACE":   true,  // 调试追踪
    "DELETE":  true,  // 资源删除
    "PUT":     true,  // 资源更新
    "PATCH":   true,  // 部分更新
    "OPTIONS": true,  // CORS 探测
}
```

### 危险攻击模式（50+ 个，解码后匹配）

```go
// defaultDangerousPatterns 覆盖 8 类攻击：
// SQL 注入：select, union select, or 1=1, drop table, sleep(, ...
// XSS：<script, javascript:, onerror=, alert(, ...
// 路径遍历：../, etc/passwd, proc/self, ...
// 命令注入：; cat, | wget, $(, ...
// 命令执行：system(, exec(, shell_exec(, ...
// 文件包含：file_get_contents(, include(, ...
// SSRF：127.0.0.1, 169.254., metadata, ...
// SSTI：${, {{, <%=, ...
//
// 解码支持：URL 编码(%xx)、Unicode(\uXXXX)、Hex(\xHH)、HTML entity(&#60;)
// 三重循环解码处理多层编码（如 %2527 → %27 → '）
```

**检测逻辑**：路径先解码，再与模式列表做子串匹配。无论状态码多少都计数（200 响应的注入尝试同样危险）。

### 三段式特征列表架构

```
┌─────────────────────────────────────────────────────┐
│              三段式特征列表合并引擎                    │
│                                                     │
│  ① Builtin（程序内置）  ← 代码中的默认值              │
│  ② Local（用户配置）   ← YAML 中的 local 字段        │
│  ③ Cloud（云端拉取）   ← 云端威胁情报 API             │
│                                                     │
│  → 合并去重 → 应用 Excludes → 最终生效列表            │
└─────────────────────────────────────────────────────┘
```

**核心 API**：
```go
// 合并单个特征列表
result := detector.ResolveFeatureList(
    builtinItems,    // 内置默认值
    featureConfig,   // FeatureListConfig{Local, Excludes, DisableBuiltin, DisableCloud}
    cloudItems,      // 云端条目（可为 nil）
)
// result.Items  → 最终去重后的列表
// result.Sources → 每个条目的来源（"builtin"/"local"/"cloud"/"builtin+cloud"）
// result.Excluded → 被排除的条目及原始来源

// 云端拉取接口
type CloudFeatureFetcher interface {
    FetchLatest(tenantID string, currentVersion int64) (*CloudFeatureList, error)
}
```

**YAML 配置格式**（向后兼容）：
```yaml
# 格式一：简单列表
known_http_clients: ["okhttp", "python-requests"]

# 格式二：结构化（支持排除项）
known_http_clients:
  local: ["okhttp", "python-requests", "java-http"]
  excludes: ["java-http"]   # 排除确实存在的业务路径/UA
  disable_builtin: false    # 禁用内置默认值
  disable_cloud: false      # 禁用云端拉取
```

---

## 11. 扩展点与待开发接口

### 已预留扩展点

| 扩展点 | 位置 | 接口 |
|---|---|---|
| 自定义日志解析器 | `logparser/parser.go` | `Parser` 接口 + `Registry.Register()` |
| 自定义检测维度 | `detector/scorer.go` | 权重配置 + `ScoreWithDetail()` |
| 自定义特征模式 | `detector/decode.go` | `defaultDangerousPatterns` 列表 + YAML `dangerous_patterns` |
| 云端威胁情报 | `detector/featurelist.go` | `CloudFeatureFetcher` 接口 + `NoopFeatureFetcher` |
| 特征列表排除 | `detector/featurelist.go` | `FeatureListConfig.Excludes` 字段 |
| 自定义插件（已落地） | `plugin/loader.go` | `Plugin` 接口 + `stlplugin.Open` 真实 .so 加载 + `NoopPlugin` 降级 |
| 云端同步调度（已落地） | `cloudsync/engine.go` | `SyncEngine` 四协程 + 双层 Diff + 版本追踪 |
| 云端命令下发 | `cloudsync/engine.go` | `SyncEngine.commandLoop` → `ipMgr.ApplyCloud()` |
| 心跳状态 | `snapshot/manager.go` | `HeartbeatState` 枚举 |

### 待开发任务（Phase 2）

| 任务 | 说明 | 计划文档 |
|---|---|---|
| 任务 9 | 云端基础设施搭建 | `.trae/specs/wardenet-mvp-v0.1/tasks.md` |
| 任务 10 | Agent ↔ Cloud API 契约 | 同上 |
| 任务 11 | 租户与 Agent 接入 | 同上 |
| 任务 12-18 | 云端 SaaS 各功能模块 | 同上 |
| 任务 22 | 云端特征值动态同步 | `.trae/documents/features_cloud_sync_plan.md` |

### 测试覆盖

| 包 | 测试文件 | 覆盖范围 |
|---|---|---|
| `logparser` | `parsers_test.go` | 4 种解析器表驱动测试 |
| `logparser` | `tail_test.go` | Tail 续读 + 轮转检测 |
| `detector` | `detector_test.go` | 滑动窗口 + 打分逻辑 + 防误杀机制（34 个测试用例） |
| `detector` | `featurelist_test.go` | 三段式特征列表合并引擎（14 个测试用例） |
| `ipsetutil` | `manager_test.go` | 黑白名单状态机 |
| `ttl` | `manager_test.go` | TTL 过期清理 |
| `snapshot` | `manager_test.go` | 快照持久化 |
| `stats` | `collector_test.go` | 统计收集 |
| `cli` | `handler_test.go` | CLI 命令处理 |
| `unixsocket` | `server_test.go` | Unix Socket 通信 |
| `config` | `loader_test.go` | 配置加载 |
| `plugin` | `loader_test.go` | 插件加载 |
| `logger` | `logger_test.go` | 日志轮转 |

---

## 附录：文件快速索引

| 模块 | 核心文件 | 功能 |
|---|---|---|
| 入口 | [main.go](file:///d:/coder/business/WardenNet/agent/cmd/wardennet/main.go) | 19 步启动流程（含基线预扫描） |
| 适配 | [adapter.go](file:///d:/coder/business/WardenNet/agent/cmd/wardennet/adapter.go) | 接口适配器 |
| 日志采集 | [tail.go](file:///d:/coder/business/WardenNet/agent/internal/logparser/tail.go) | 文件 tail 续读 |
| 解析器 | [parser.go](file:///d:/coder/business/WardenNet/agent/internal/logparser/parser.go) | 解析器接口 + Registry |
| Nginx | [nginx.go](file:///d:/coder/business/WardenNet/agent/internal/logparser/nginx.go) | Nginx access log |
| Tomcat | [tomcat.go](file:///d:/coder/business/WardenNet/agent/internal/logparser/tomcat.go) | Tomcat access log |
| 检测 | [detector.go](file:///d:/coder/business/WardenNet/agent/internal/detector/detector.go) | 检测器主体 |
| 窗口 | [window.go](file:///d:/coder/business/WardenNet/agent/internal/detector/window.go) | 滑动窗口 + 特征值 |
| 基线 | [baseline.go](file:///d:/coder/business/WardenNet/agent/internal/detector/baseline.go) | P95 分位数自学习引擎 |
| 打分 | [scorer.go](file:///d:/coder/business/WardenNet/agent/internal/detector/scorer.go) | 基线偏差 + 绝对特征固定权重 |
| 详情 | [detail.go](file:///d:/coder/business/WardenNet/agent/internal/detector/detail.go) | 评分详情结构 |
| 解码 | [decode.go](file:///d:/coder/business/WardenNet/agent/internal/detector/decode.go) | 路径解码 + 危险模式匹配 |
| 特征列表 | [featurelist.go](file:///d:/coder/business/WardenNet/agent/internal/detector/featurelist.go) | 三段式合并引擎 |
| IP 管理 | [manager.go](file:///d:/coder/business/WardenNet/agent/internal/ipsetutil/manager.go) | 黑白名单状态机 |
| TTL | [manager.go](file:///d:/coder/business/WardenNet/agent/internal/ttl/manager.go) | TTL 过期管理 |
| 快照 | [manager.go](file:///d:/coder/business/WardenNet/agent/internal/snapshot/manager.go) | 状态持久化 |
| 统计 | [collector.go](file:///d:/coder/business/WardenNet/agent/internal/stats/collector.go) | 统计收集 |
| CLI | [handler.go](file:///d:/coder/business/WardenNet/agent/internal/cli/handler.go) | 命令处理器 |
| Socket | [server.go](file:///d:/coder/business/WardenNet/agent/internal/unixsocket/server.go) | Unix Socket 服务 |
| 配置 | [config.go](file:///d:/coder/business/WardenNet/agent/internal/config/config.go) | 配置结构 |
| 日志 | [logger.go](file:///d:/coder/business/WardenNet/agent/internal/logger/logger.go) | 日志器 |
| 插件 | [loader.go](file:///d:/coder/business/WardenNet/agent/internal/plugin/loader.go) | 插件加载 |
