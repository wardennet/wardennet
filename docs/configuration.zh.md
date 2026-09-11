# 配置参考

> 配套文档：[README](../README.zh.md) · [架构总览](./architecture.zh.md) · [快速开始](./quick-start.zh.md)

配置文件默认路径 `/etc/wardennet/config.yaml`，所有字段**未声明时使用内置默认值**。

> 完整示例见 `agent/configs/wardennet.yaml.example`

---

## 目录

1. [配置加载规则](#1-配置加载规则)
2. [agent 段](#2-agent-段)
3. [log 段](#3-log-段)
4. [stats 段](#4-stats-段)
5. [log_sources 段](#5-log_sources-段)
6. [detector 段](#6-detector-段)
7. [ipset 段](#7-ipset-段)
8. [unix_socket 段](#8-unix_socket-段)
9. [cloud 段（可选）](#9-cloud-段可选)
10. [ttl 段](#10-ttl-段)

---

## 1. 配置加载规则

优先级（高 → 低）：

1. 启动参数 `--config /path/to/config.yaml`
2. 环境变量 `WARDENNET_CONFIG=/path/to/config.yaml`
3. 默认路径 `/etc/wardennet/config.yaml`
4. 内置默认值

缺失字段静默回退到默认值，不报错。

---

## 2. agent 段

```yaml
agent:
  local_block_ttl: 3600   # 本地拉黑默认 TTL（秒）
  cloud_block_ttl: 7200   # 云端下发拉黑 TTL 上限（秒）
  cloud_max_ttl:   86400  # 云端下发等级最大 TTL 上限（秒）
```

| 字段 | 默认 | 说明 |
|------|------|------|
| `local_block_ttl` | 3600 | 本地 detector 触发的拉黑有效时间 |
| `cloud_block_ttl` | 7200 | 云端下发的 TTL 不得超过此值（安全兜底） |
| `cloud_max_ttl` | 86400 | 云端等级最大 TTL |

---

## 3. log 段

```yaml
log:
  level: info           # debug / info / warn / error
  file: /var/log/wardennet/agent.log   # 空字符串则仅 stdout
  max_size:    100      # 单文件最大 MB
  max_backups: 7        # 保留旧文件数
  max_age:     30       # 旧文件保留天数
  compress:    true     # gzip 压缩旧文件
```

生产环境建议 `level: info`。`debug` 会输出每个请求的详细打分明细，量大。

---

## 4. stats 段

```yaml
stats:
  report_interval: 60   # 秒；0 禁用
```

每 60 秒输出一次累计统计：`processed_events` / `total_ips` / `high_score_count` / `top_blocked` 等。

---

## 5. log_sources 段

多日志源支持，每个源独立配置：

```yaml
log_sources:
  nginx_access:
    path: /var/log/nginx/access.log
    parser: nginx_access
    # allow_upload: true        # 默认 true；云端协同开启时是否上报

  apache_access:
    path: /var/log/apache2/access.log
    parser: apache_access

  tomcat_access:
    path: /usr/local/tomcat/logs/localhost_access_log.txt
    parser: tomcat_access

  linux_auth:
    path: /var/log/auth.log
    parser: linux_auth
    # allow_upload: false       # 默认 false；数据最小化合规

  # 自定义正则格式
  custom_app:
    path: /var/log/myapp/access.log
    parser: custom
    custom_regex: '^(\S+) - - \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) (\d+) "([^"]*)" "([^"]*)"'
    regex_groups:
      ip: 1
      time: 2
      request_method: 3
      request_path: 4
      status: 5
      bytes: 6
      referer: 7
      uagent: 8
```

可用 parser：`nginx_access` / `apache_access` / `tomcat_access` / `linux_auth` / `custom`

---

## 6. detector 段

### 基础开关与阈值

```yaml
detector:
  enabled: true               # 总开关
  score_high: 50              # 触发本地拉黑候选的风险分阈值
  score_medium: 30            # 中等风险阈值（进入观察名单）
  score_low: 15               # 低风险阈值（仅统计记录）

  # ---- 灵敏度分档（三档内置，无需细调权重）----
  # high:   偏离 2x 即触发 — 高风险业务
  # medium: 偏离 5x         — 默认推荐
  # low:    偏离 10x        — 宽松场景
  sensitivity: medium

  # ---- 运行模式 ----
  # block:  正常封禁
  # report: 只评分上报，不封禁（上线初期安全过渡）
  mode: block
```

### 特征列表（三段式合并架构）

三种特征列表字段支持**双格式**：

```yaml
# 格式一：简单列表（向后兼容）
known_http_clients: ["okhttp", "python-requests", "curl"]
sensitive_paths: ["/.env", "/admin/config"]
dangerous_patterns: ["\\.\\./", "union.*select"]

# 格式二：结构化（推荐）
known_http_clients:
  local: ["my-custom-client"]   # 追加到内置默认
  excludes: ["internal-api"]    # 从默认里排除
  disable_builtin: false
  disable_cloud: false
```

三段式合并规则：

```
最终列表 = Builtin(默认) + CloudFetch(云端) + Local(用户配置)
           - Excludes(用户排除)
           [ - disable_builtin → 跳过 Builtin ]
           [ - disable_cloud   → 跳过 CloudFetch ]
```

### Consistency 评分参数（可选）

```yaml
detector:
  consistency:
    prefix_coherence_threshold: 0.5
    path_concentration_threshold: 0.4
    status_homogeneity_threshold: 0.6
    method_semantics_weight: 0.3
    scanner_behavior_weight: 0.5
```

未声明时使用代码内置默认值（平衡值）。

---

## 7. ipset 段

```yaml
ipset:
  whitelist:
    - "127.0.0.1"
    - "::1"
    - "10.0.0.0/8"
    - "192.168.0.0/16"
  blacklist: []     # 本地预加载黑名单（断网模式兜底）
```

**白名单硬约束**：命中白名单 → 跳过所有检测与拉黑。可配精确 IP 或 CIDR。

---

## 8. unix_socket 段

```yaml
unix_socket:
  path: /var/run/wardennet.sock
```

默认 `/var/run/wardennet.sock`，权限 0600。

---

## 9. cloud 段（可选）

```yaml
cloud:
  enabled: false
  base_url: https://api.wardenet.io
  tenant_id: your-tenant-id
  agent_secret: your-agent-secret
```

| 字段 | 说明 |
|------|------|
| `enabled` | 启用云端协同。需要**同时** `libcloudplugin.so` 存在才生效 |
| `base_url` | Cloud SaaS 地址 |
| `tenant_id` | SaaS 注册后获得 |
| `agent_secret` | SaaS 注册后获得（HMAC 鉴权用） |

> 没有 CloudPlugin 时即使 `cloud.enabled: true` 也不会发任何请求，Agent 输出 warn 日志后跳过。

---

## 10. ttl 段

```yaml
ttl:
  default_ttl: 3600         # 默认秒数
  cleanup_interval: 60      # 扫描间隔秒
```