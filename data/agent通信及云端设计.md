# WardenNet Agent?服务端通信与服务端设计开发文档

> 
> 文档版本：V1.1
> 迭代区分：V0.1 MVP（千级节点，抖动轮询） / V1.0（十万?百万节点，大规模增强）
> 前置约束：
> 
> 
> 1. 全局?租户双层Diff架构；**租户私有白名单裁决下沉Agent本地执行，云端不生成反向remove**
> 2. 全局情报L2/L3、公共特征库：云端每10分钟定时生成全局增量Diff，支持紧急手动触发生成；每日生成全局基准快照
> 3. V0.1不实现长轮询wait?notify；V1.0才引入独立Go信号网关做wait?notify长轮询
> 4. Agent本地具备完整防护能力，云端情报属于联防增强，不是第一拦截手段
> 5. 系统全局白名单：云端全局Diff阶段直接过滤，不下发给任何Agent；租户私有白名单仅下发集合，冲突由Agent本地裁决

## 目录

1. 总体设计目标
2. 架构分层总览
3. 身份鉴权模型
4. 数据版本模型（全局版本 + 租户版本）
5. V0.1 MVP 通信协议（抖动短轮询）
6. V1.0大规模增强：wait?notify长轮询信号网关设计
7. Diff数据包完整定义
8. 服务端模块详细设计
9. Agent侧通信状态机
10. 存储、缓存策略
11. 限流、降级、故障保护
12. 业务规则约束
13. V0.1 / V1.0功能开关边界
14. 风险与注意事项

---

## 1. 总体设计目标

1. **V0.1 MVP目标（千级Agent）**
   - 架构简单易实现，不需要额外中间件/网关；
   - Agent采用`10min ±20%随机抖动`轮询，区间8?12分钟；
   - 全局基准+全局增量diff + 租户私有diff；
   - 通信包含：Agent上报证据、Agent拉取diff变更集；
   - 鉴权、签名校验、限流、TTL、降级断网逻辑完整。
2. **V1.0大规模目标（十万~百万Agent）**
   - 新增独立Go语言实现wait?notify信号网关，只做变更信号通知，不执行业务计算、不访问PG；
   - 信号唤醒后Agent增加随机抖动延迟再拉取diff，解决惊群风暴；
   - Agent长轮询失败自动降级为8?12min抖动短轮询兜底；
   - 全局基准快照放对象存储，业务服务只返回下载URL，卸载带宽压力。

> 
> 核心原则：
> 
> 
> - 全局公共情报只生成一份，所有租户复用；租户独有数据仅保存在租户diff；
> - 系统全局白名单云端过滤；租户私有白名单下发集合，**黑名单与白名单冲突裁决全部下沉Agent本地**；
> - Agent断网可完全本地独立运行，不依赖云端。

## 2. 架构分层总览

### V0.1 MVP分层

```
Agent(Golang)
    ↓ HTTPS
Python FastAPI SaaS业务服务
    ├─鉴权中间件
    ├─证据上报服务
    ├─diff生成服务（全局diff + 租户diff）
    ├─租户/威胁情报/白名单业务服务
    ├─Redis缓存（diff缓存、限流、计数器）
    └─PostgreSQL持久存储
```

### V1.0大规模完整分层

```
Agent(Golang)
   ↓ HTTPS
┌─────────────────┐
│ Go信号网关(wait?notify) │ ← 只维护TCP长连接、Redis Pub/Sub订阅，不访问PG
└────────┬────────┘
         │信号事件
         ↓
Python FastAPI SaaS业务服务
    ├─鉴权中间件
    ├─证据上报服务
    ├─diff生成服务（全局diff +租户diff）
    ├─租户/威胁情报/白名单业务服务
    ├─Redis（pub/sub事件、diff缓存、限流）
    ├─PostgreSQL持久库
    └─对象存储S3：存放全局基准快照
```

> 
> 重要：Python业务进程**不承接大量长轮询hold连接**；长轮询全部交给独立Go网关。

## 3. 身份鉴权模型

1. Agent接入凭证：`agent_id + agent_secret`，绑定唯一`tenant_id`
2. 所有Agent请求必须HTTP请求头携带：

```
X?Agent?Id: <agent_id>
X?Signature: <HMAC?SHA256签名>
```

- 签名算法：对请求path + timestamp + request_body做HMAC?SHA256，密钥为agent_secret
- 请求携带时间戳，服务端校验时间戳偏差不能超过60s，防重放攻击

3. 校验失败返回：`code:10002 鉴权失败`
4. 一个agent_id严格归属一个tenant_id，禁止跨租户访问其他租户diff数据。

## 4. 数据版本模型

### 4.1 全局版本（公共情报，所有租户共用）

- `global_base`：每日基准快照标识，格式`base?YYYYMMDD`，例如 `base?20260831`
- `global_incr_seq`：全局增量序号，每一次生成全局增量diff该序号+1；每10min定时任务生成，支持API紧急触发生成。

> 
> 每日零点生成新的`global_base?YYYYMMDD`基准快照，丢弃前一天全部global_incr_seq增量diff。
> Agent如果本地`global_base`不等于服务端当日基准 → 需要拉取完整当日全局基准快照。

### 4.2 租户私有版本

每个租户独立 `tenant_seq`（整数）

- 租户发生变更（租户L1增删、租户私有白名单增删、远程指令），该租户`tenant_seq +=1`。
- 每个租户保留最近N条租户增量变更（例如N=30）；版本差距超过阈值，返回`full_sync:true`，下发租户私有全量快照。

### Agent本地持久保存版本状态

Agent本地快照持久存储：

```
{
  "global": {
    "base": "base?20260831",
    "incr_seq": 10
  },
  "tenant": {
    "seq": 42
  }
}
```

## 5. V0.1 MVP通信协议（抖动短轮询）

> 
> V0.1不实现wait?notify长轮询。Agent轮询基础间隔10分钟，叠加±20%随机抖动，实际轮询区间8?12min。
> Agent联网恢复时，**不等待轮询计时，立刻执行一次diff拉取，快速补全状态**。

### 5.1 接口1：拉取Diff变更集

`GET /api/sync/diff`
请求头：`X?Agent?Id`、`X?Signature`
Query参数：

- `global_base`
- `global_incr_seq`
- `tenant_seq`

响应JSON结构（统一外层code/msg/data）：

```
{
  "code": 200,
  "msg": "success",
  "data": {
    "global": {
      "need_base": false,
      "base_name": "base?20260831",
      "incr_list": [
        {
          "incr_seq":11,
          "add_list": [{"ip":"1.1.1.1","level":"L3","ttl":7200}],
          "remove_list":["2.2.2.2"],
          "feature_add":[{"id":"feat_001","type":"path","match_type":"literal","pattern":"/phpmyadmin/","risk_weight":35}],
          "feature_remove":["feat_002"]
        }
      ]
    },
    "tenant": {
      "full_sync": false,
      "tenant_seq": 44,
      "add_list": [{"ip":"10.0.0.5","level":"L1","ttl":3600}],
      "remove_list": [],
      "whitelist_add": ["192.168.1.100"],
      "whitelist_remove": []
    }
  }
}
```

#### 响应字段说明

1. `global.need_base=true`：Agent本地全局base不是当日基准，**需要拉取当日完整全局基准快照**。
2. `global.incr_list`：需要应用的全局增量diff数组，按seq从小到大顺序执行。
3. `tenant.full_sync=true`：租户版本差距超限，Agent拉取租户私有完整快照。
4. `tenant.add_list / remove_list`：**仅本租户产出的L1黑名单**；不包含全局L2/L3。
5. `tenant.whitelist_add / whitelist_remove`：租户私有白名单变更集合。> 
> ??云端不会为租户私有白名单生成黑名单反向remove；黑名单与白名单冲突全部由Agent本地裁决。

### 5.2 接口2：拉取全局完整基准快照

`GET /api/sync/global?base?snapshot?base_name=base?20260831`

> 
> V0.1直接返回完整JSON快照；V1.0返回对象存储下载URL，卸载业务服务带宽。
> 返回内容：完整全局黑名单集合、系统全局过滤后黑名单、公共特征库集合。

### 5.3 接口3：拉取租户私有完整快照

`GET /api/sync/tenant?snapshot`
返回：该租户私有L1黑名单全集、租户私有白名单全集。

### 5.4 接口4：Agent上报攻击证据

`POST /api/evidence/report`
请求头鉴权签名；请求体events事件数组、evidence_files对象存储key列表。

> 
> 原有spec定义不变。
> 约束：`linux_auth`审计日志证据默认拒绝接收；租户一票制、时间戳校验、QPS限流。

### Agent本地diff应用顺序（严格不可调换）

1. 如果`need_base=true`：下载并应用**全局基准快照**
2. 按seq升序，逐条应用`global.incr_list`内全部全局增量diff
3. 如果`tenant.full_sync=true`：应用租户私有快照
4. 应用租户私有diff的`add_list/remove_list`、`whitelist_add/whitelist_remove`
5. **本地裁决优先级逻辑**：
 收到黑名单add条目时，先判断：
 `本地配置白名单 > 系统全局白名单 > 租户私有白名单`
 命中任意白名单 → 跳过ipset拉黑；若IP已存在黑名单则执行ipset del。
 收到`whitelist_add`：若IP已经存在本地黑名单集合，立刻执行ipset del。
 收到`whitelist_remove`：若IP仍然存在黑名单集合，重新执行ipset add。

## 6. V1.0大规模增强：wait?notify长轮询信号网关设计

> 
> V1.0才启用；V0.1不实现。

### 6.1 Go信号网关职责（独立服务）

1. 对外暴露接口 `GET /api/sync/wait?notify`，做HTTP长轮询；
2. 维护大量Agent TCP连接；每个连接保存 `agent_id、tenant_id、本地tenant_seq、本地global_incr_seq`；
3. 订阅Redis Pub/Sub两个事件通道：
   - `event:global_change`：全局diff生成完成发布该事件；
   - `event:tenant:{tenant_id}`：租户发生私有变更发布事件；
4. 收到对应事件，唤醒对应Agent长轮询连接，返回`has_change:true`；
5. 长轮询最大兜底超时12min，超时返回`has_change:false`；
6. **禁止访问PostgreSQL，禁止计算diff，不处理业务逻辑**。

> 
> 返回wait?notify响应示例：

```
{"code":200,"msg":"ok","data":{"has_change":true}}
```

### 6.2 Agent在V1.0状态机

1. 优先发起wait?notify长轮询；
2. 收到`has_change:true` → **执行0?5s随机抖动延迟**，再调用`/api/sync/diff`拉取真实diff；拉取完成，再次回到wait?notify；
3. 收到超时返回`has_change:false` → 立即重新发起wait?notify；
4. 连续N次长轮询失败 → **自动降级切换到V0.1的8?12min抖动短轮询兜底**；网络恢复正常后切回长轮询。

### 6.3 事件发布规则（SaaS业务服务）

1. 全局diff（基准/增量）生成完成：发布 `event:global_change` 到Redis Pub/Sub；
2. 租户发生私有变更(L1、私有白名单、远程指令)：发布 `event:tenant:{tenant_id}`；只唤醒该租户下所有Agent。

> 
> 重要：全局事件会唤醒全部在线Agent，**必须依靠Agent侧抖动延迟打散diff拉取请求，防止惊群脉冲风暴**。

## 7. 服务端模块详细设计

### 7.1 模块划分

1. **鉴权安全模块**
   - Agent签名校验、时间戳防重放、tenant?agent_id绑定校验；
   - 接口全局异常码体系（spec.md定义：10001~30001）。
2. **证据上报模块**
   - 接收Agent上报事件；租户一票制防刷；新租户72h冷却降权；
   - 原始证据写入对象存储，PG仅存UUID引用；QPS限流。
3. **威胁情报引擎**
   - L1/L2/L3等级流转、分数衰减定时任务；
   - 全局L2/L3情报管理；公共特征库管理。
4. **白名单管理模块**
   - 系统全局白名单：生成全局diff阶段直接过滤，IP不会下发给任何Agent；
   - 租户私有白名单：仅存储，输出到租户diff的whitelist_*字段；**云端不做黑名单剔除计算**。
5. **全局Diff生成定时任务**
   - ①每日定时：生成当日`global_base?YYYYMMDD`完整基准快照；存入对象存储；
   - ②每10min定时任务：生成一份全局增量diff，global_incr_seq自增；
   - ③提供内部API，支持**紧急手动触发立即生成全局增量diff**（应对突发高危扫描）；
   - 生成完成发布Redis `event:global_change`事件；
   - 自动清理过期的昨日全部global_incr_seq增量。
6. **租户Diff生成服务**
   - 根据`tenant_id`、客户端上报`tenant_seq`，读取租户L1变更、租户私有白名单变更；
   - 如果版本差距在保留窗口内，生成合并后的租户增量diff；
   - 如果版本差距超过阈值，返回full_sync=true，输出租户完整快照；
   - 租户发生变更后，tenant_seq +=1，发布Redis `event:tenant:{tenant_id}`事件；
7. **Diff缓存服务**
   - Redis缓存：全局增量diff、租户合并diff结果；
   - key设计：`diff:global:{incr_seq}`，`diff:tenant:{tenant_id}:{from_seq}`
   - 设置合理TTL，避免缓存无限膨胀；热路径优先读取Redis，减少PG查询。
8. **定时清理任务**
   - TTL自动清理威胁记录、证据、白名单过期记录；
   - 清理过期diff变更日志；
9. **Web后台管理模块**
   - 管理员：全局情报、全局白名单、公共特征库、租户管理；
   - 租户管理员：本租户私有白名单、L1共享开关、申诉工单；
   - 后台提示：云端情报同步存在8?12分钟延迟；紧急操作建议使用Agent本地CLI。

## 8. 存储与缓存策略

1. **PostgreSQL**
   - 威胁情报表：`wardenet_ip_threat`（L1/L2/L3，分数、等级、TTL）
   - 租户表、agent节点表、白名单表、证据元数据表、审计日志表、diff_changelog变更事件表。
   - changelog仅用于diff计算与审计；**不直接原样下发给Agent，云端做合并之后输出单份diff**。
2. **Redis**
   - diff结果缓存；
   - Pub/Sub事件（V1.0大规模）；
   - 限流计数器、签名时间戳防重放、版本标记。
3. **对象存储 / 本地文件**
   - 原始攻击证据片段；
   - V1.0存放全局基准快照大文件。

> 
> 热路径（Agent同步diff接口）尽量命中Redis缓存，减少PG查询压力。

## 9. 限流、降级、故障保护

### 9.1 Agent侧保护

1. 所有http请求指数退避重试；
2. diff拉取失败不影响Agent本地防护；
3. V1.0长轮询失败自动降级抖动短轮询。

### 9.2 服务端限流

1. `/api/evidence/report`：单Agent QPS限流，超限返回429(10006)；
2. `/api/sync/diff`接口：全局限流 + 单agent限流；
3. V1.0全局基准快照下载接口做限流；Agent请求快照必须带随机抖动。

### 9.3 故障降级

1. diff缓存失效：降级直接从PG计算diff结果；
2. Redis不可用：V0.1可以继续运行（失去缓存，性能下降）；V1.0长轮询网关失去pub/sub事件，Agent全部自动切到抖动短轮询兜底。

## 10. 关键业务规则约束（不可修改）

1. **系统全局白名单**：全局diff生成阶段过滤，IP不下发给Agent；租户私有白名单只下发集合，黑名单?白名单冲突裁决全部下沉Agent本地。
2. 全局diff包含L2/L3黑名单、公共特征库；**不包含任何租户私有L1、租户私有白名单**。
3. 租户diff只包含：租户L1黑名单变更、租户私有白名单变更。
4. Agent应用diff顺序严格：全局基准 → 全局增量集合 →（租户快照）→ 租户私有diff。
5. 白名单只做封禁豁免，**云端不修改、不删除威胁证据、威胁等级记录**。
6. 全局diff每10分钟定时生成，保留紧急触发接口；每日生成新全局基准快照，丢弃昨日增量。
7. Agent断网降级：完全使用本地快照运行，本地检测、本地ipset拦截不受影响。
8. L1情报永远不会跨租户泄露。

## 11. V0.1 MVP 与 V1.0功能边界

| 功能 | V0.1 MVP | V1.0大规模 |
| --- | --- | --- |
| 同步模式 | 8?12min ±20%抖动短轮询 | wait?notify长轮询 + 抖动短轮询降级兜底 |
| 全局基准快照接口 | 直接返回JSON报文 | 返回对象存储下载URL，卸载带宽 |
| Go独立wait?notify信号网关 | ?不实现 | ?实现 |
| Redis Pub/Sub事件通知 | ?无 | ?有 |
| 百万级节点适配 | ?仅千级 | ?十万?百万 |
| 全局?租户双层diff | ?实现 | ?继承 |
| 租户白名单裁决下沉Agent | ?实现 | ?继承 |

## 12. 风险与注意事项

1. V0.1不要引入长轮询网关，避免过度设计，增加开发复杂度。
2. V1.0严禁Python业务进程hold大量长轮询连接，会耗尽线程池。
3. V1.0全局事件唤醒全部Agent，**Agent必须增加随机抖动延迟再拉diff，防止惊群脉冲流量**。
4. Agent后台操作（租户白名单、远程解封）V0.1最大生效延迟12分钟；后台UI需要提示延迟，本地CLI作为紧急兜底手段。
5. 全局diff 10min是云端生成粒度，不是Agent最小轮询间隔。
6. 本地防护优先，云端联防情报是增强能力，不能作为唯一拦截手段。
