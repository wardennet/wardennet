# 项目规格说明书 spec.md
## 1. 项目基础信息
技术栈：
数据库：
架构分层：
公共通用模块：common、utils、exception、security

## 2. 全局业务规则
1. 权限规则：xxx
2. 数据校验规则：xxx
3. 接口统一返回格式：xxx
4. 异常码定义：xxx

## 3. 模块划分
| 模块名 | 职责范围 | 核心接口 | 对应数据库表 |
|--------|----------|----------|--------------|
| 用户模块 | 用户登录、信息管理 | /api/user/login | t_user |
| 业务模块 | 核心业务流程 | /api/order/create | t_order |

## 4. 接口契约（节选示例）
### 接口1：创建订单
请求地址：POST /api/order/create
请求参数：
{
  "userId": Long,
  "goodsId": Long,
  "num": Integer
}
响应参数：
{
  "code": 200,
  "msg": "success",
  "data": {"orderId": Long}
}
校验规则：num必须大于0，userId必须存在

## 5. 禁止实现范围
1. 暂不开发xx功能
2. 不做xx权限逻辑
3. 数据库不新增xx字段