# 贡献指南

> 配套文档：[README](../README.zh.md) · [架构总览](./architecture.zh.md)

感谢你对 WardenNet Agent 的关注！本文档适用于本开源仓库的贡献。

---

## 目录

1. [开源范围](#1-开源范围)
2. [开发环境](#2-开发环境)
3. [代码规范](#3-代码规范)
4. [架构红线](#4-架构红线)
5. [提交流程](#5-提交流程)
6. [测试要求](#6-测试要求)

---

## 1. 开源范围

| 目录 | 许可 | 说明 |
|------|------|------|
| `agent/`（不含闭源 cloudplugin） | AGPLv3 | Go 客户端核心，本仓库内容 |
| `agent/internal/cloudplugin/` | 闭源 | Cloud SaaS 对接实现，不包含 |
| `cloud/` + Web 前端 | 闭源 | 商业 SaaS 平台 |

**本指南仅适用于开源部分**。Cloud SaaS 和闭源插件禁止未经授权的复制或分发。

---

## 2. 开发环境

### Go 环境

```bash
cd agent
go build ./...
go vet ./...
go test ./...
```

| 项目 | 要求 |
|------|------|
| Go SDK | >= 1.27 |
| 编译目标 | Windows/macOS 上自动内存 Mock；Linux 上真实 ipset/iptables |
| 格式化 | `gofmt`（Go 官方标准，无需额外工具） |

### 运行无插件模式（单机）

```bash
cd agent/cmd/wardennet
go run .
```

无 `libcloudplugin.so` 时 Agent 自动进入单机模式（NoopPlugin）。Windows 上用内存 Mock Client，`go run` 直接可用。

---

## 3. 代码规范

### 硬性规则

- **文件不超过 500 行**，超过必须拆分到子模块
- **业务逻辑在独立模块**，CLI/网络层只做编排（`main.go` 只负责启动装配）
- **禁止 `_ = someFunc()` 吞错误**，每个 `error` 必须处理
- **测试优先**：每个功能改动附单元测试，无裸代码提交
- **并发代码必须 `go test -race` 通过**

### Go 风格

遵循 [Effective Go](https://go.dev/doc/effective_go) + `gofmt`。

几个常见约定：

```go
// 包注释一句话说明职责
package detector // Package detector implements sliding-window attack scoring.

// 错误必须命名为 Err*
var ErrInvalidConfig = errors.New("invalid configuration")

// 内部模块间用 interface 解耦，便于 Mock 测试
type WhitelistChecker interface {
    Contains(ip string) bool
}
```

### 配置与常量

- 运行时阈值用 YAML 配置 + 代码默认值，不能硬编码魔法数
- 编译期常量用 `const`（如 `ObserveWindowSec = 30`）
- 闭源插件用 build tag `plugin` 隔离

---

## 4. 架构红线

以下规则**严禁违反**，违反的 PR 会被拒绝：

### 红线 1：禁止绕过 Plugin 接口

```go
// ❌ 禁止
import "github.com/wardenet/agent/internal/cloudplugin"

// ✅ 正确
import "github.com/wardenet/agent/internal/plugin"
// 调用 plugin.Plugin.Auth() / plugin.Plugin.Diff() 等
```

### 红线 2：禁止在开源端发 HTTP

```go
// ❌ 禁止
resp, err := http.Post("https://api.wardenet.io/...", ...)

// ✅ 所有云端能力必须走 plugin.Plugin 接口
```

### 红线 3：禁止在开源端持有云端凭证

`cloudsync` 包只能持有 `plugin.Plugin` 接口引用，不能 import cloudclient、不能存 `agent_secret`。

### 红线 4：模块零交叉依赖

| 开源包 | 可依赖 | 不可依赖 |
|--------|--------|----------|
| `detector` | `logger`, `config` | `ipsetutil`, `cloudsync`, `plugin` |
| `cloudsync` | `plugin`, `ipsetutil`, `config` | `cloudplugin`（闭源）, `http` 标准库 |
| `ipsetutil` | `logger` | `detector`, `cloudsync` |

**原则**：下层包不能知道上层包的存在。detector 不知道 ipsetutil；ipsetutil 不知道 detector。主程序 `main.go` 负责组装它们。

### 红线 5：不修改双端技术栈

- Agent 保持 Go，Cloud SaaS 保持 Python FastAPI
- 不换 Go 版本（固定 >= 1.27）

---

## 5. 提交流程

1. Fork 本仓库，创建特性分支
   ```bash
   git checkout -b feature/add-xxx
   # 或
   git checkout -b fix/issue-xxx
   ```

2. 本地开发 + 测试
   ```bash
   cd agent
   go build ./...
   go vet ./...
   go test -race ./...
   ```

3. 提交
   ```bash
   git add .
   git commit -m "feat(detector): add xxx scoring dimension"
   ```

4. Push 并创建 Pull Request

### Commit 消息格式

采用 [Conventional Commits](https://www.conventionalcommits.org/)：

```
<type>(<scope>): <subject>

feat(detector): add MAD-based outlier removal
fix(ipsetutil): handle empty whitelist CIDR parsing
docs(architecture): update data flow diagram
refactor(cli): extract handler from main.go
test(detector): add baseline cold start regression test
```

types: `feat` / `fix` / `docs` / `refactor` / `test` / `chore` / `build` / `ci`

---

## 6. 测试要求

### 单元测试

- 每个 `internal/*` 包应有对应的 `_test.go`
- 表驱动测试优先
- Mock 依赖（用 interface 解耦）
- `go test -race` 必须通过

### 已有测试清单（参考）

| 包 | 测试文件 | 覆盖重点 |
|----|----------|----------|
| `detector` | `detector_test.go` / `consistency_test.go` / `window.go` 内嵌测试 | 滑动窗口、评分、多事件确认 |
| `ipsetutil` | `manager_test.go` / `priority_test.go` | 白名单优先、ApplyCloud 顺序 |
| `cloudsync` | `decision_test.go` | 综合决策引擎 |
| `config` | `loader_test.go` | 配置合并、默认值回退 |
| `logparser` | `parsers_test.go` / `tail_test.go` | 多格式解析、tail 续读 |
| `pidlock` | `pidlock_linux_test.go` | Flock 单实例互斥 |

### 不强制

- 纯数据结构转换的 Adapter（`cmd/wardennet/adapter.go`）可以不写独立测试
- 配置示例 YAML 不写测试

---

## License

贡献代码即同意以 AGPLv3 许可授权。闭源 CloudPlugin 和 Cloud SaaS 不在此范围。