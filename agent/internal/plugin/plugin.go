// Package plugin 定义 WardenNet Agent 的云端商业插件加载骨架。
//
//  Phase 1：无插件模式下 Agent 100% 单机运行，所有云端能力通过 NoopPlugin 静默降级。
//  Phase 2：加载 libcloudplugin.so 获得鉴权 / 上报 / 双层 Diff / 远程指令 / wait-notify 能力。
//
//  所有接口与数据结构对齐 docs/agent通信及云端设计.md v1.1。
package plugin

// ===== 上下文与数据结构 =====

// AuthContext 插件鉴权入参。
type AuthContext struct {
	AgentID   string `json:"agent_id"`
	Secret    string `json:"secret"`
	Token     string `json:"token"`
	Signature string `json:"signature"`
	Timestamp int64  `json:"timestamp"`
	Hostname  string `json:"hostname,omitempty"`
	Version   string `json:"version,omitempty"`
	OS        string `json:"os,omitempty"`
}

// AuthResult 插件鉴权结果。
type AuthResult struct {
	OK      bool   `json:"ok"`
	Err     string `json:"err,omitempty"`
	AgentID string `json:"agent_id,omitempty"`
	Expires int64  `json:"expires,omitempty"`
}

// ReportEvent 上报载荷结构体。Type/Timestamp/Payload 三元组用于云端上报的事件序列化。
type ReportEvent struct {
	Type      string `json:"type"`      // detection_alert / block_action / heartbeat
	Timestamp int64  `json:"timestamp"`
	Payload   string `json:"payload"`   // JSON 字符串
}

// ---- 双层 Diff 数据结构（对齐设计文档 §5.1）----

// DiffRequest Diff 同步请求（Agent 本地状态摘要）。
type DiffRequest struct {
	AgentID    string `json:"agent_id"`
	TenantID   string `json:"tenant_id"`
	GlobalBase string `json:"global_base"`     // base-YYYYMMDD
	GlobalSeq  int64  `json:"global_incr_seq"` // 当前全局增量序号
	TenantSeq  int64  `json:"tenant_seq"`      // 当前租户序号
	LastSyncAt int64  `json:"last_sync_at"`
}

// ThreatScore 云端下发的威胁评分项（V2 安全防御层核心）。
// Agent 收到后结合本地 detector 评分综合决策，云端不直接下发拉黑指令。
type ThreatScore struct {
	IP        string  `json:"ip"`
	Score     float64 `json:"score"`      // 0-100 云端威胁评分
	VoteCount int     `json:"vote_count,omitempty"`  // 独立投票租户数（全局池有值）
	Source    string  `json:"source,omitempty"`       // global / private
}

// GlobalIncr 全局单条增量（对齐设计文档 §5.1 incr_list 项）。
type GlobalIncr struct {
	IncrSeq       int64                  `json:"incr_seq"`
	ThreatAdd     []ThreatScore          `json:"threat_add,omitempty"`
	FeatureAdd    []map[string]interface{} `json:"feature_add,omitempty"`
	FeatureRemove []string               `json:"feature_remove,omitempty"`
}

// DecisionWeightsConfig 云端下发的决策引擎权重。
// 可选，DiffResult 和 GlobalSnapshot 都可以携带。
// 三项权重之和应 ≈ 1.0（Agent 会做 normalize 校验）。
// 语义绑定：三个子得分都是 0-100 范围，权重是"综合决策时各维度的相对重要性"。
type DecisionWeightsConfig struct {
	Cloud    float64 `json:"cloud,omitempty"`    // 云端评分权重（默认 0.4）
	Local    float64 `json:"local,omitempty"`    // 本地频率评分权重（默认 0.3）
	Detector float64 `json:"detector,omitempty"` // detector 评分权重（默认 0.3）
}

// DiffResult Diff 同步结果（云端下发，双层格式）。
type DiffResult struct {
	OK  bool   `json:"ok"`
	Err string `json:"err,omitempty"`

	Global struct {
		NeedBase     bool          `json:"need_base"`
		BaseName     string        `json:"base_name"`
		ThreatScoring []ThreatScore `json:"threat_scoring,omitempty"` // V2：全局共享池评分快照
		IncrList     []GlobalIncr  `json:"incr_list"`
	} `json:"global"`

	Tenant struct {
		FullSync      bool          `json:"full_sync"`
		TenantSeq     int64         `json:"tenant_seq"`
		ThreatScoring []ThreatScore `json:"threat_scoring,omitempty"`
		WhiteAdd      []string      `json:"whitelist_add"`
		WhiteDel      []string      `json:"whitelist_remove"`
	} `json:"tenant"`

	// v1.2 新增：决策引擎权重。云端可热更 Agent 综合决策公式的权重系数。
	// nil 或三个字段都为 0 时 Agent 使用默认值（0.4/0.3/0.3）。
	// 安全设计：Agent 收到权重后做 normalize 校验——三项之和必须在 [0.5, 1.5] 范围内，
	// 否则拒绝应用（防止云端被投毒下发极端权重）。
	DecisionWeights *DecisionWeightsConfig `json:"decision_weights,omitempty"`

	ServerTime int64 `json:"server_time,omitempty"`
}

// GlobalSnapshot 全局 base 快照。
type GlobalSnapshot struct {
	BaseName      string         `json:"base_name"`
	ThreatScoring []ThreatScore  `json:"threat_scoring,omitempty"`
	FeatureList   []map[string]interface{} `json:"features"`
	ServerTime    int64          `json:"server_time,omitempty"`
}

// TenantSnapshot 租户完整快照。
type TenantSnapshot struct {
	TenantID      string         `json:"tenant_id"`
	ThreatScoring []ThreatScore  `json:"threat_scoring,omitempty"`
	WhiteAdd      []string       `json:"whitelist_add"`
	WhiteDel      []string       `json:"whitelist_remove"`
	ServerTime    int64          `json:"server_time,omitempty"`
}

// ScoringWeightsConfig 云端下发的特征库权重（ScoreWeights 的 plugin 层镜像）。
// 独立于 detector.ScoreWeights 定义，避免 plugin 包依赖 detector 包（项目硬约束：零跨内部包依赖）。
// 所有字段为正整数，0 表示"不调整此维度权重"（保留本地默认值）。
type ScoringWeightsConfig struct {
	DangerousPattern int `json:"dangerous_pattern,omitempty"`
	DangerousMethod  int `json:"dangerous_method,omitempty"`
	HeadMethod       int `json:"head_method,omitempty"`
	FileUpload       int `json:"file_upload,omitempty"`
}

// FeatureResult 特征值同步结果。
type FeatureResult struct {
	Version  int64                    `json:"version"`
	Features []map[string]interface{} `json:"features"`

	// v1.2 新增：特征库权重。跟 FeatureResult 同步下发（可选）。
	// 表示云端想覆盖 Agent 本地 ScoreWeights 的某个维度（非零才覆盖）。
	Weights *ScoringWeightsConfig `json:"weights,omitempty"`
}

// RemoteCommand 云端下发的远程指令。
type RemoteCommand struct {
	ID        string                 `json:"id"`
	Command   string                 `json:"command"` // reload/status/shutdown/block.add/block.del/...
	Args      map[string]interface{} `json:"args,omitempty"`
	Timestamp int64                  `json:"timestamp"`
}

// CommandResult 远程指令执行结果。
type CommandResult struct {
	ID   string      `json:"id"`
	Ok   bool        `json:"ok"`
	Err  string      `json:"err,omitempty"`
	Data interface{} `json:"data,omitempty"`
}

// ===== Plugin 接口 =====

// Plugin 云端商业插件接口。所有方法必须并发安全。
// Agent 端核心业务逻辑（detector / ipset / ttl / logparser）**不依赖**任何具体实现，
// 仅通过此接口调用云端能力。无插件时 NoopPlugin 静默降级。
type Plugin interface {
	// ---- 生命周期 ----
	Init(agentID, version string) error
	Shutdown() error

	// ---- 鉴权 ----
	// Auth: V0.1 MVP 注册 / 获取 secret；V1.0 也支持心跳验证
	Auth(ctx AuthContext) (AuthResult, error)
	// Heartbeat: 定时心跳；返回 needDiff=true 表示 Agent 应立即拉取 Diff
	Heartbeat() (needDiff bool, err error)

	// ---- 数据上报 ----
	// ReportFull: 完整上报接口，接收完整 detector.Event 列表
	//   闭源插件内部负责：
	//     1. 防投毒校验（信誉评分 / 批量刷票检测 / IP 画像 / 行为一致性）
	//     2. 商业评分调整
	//     3. 聚合去重
	//     4. 合规裁剪 → 只上传最小威胁情报载荷
	ReportFull(events interface{}) error

	// ---- Diff 同步（双层格式，对齐设计文档 §5.1）----
	// Diff: 拉取双层 Diff（全局增量 + 租户增量）
	Diff(req DiffRequest) (DiffResult, error)
	// FetchFullGlobalSnapshot: 拉取全局 base 快照
	FetchFullGlobalSnapshot() (GlobalSnapshot, error)
	// FetchTenantSnapshot: 拉取租户完整快照
	FetchTenantSnapshot() (TenantSnapshot, error)

	// ---- 远程指令 ----
	// HandleCommand: 执行云端下发的指令（block.add/remove/reload/...）
	HandleCommand(cmd RemoteCommand) (CommandResult, error)
	// FetchPendingCommands: V0.1 轮询模式拉取待执行指令；V1.0 wait-notify 插件内部自管理
	FetchPendingCommands() ([]RemoteCommand, error)

	// ---- 特征值 ----
	// FetchFeatures: 同步云端特征值
	FetchFeatures(tenantID string, currentVersion int64) (*FeatureResult, error)
}

// ===== NoopPlugin — 离线模式实现 =====

// NoopPlugin 无插件降级实现：所有方法返回安全默认值，不 panic、不阻塞、不持有外部资源。
// 确保 Agent 在无任何云端依赖时 100% 单机运行。
type NoopPlugin struct{}

var _ Plugin = (*NoopPlugin)(nil) // 编译期断言 NoopPlugin 实现 Plugin 接口

// Init 实现 Plugin 接口。
func (n *NoopPlugin) Init(agentID, version string) error { return nil }

// Shutdown 实现 Plugin 接口。
func (n *NoopPlugin) Shutdown() error { return nil }

// Auth 实现 Plugin 接口。
func (n *NoopPlugin) Auth(ctx AuthContext) (AuthResult, error) {
	return AuthResult{OK: false, Err: "no plugin"}, nil
}

// Heartbeat 实现 Plugin 接口 — 离线模式不需要拉 Diff。
func (n *NoopPlugin) Heartbeat() (bool, error) { return false, nil }

// ReportFull 实现 Plugin 接口 — 静默丢弃，离线模式无云端上报。
func (n *NoopPlugin) ReportFull(events interface{}) error { return nil }

// Diff 实现 Plugin 接口 — 关键：返回 OK:true + 全空，Agent 同步 goroutine 认为无变更。
func (n *NoopPlugin) Diff(req DiffRequest) (DiffResult, error) {
	var result DiffResult
	result.OK = true
	result.Global.NeedBase = false
	result.Global.BaseName = ""
	result.Global.IncrList = nil
	result.Tenant.FullSync = false
	result.Tenant.TenantSeq = req.TenantSeq
	result.Tenant.WhiteAdd = nil
	result.Tenant.WhiteDel = nil
	return result, nil
}

// FetchFullGlobalSnapshot 实现 Plugin 接口 — 返回空快照。
func (n *NoopPlugin) FetchFullGlobalSnapshot() (GlobalSnapshot, error) {
	return GlobalSnapshot{FeatureList: nil}, nil
}

// FetchTenantSnapshot 实现 Plugin 接口 — 返回空租户快照。
func (n *NoopPlugin) FetchTenantSnapshot() (TenantSnapshot, error) {
	return TenantSnapshot{WhiteAdd: nil, WhiteDel: nil}, nil
}

// HandleCommand 实现 Plugin 接口 — 提示 Agent 当前离线。
func (n *NoopPlugin) HandleCommand(cmd RemoteCommand) (CommandResult, error) {
	return CommandResult{ID: cmd.ID, Ok: false, Err: "no plugin"}, nil
}

// FetchPendingCommands 实现 Plugin 接口 — 无远程指令。
func (n *NoopPlugin) FetchPendingCommands() ([]RemoteCommand, error) {
	return nil, nil
}

// FetchFeatures 实现 Plugin 接口 — 返回空特征值，detector 降级为本地静态特征。
func (n *NoopPlugin) FetchFeatures(tenantID string, currentVersion int64) (*FeatureResult, error) {
	return &FeatureResult{Version: currentVersion, Features: nil}, nil
}