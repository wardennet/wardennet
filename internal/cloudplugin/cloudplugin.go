
// Package main — WardenNet CloudPlugin 闭源插件实现。
//
// 编译：
//
//	go build -buildmode=plugin -o libcloudplugin.so ./libcloudplugin/
//
// 主进程通过 plugin.Open("/usr/lib/wardennet/libcloudplugin.so") 加载，
// Lookup("NewPlugin") 拿到工厂函数，返回的 CloudPlugin 完整实现
// github.com/wardennet/agent/internal/plugin.Plugin 接口。
package cloudplugin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/wardennet/agent/internal/plugin"
)

// CloudPlugin 闭源云端插件主实现。
// 所有 HTTP 调用委托给 HTTPClient；Agent 端的 cloudsync 调度引擎负责调用时机。
type CloudPlugin struct {
	mu       sync.Mutex
	cfgJSON  string           // Init 时接收的完整配置 JSON
	version  string           // Agent 版本（Init 时传入）
	agentID  string           // Auth 后云端返回的 agent_id
	tenantID string           // 从 CloudSection 配置读取
	baseURL  string           // 从 CloudSection 配置读取
	agentSecret string       // HMAC 密钥

	// 运行时 HTTP 客户端（Auth 后初始化，因为 auth 路径和后续路径共用）
	http *HTTPClient

	initialized bool
}

// NewPlugin 导出工厂函数，主进程通过 plugin.Open 后 Lookup("NewPlugin") 获取。
func NewPlugin() plugin.Plugin {
	return &CloudPlugin{}
}

// Init 实现 Plugin.Init。
// cfg 参数是 cloudsync 传入的 CloudSection JSON（含 base_url / tenant_id / agent_secret 等），
// CloudPlugin 内部解析后初始化 HTTPClient。
func (c *CloudPlugin) Init(cfg string, agentVersion string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.initialized {
		return nil // 幂等
	}

	c.cfgJSON = cfg
	c.version = agentVersion

	// 解析 CloudSection JSON
	var raw struct {
		Enabled     bool   `json:"Enabled"`
		BaseURL     string `json:"BaseURL"`
		TenantID    string `json:"TenantID"`
		AgentSecret string `json:"AgentSecret"`
	}
	if err := json.Unmarshal([]byte(cfg), &raw); err != nil {
		return fmt.Errorf("parse cloud config: %w", err)
	}

	if !raw.Enabled || raw.BaseURL == "" {
		return fmt.Errorf("cloud not configured: enabled=%v base_url=%q", raw.Enabled, raw.BaseURL)
	}

	c.baseURL = raw.BaseURL
	c.tenantID = raw.TenantID
	c.agentSecret = raw.AgentSecret

	c.http = NewHTTPClient(c.baseURL, "", c.tenantID, c.agentSecret)
	c.initialized = true

	return nil
}

// Shutdown 实现 Plugin.Shutdown。清理内部资源。
func (c *CloudPlugin) Shutdown() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.initialized = false
	return nil
}

// ===== 鉴权 =====

// Auth 实现 Plugin.Auth。注册 Agent 到云端，拿到 agent_id 与可能的新 secret。
// AuthContext.Secret 优先来自 cloudsync 的 AuthContext 入参，fallback 到 Init 时的 CloudSection。
func (c *CloudPlugin) Auth(ctx plugin.AuthContext) (plugin.AuthResult, error) {
	c.mu.Lock()
	secret := ctx.Secret
	if secret == "" {
		secret = c.agentSecret
	}
	c.mu.Unlock()

	// 注意：register 接口是无鉴权的（首次注册还没有 secret），
	// 所以空 secret 是合法场景——Agent 第一次上线时就靠这一步拿 secret。
	// 如果有 secret（非首次），也可以带上去做鉴权；
	// 如果没有 secret，register 接口允许匿名调用（只需要 tenant_id + hostname）。

	c.mu.Lock()
	http := c.http
	c.mu.Unlock()
	if http == nil {
		return plugin.AuthResult{OK: false, Err: "http client not initialized"}, nil
	}

	body := map[string]string{
		"tenant_id":     c.tenantID,
		"hostname":      ctx.Hostname,
		"os":            runtime.GOOS,
		"agent_version": c.version,
	}
	if secret != "" {
		body["secret"] = secret
	}

	// Auth 阶段还不知道 agent_id（注册后才拿到），临时用空 agent_id 请求 register
	// 云端 register 接口是无鉴权的（首次注册还没有 secret），所以不需要签名
	// 但 HTTPClient.Sign 在空 agent_id + 空 secret 时会生成空签名——能通过 register 的"无签名"校验
	resp, httpErr := c.http.doRequest("POST", "/api/agent/register", body, nil)
	if httpErr != nil {
		return plugin.AuthResult{OK: false, Err: httpErr.Error()}, nil
	}
	data, httpErr2, apiErr := parseResponse(resp)
	if httpErr2 != nil || apiErr != nil {
		msg := ""
		if httpErr2 != nil {
			msg = httpErr2.Error()
		} else {
			msg = apiErr.Error()
		}
		return plugin.AuthResult{OK: false, Err: msg}, nil
	}

	// 解析返回的 agent_id
	var result struct {
		AgentID       string `json:"agent_id"`
		Secret        string `json:"secret"`
		CloudEndpoint string `json:"cloud_endpoint"`
		Existing      bool   `json:"existing"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return plugin.AuthResult{OK: false, Err: "parse auth response: " + err.Error()}, nil
	}

	// 记录 agent_id，后续 Diff/Command 用
	c.mu.Lock()
	c.agentID = result.AgentID
	if result.Secret != "" {
		c.agentSecret = result.Secret
	}
	c.mu.Unlock()

	// 用新的 agent_id 重建 http client，后续请求签名带上
	c.http = NewHTTPClient(c.baseURL, result.AgentID, c.tenantID, c.agentSecret)

	return plugin.AuthResult{
		OK:      true,
		AgentID: result.AgentID,
	}, nil
}

// Heartbeat 实现 Plugin.Heartbeat。
// 云端心跳同时返回"是否有 Diff 变更"的提示（need_diff 字段）。
func (c *CloudPlugin) Heartbeat() (bool, error) {
	c.mu.Lock()
	agentID := c.agentID
	c.mu.Unlock()

	if agentID == "" {
		return false, fmt.Errorf("heartbeat: agent_id not known yet (auth first)")
	}

	body := map[string]interface{}{
		"agent_id":        agentID,
		"tenant_id":      c.tenantID,
		"timestamp":      time.Now().Unix(),
		"global_base":    "", // 心跳不携带版本，Diff 自己会带
		"global_incr_seq": 0,
		"tenant_seq":     0,
	}

	resp, err := c.http.doRequest("POST", "/api/sync/v2/heartbeat", body, nil)
	if err != nil {
		return false, err
	}
	_, httpErr, apiErr := parseResponse(resp)
	if httpErr != nil || apiErr != nil {
		return false, fmt.Errorf("heartbeat response: %v %v", httpErr, apiErr)
	}

	// 心跳合一接口已经返回了 Diff 数据，但 CloudPlugin.Heartbeat 只返回 needDiff 标志。
	// 云端心跳接口已自动推进 diff 状态，cloudsync 引擎看到 needDiff 会再次调用 Diff() 拉完整数据。
	// 这里直接返回 needDiff=true 让 Agent 立刻触发 Diff 拉取（简化实现，保证数据新鲜）
	return true, nil
}

// ===== Diff 同步（双层格式）=====

// Diff 实现 Plugin.Diff。POST /api/sync/v2/diff，解析双层 DiffResult。
func (c *CloudPlugin) Diff(req plugin.DiffRequest) (plugin.DiffResult, error) {
	c.mu.Lock()
	http := c.http
	c.mu.Unlock()
	if http == nil {
		return plugin.DiffResult{OK: false, Err: "http client not ready"}, nil
	}

	body := map[string]interface{}{
		"tenant_id":       req.TenantID,
		"global_base":     req.GlobalBase,
		"global_incr_seq": req.GlobalSeq,
		"tenant_seq":      req.TenantSeq,
	}

	resp, err := http.doRequest("POST", "/api/sync/v2/diff", body, nil)
	if err != nil {
		return plugin.DiffResult{OK: false, Err: err.Error()}, nil
	}
	data, httpErr, apiErr := parseResponse(resp)
	if httpErr != nil || apiErr != nil {
		return plugin.DiffResult{OK: false, Err: fmt.Sprintf("%v %v", httpErr, apiErr)}, nil
	}

	var raw struct {
		Global struct {
			NeedBase      bool                     `json:"need_base"`
			BaseName      string                   `json:"base_name"`
			ThreatScoring []map[string]interface{} `json:"threat_scoring"`
			IncrList      []map[string]interface{} `json:"incr_list"`
		} `json:"global"`
		Tenant struct {
			FullSync      bool                     `json:"full_sync"`
			TenantSeq     int64                    `json:"tenant_seq"`
			ThreatScoring []map[string]interface{} `json:"threat_scoring"`
			WhiteAdd      []string                 `json:"whitelist_add"`
			WhiteDel      []string                 `json:"whitelist_remove"`
		} `json:"tenant"`
		ServerTime int64 `json:"server_time"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return plugin.DiffResult{OK: false, Err: "parse diff: " + err.Error()}, nil
	}

	result := plugin.DiffResult{
		OK:         true,
		ServerTime: raw.ServerTime,
	}
	result.Global.NeedBase = raw.Global.NeedBase
	result.Global.BaseName = raw.Global.BaseName

	// V2：解析全局 threat_scoring
	for _, item := range raw.Global.ThreatScoring {
		result.Global.ThreatScoring = append(result.Global.ThreatScoring, parseThreatScore(item))
	}

	// 解析全局增量
	for _, incrRaw := range raw.Global.IncrList {
		incr := plugin.GlobalIncr{}
		if v, ok := incrRaw["incr_seq"].(float64); ok {
			incr.IncrSeq = int64(v)
		}
		if list, ok := incrRaw["threat_add"].([]interface{}); ok {
			for _, item := range list {
				if m, ok := item.(map[string]interface{}); ok {
					incr.ThreatAdd = append(incr.ThreatAdd, parseThreatScore(m))
				}
			}
		}
		if list, ok := incrRaw["feature_add"].([]interface{}); ok {
			for _, item := range list {
				if m, ok := item.(map[string]interface{}); ok {
					incr.FeatureAdd = append(incr.FeatureAdd, m)
				}
			}
		}
		if list, ok := incrRaw["feature_remove"].([]interface{}); ok {
			for _, s := range list {
				if str, ok := s.(string); ok {
					incr.FeatureRemove = append(incr.FeatureRemove, str)
				}
			}
		}
		result.Global.IncrList = append(result.Global.IncrList, incr)
	}

	// 租户层
	result.Tenant.FullSync = raw.Tenant.FullSync
	result.Tenant.TenantSeq = raw.Tenant.TenantSeq
	for _, item := range raw.Tenant.ThreatScoring {
		result.Tenant.ThreatScoring = append(result.Tenant.ThreatScoring, parseThreatScore(item))
	}
	result.Tenant.WhiteAdd = raw.Tenant.WhiteAdd
	result.Tenant.WhiteDel = raw.Tenant.WhiteDel

	return result, nil
}

// parseThreatScore 从云端返回的 map 中提取 ThreatScore。
// 兼容字段：score 可能是 float64（JSON 默认）也可能是 int。
func parseThreatScore(m map[string]interface{}) plugin.ThreatScore {
	ts := plugin.ThreatScore{}
	if ip, ok := m["ip"].(string); ok {
		ts.IP = ip
	}
	if score, ok := m["score"]; ok {
		switch v := score.(type) {
		case float64:
			ts.Score = v
		case int:
			ts.Score = float64(v)
		}
	}
	if vc, ok := m["vote_count"].(float64); ok {
		ts.VoteCount = int(vc)
	}
	if src, ok := m["source"].(string); ok {
		ts.Source = src
	}
	return ts
}

// FetchFullGlobalSnapshot 实现 Plugin.FetchFullGlobalSnapshot。
func (c *CloudPlugin) FetchFullGlobalSnapshot() (plugin.GlobalSnapshot, error) {
	c.mu.Lock()
	http := c.http
	c.mu.Unlock()
	if http == nil {
		return plugin.GlobalSnapshot{}, fmt.Errorf("http client not ready")
	}

	resp, err := http.doRequest("GET", "/api/sync/v2/global-snapshot", nil, nil)
	if err != nil {
		return plugin.GlobalSnapshot{}, err
	}
	data, httpErr, apiErr := parseResponse(resp)
	if httpErr != nil || apiErr != nil {
		return plugin.GlobalSnapshot{}, fmt.Errorf("%v %v", httpErr, apiErr)
	}

	var raw struct {
		BaseName      string                   `json:"base_name"`
		ThreatScoring []map[string]interface{} `json:"threat_scoring"`
		Features      []map[string]interface{} `json:"features"`
		ServerTime    int64                    `json:"server_time"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return plugin.GlobalSnapshot{}, err
	}

	var scores []plugin.ThreatScore
	for _, item := range raw.ThreatScoring {
		scores = append(scores, parseThreatScore(item))
	}

	return plugin.GlobalSnapshot{
		BaseName:      raw.BaseName,
		ThreatScoring: scores,
		FeatureList:   raw.Features,
		ServerTime:    raw.ServerTime,
	}, nil
}

// FetchTenantSnapshot 实现 Plugin.FetchTenantSnapshot。
func (c *CloudPlugin) FetchTenantSnapshot() (plugin.TenantSnapshot, error) {
	c.mu.Lock()
	http := c.http
	tenantID := c.tenantID
	c.mu.Unlock()
	if http == nil {
		return plugin.TenantSnapshot{}, fmt.Errorf("http client not ready")
	}

	resp, err := http.doRequest("GET", "/api/sync/v2/tenant-snapshot?tenant_id="+urlEscape(tenantID), nil, nil)
	if err != nil {
		return plugin.TenantSnapshot{}, err
	}
	data, httpErr, apiErr := parseResponse(resp)
	if httpErr != nil || apiErr != nil {
		return plugin.TenantSnapshot{}, fmt.Errorf("%v %v", httpErr, apiErr)
	}

	var raw struct {
		TenantID      string                   `json:"tenant_id"`
		ThreatScoring []map[string]interface{} `json:"threat_scoring"`
		WhitelistAdd  []string                 `json:"whitelist_add"`
		WhitelistDel  []string                 `json:"whitelist_remove"`
		ServerTime    int64                    `json:"server_time"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return plugin.TenantSnapshot{}, err
	}

	var scores []plugin.ThreatScore
	for _, item := range raw.ThreatScoring {
		scores = append(scores, parseThreatScore(item))
	}

	return plugin.TenantSnapshot{
		TenantID:      raw.TenantID,
		ThreatScoring: scores,
		WhiteAdd:      raw.WhitelistAdd,
		WhiteDel:      raw.WhitelistDel,
		ServerTime:    raw.ServerTime,
	}, nil
}

// ===== Nonce + Digest 工具 =====

// requestNonce 向云端请求一次性 Nonce + 云端时间戳。
// 使用 V1 签名（还没拿到 nonce，所以消息里不含 nonce）。
// Returns:
//   nonce    - 云端分配的一次性令牌
//   serverTs - 云端返回的 Unix 时间戳（用于签名，避免 Agent 时钟偏移）
//   err      - 请求/解析错误
func (c *CloudPlugin) requestNonce() (nonce string, serverTs int64, err error) {
	c.mu.Lock()
	http := c.http
	c.mu.Unlock()
	if http == nil {
		return "", 0, fmt.Errorf("http client not ready")
	}

	// nonce 接口在鉴权后才能调用，用 V1 签名（空 nonce + 空 events_digest）
	body := map[string]interface{}{}
	resp, reqErr := http.doRequest("POST", "/api/agent/nonce", body, nil)
	if reqErr != nil {
		return "", 0, reqErr
	}
	data, httpErr, apiErr := parseResponse(resp)
	if httpErr != nil || apiErr != nil {
		return "", 0, fmt.Errorf("nonce response: %v %v", httpErr, apiErr)
	}

	var result struct {
		Nonce     string `json:"nonce"`
		Timestamp int64  `json:"timestamp"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return "", 0, fmt.Errorf("parse nonce: %w", err)
	}
	return result.Nonce, result.Timestamp, nil
}

// computeEventsDigest 对 FinalThreatPayload 列表计算私有 Digest（WARDENNET_DIGEST_V1）。
// 与云端 _compute_events_digest_inner 算法完全一致：
//
//	sort by (attacker_ip, timestamp)
//	for each: "attacker_ip|score|timestamp"
//	join with ";" + "WARDENNET_DIGEST_V1"
//	sha256 hex
func computeEventsDigest[T interface {
	GetAttackerIP() string
	GetScore() int
	GetTimestamp() int64
}](events []T) string {
	// 直接用 FinalThreatPayload 结构（闭源内部定义）
	return "" // 占位——下面用具体类型实现
}

// computeDigestForFinalPayloads 具体实现（FinalThreatPayload 是闭源内部结构）
// 不依赖 interface 泛型，避免额外 import
func computeDigestForFinalPayloads(events []finalThreatPayloadLite) string {
	if len(events) == 0 {
		return ""
	}
	// 按 (attacker_ip, timestamp) 排序
	type pair struct {
		ip   string
		ts   int64
		body string
	}
	items := make([]pair, 0, len(events))
	for _, ev := range events {
		items = append(items, pair{
			ip:   ev.AttackerIP,
			ts:   ev.Timestamp,
			body: fmt.Sprintf("%s|%d|%d", ev.AttackerIP, ev.Score, ev.Timestamp),
		})
	}
	// 冒泡排序（events 数量不大，最多几百条）
	for i := 0; i < len(items)-1; i++ {
		for j := i + 1; j < len(items); j++ {
			if items[i].ip > items[j].ip ||
				(items[i].ip == items[j].ip && items[i].ts > items[j].ts) {
				items[i], items[j] = items[j], items[i]
			}
		}
	}
	var raw strings.Builder
	for i, it := range items {
		if i > 0 {
			raw.WriteByte(';')
		}
		raw.WriteString(it.body)
	}
	raw.WriteString("WARDENNET_DIGEST_V1")
	h := sha256.Sum256([]byte(raw.String()))
	return hex.EncodeToString(h[:])
}

// finalThreatPayloadLite Digest 计算用的轻量结构（避免跨包依赖 FinalThreatPayload）。
type finalThreatPayloadLite struct {
	AttackerIP string
	Score      int
	Timestamp  int64
}

// ===== 上报 =====

// ReportFull 实现 Plugin.ReportFull（V2 完整上报接口）。
//
// 流程：
//  1. 接收完整 detector.Event 列表（interface{} 因为闭源独立编译）
//  2. 闭源内部：防投毒校验 + 商业评分 + 聚合去重 + 合规裁剪
//  3. 请求云端 Nonce（V1 签名）
//  4. 对裁剪后的 FinalThreatPayload 算 events_digest
//  5. 带 nonce + digest 发 V2 签名请求到 /api/evidence/report
func (c *CloudPlugin) ReportFull(events interface{}) error {
	rawList, ok := events.([]interface{})
	if !ok {
		return nil
	}

	c.mu.Lock()
	http := c.http
	agentID := c.agentID
	c.mu.Unlock()
	if http == nil {
		return fmt.Errorf("http client not ready")
	}

	// ====== Step 1-4: 防投毒 + 聚合 + 裁剪（闭源占位实现）======

	// ── V2.1: FeatureStat 特征维度聚合（闭源插件内部完成）──────────────────
	//
	//  闭源插件接收到完整 detector.Event 列表后，按以下维度聚合成 FeatureStat：
	//
	//  | dim                        | 来源字段                    | 说明                                    |
	//  |-----------------------------|-----------------------------|---------------------------------------|
	//  | "sensitive_path"            | event.Path                  | 匹配 DefaultSensitivePaths() 中的路径  |
	//  | "dangerous_pattern"        | event.Body + event.Path     | 匹配 DangerousPatterns 中的危险模式     |
	//  | "bot_ua"                    | event.UserAgent             | 匹配 DefaultBotUserAgents() 中的 UA    |
	//  | "dangerous_method"          | event.Method                | DELETE/PUT/PATCH/TRACE/CONNECT         |
	//  | "empty_referer"             | event.Referer == ""         | 空 Referer 计数                        |
	//  | "file_upload_blocked"       | event.FileExt + event.Status| 文件上传拦截（如 .php/.exe）            |
	//  | "status_4xx" 高频 path      | event.Path + event.Status   | 4xx 高频路径 Top-10                    |
	//
	//  聚合算法：
	//    1. 遍历 detector.Event 列表，每条事件检查上述维度匹配
	//    2. 按 (dim, value) 为 key 累加 hit_count / high_count / low_count
	//       （LocalRiskScore >= ScoreHigh 算 high，< ScoreHigh 算 low）
	//    3. Top-20 裁剪：每个 dim 只保留 hit_count 最高的 20 个 value
	//    4. 填充 FinalThreatPayload.FeatureStats 子数组
	//
	//  合规边界：
	//    FeatureStat 只上报"命中特征的聚合统计"，不上报原始 Path / UA / Body / Method
	//    命中 EvidenceService.FORBIDDEN_FIELDS 的原始字段绝对禁止出现在上报载荷中。
	//    这就是为什么聚合必须在闭源插件内部完成（开源端不做裁剪）。
	//
	//  ⚠️ 本开源版本中 FeatureStats 为空切片（nil），真实聚合逻辑在闭源编译产物中。
	//     ReportFull 单次 POST /api/evidence/report 同时携带 threat_votes + feature_stats。

	type FeatureStat struct {
		Dim       string `json:"dim"`
		Value     string `json:"value"`
		HitCount  int    `json:"hit_count"`
		HighCount int    `json:"high_count"`
		LowCount  int    `json:"low_count"`
	}

	type FinalThreatPayload struct {
		AgentID      string        `json:"agent_id"`
		AttackerIP   string        `json:"attacker_ip"`
		Source       string        `json:"source"`
		DataSource   string        `json:"data_source"`
		ClientIPFrom string        `json:"client_ip_from"`
		Score        int           `json:"score"`
		IsHigh       bool          `json:"is_high"`
		Timestamp    int64         `json:"timestamp"`
		FeatureStats []FeatureStat `json:"feature_stats,omitempty"`
	}

	aggregated := make(map[string]FinalThreatPayload)

	for _, item := range rawList {
		eventMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		attackerIP, _ := eventMap["source_ip"].(string)
		if attackerIP == "" {
			continue
		}

		score := 0
		if s, ok := eventMap["local_risk_score"].(float64); ok {
			score = int(s)
		}

		entry := FinalThreatPayload{
			AgentID:      agentID,
			AttackerIP:   attackerIP,
			Source:       mapStr(eventMap, "source"),
			DataSource:   "log_file",
			ClientIPFrom: mapStr(eventMap, "client_ip_from"),
			Score:        score,
			IsHigh:       score >= 80,
			Timestamp:    int64(mapFloat(eventMap, "timestamp", 0)),
		}

		if existing, dup := aggregated[attackerIP]; dup {
			if entry.Score > existing.Score {
				aggregated[attackerIP] = entry
			}
		} else {
			aggregated[attackerIP] = entry
		}
	}

	if len(aggregated) == 0 {
		return nil
	}

	// 转成 slice + 计算 Digest
	payloads := make([]FinalThreatPayload, 0, len(aggregated))
	digestInput := make([]finalThreatPayloadLite, 0, len(aggregated))
	for _, fp := range aggregated {
		payloads = append(payloads, fp)
		digestInput = append(digestInput, finalThreatPayloadLite{
			AttackerIP: fp.AttackerIP,
			Score:      fp.Score,
			Timestamp:  fp.Timestamp,
		})
	}
	eventsDigest := computeDigestForFinalPayloads(digestInput)

	// ====== Step 5: 请求 Nonce（V1 签名，因为还没 nonce）======
	// 同时拿到云端时间戳，用于 Step 6 的 V2 签名（避免 Agent 时钟偏移）
	nonce, serverTs, err := c.requestNonce()
	var tsForSignature string
	if err != nil {
		// nonce 接口本身可能因为新表还没上线而失败，
		// 降级：不带 nonce 走 V1 签名，保证 P0 先跑通
		nonce = ""
		tsForSignature = "" // 空 → doRequest 会 fallback 到 Agent 本地时间
	} else {
		tsForSignature = fmt.Sprintf("%d", serverTs)
	}

	// ====== Step 6: 构造上传 payload + V2 签名 ======
	uploadEvents := make([]plugin.ReportEvent, 0, len(payloads))
	for _, fp := range payloads {
		payloadJSON, _ := json.Marshal(fp)
		uploadEvents = append(uploadEvents, plugin.ReportEvent{
			Type:      "detection_alert",
			Timestamp: time.Now().Unix(),
			Payload:   string(payloadJSON),
		})
	}

	body := map[string]interface{}{
		"tenant_id":     c.tenantID,
		"agent_id":      agentID,
		"data_source":   "log_file",
		"events":        uploadEvents,
		"events_digest": eventsDigest,
	}

	// V2 签名：带 nonce + events_digest + 云端 timestamp（避免时钟偏移）
	opts := map[string]string{
		"nonce":          nonce,
		"events_digest":  eventsDigest,
		"timestamp":      tsForSignature, // 关键！用云端时间戳签名
	}

	resp, err := http.doRequest("POST", "/api/evidence/report", body, nil, opts)
	if err != nil {
		return err
	}
	_, httpErr, apiErr := parseResponse(resp)
	if httpErr != nil {
		return httpErr
	}
	return apiErr
}

func mapStr(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func mapFloat(m map[string]interface{}, key string, def float64) float64 {
	if v, ok := m[key].(float64); ok {
		return v
	}
	return def
}
// ===== 远程指令 =====

// FetchPendingCommands 实现 Plugin.FetchPendingCommands。
// 从云端拉取 Agent 的待执行远程指令（block.add / reload 等）。
func (c *CloudPlugin) FetchPendingCommands() ([]plugin.RemoteCommand, error) {
	c.mu.Lock()
	http := c.http
	agentID := c.agentID
	c.mu.Unlock()
	if http == nil {
		return nil, nil // 未就绪时不报错，sync engine 下次会重试
	}

	if agentID == "" {
		return nil, fmt.Errorf("agent_id not known")
	}

	resp, err := http.doRequest("GET", "/api/command/pending/"+urlEscape(agentID), nil, nil)
	if err != nil {
		return nil, err
	}
	data, httpErr, apiErr := parseResponse(resp)
	if httpErr != nil {
		return nil, httpErr
	}
	if apiErr != nil {
		return nil, apiErr
	}

	var raw struct {
		Commands []struct {
			ID        string                 `json:"id"`
			Command   string                 `json:"command"`
			Payload   map[string]interface{} `json:"payload"`
			Timestamp int64                  `json:"timestamp"`
		} `json:"commands"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	out := make([]plugin.RemoteCommand, 0, len(raw.Commands))
	for _, cmd := range raw.Commands {
		out = append(out, plugin.RemoteCommand{
			ID:        cmd.ID,
			Command:   cmd.Command,
			Args:      cmd.Payload,
			Timestamp: cmd.Timestamp,
		})
	}
	return out, nil
}

// HandleCommand 实现 Plugin.HandleCommand。
// CloudPlugin 作为云端代理拿到指令后，让 Agent 本地执行（reload/status 等由主进程处理）。
// 某些指令（如 blacklist.add）需要把命令发回云端做 ACK。
func (c *CloudPlugin) HandleCommand(cmd plugin.RemoteCommand) (plugin.CommandResult, error) {
	// ACK 给云端
	c.mu.Lock()
	http := c.http
	c.mu.Unlock()
	if http != nil {
		body := map[string]interface{}{
			"command_id": cmd.ID,
			"status":     "acked",
			"message":    "cloud plugin delegated to agent",
		}
		_, _ = http.doRequest("POST", "/api/command/"+urlEscape(cmd.ID)+"/ack", body, nil)
	}

	return plugin.CommandResult{
		ID:   cmd.ID,
		Ok:   true,
		Data: map[string]interface{}{"command": cmd.Command},
	}, nil
}

// ===== 特征值 =====

// FetchFeatures 实现 Plugin.FetchFeatures。拉取云端特征库更新。
func (c *CloudPlugin) FetchFeatures(tenantID string, currentVersion int64) (*plugin.FeatureResult, error) {
	c.mu.Lock()
	http := c.http
	c.mu.Unlock()
	if http == nil {
		return &plugin.FeatureResult{Version: currentVersion, Features: nil}, nil
	}

	path := fmt.Sprintf("/api/features/sync?version=%d&tenant_id=%s", currentVersion, urlEscape(tenantID))
	resp, err := http.doRequest("GET", path, nil, nil)
	if err != nil {
		return nil, err
	}

	// 304 Not Modified → 无更新
	if resp.StatusCode == 304 {
		resp.Body.Close()
		return &plugin.FeatureResult{Version: currentVersion, Features: nil}, nil
	}

	data, httpErr, apiErr := parseResponse(resp)
	if httpErr != nil {
		return nil, httpErr
	}
	if apiErr != nil {
		return nil, apiErr
	}

	var raw struct {
		Version  int64                     `json:"version"`
		Features []map[string]interface{}  `json:"features"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	return &plugin.FeatureResult{
		Version:  raw.Version,
		Features: raw.Features,
	}, nil
}

// urlEscape 最小 URL escape，封装 net/url.PathEscape 避免额外依赖点。
func urlEscape(s string) string {
	return url.PathEscape(s)
}
