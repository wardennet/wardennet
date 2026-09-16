
// Package main — CloudPlugin HTTP 客户端层。
//
// 自包含的 HTTP + HMAC 签名 + 重试实现，不依赖任何外部包。
// 所有网络调用都通过这个 client 层发出，上层 plugin 只调用业务方法。
//
// V2 签名算法（与 cloud/app/security/auth.py generate_signature 完全一致）：
//
//	message = nonce + timestamp + agent_id + sha256(body) + events_digest
//	signature = HMAC-SHA256(secret, message)
//
// 其中 nonce 和 events_digest 为空时退化为 V1 签名（用于 register 等无需上报的接口）。
package cloudplugin

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	defaultHTTPTimeout   = 30 * time.Second
	defaultRetryMax      = 2   // 除首次外重试 2 次（共 3 次请求）
	defaultRetryInterval = 500 * time.Millisecond
	maxBodySize          = 2 * 1024 * 1024 // 响应体最大 2MB
)

// Response 云端统一响应包装 {code, msg, data}。
type Response struct {
	Code int             `json:"code"`
	Msg  string          `json:"msg"`
	Data json.RawMessage `json:"data"`
}

// HTTPClient Agent-to-Cloud HTTP 客户端，封装签名、超时、重试。
//
// V2 签名升级：所有带 nonce 的请求走 V2 消息格式。
//   - 无 nonce（register / nonce 接口本身）→ V1 签名
//   - 有 nonce（evidence report / heartbeat / diff）→ V2 签名
// events_digest 可选，有 events 的接口才传。
type HTTPClient struct {
	baseURL    string
	agentID    string
	tenantID   string
	secret     string
	httpClient *http.Client
}

// NewHTTPClient 创建云端客户端。
func NewHTTPClient(baseURL, agentID, tenantID, secret string) *HTTPClient {
	return &HTTPClient{
		baseURL:    strings.TrimRight(baseURL, "/"),
		agentID:    agentID,
		tenantID:   tenantID,
		secret:     secret,
		httpClient: &http.Client{Timeout: defaultHTTPTimeout},
	}
}

// Sign 生成 V2 HMAC-SHA256 签名。
//
//	message = nonce + timestamp + agentID + sha256(body) + eventsDigest
//
// nonce 和 eventsDigest 为空字符串时自动退化为 V1。
func (c *HTTPClient) Sign(nonce, eventsDigest, timestamp string, body []byte) string {
	bodyHash := sha256.Sum256(body)
	bodyHex := hex.EncodeToString(bodyHash[:])
	raw := nonce + timestamp + c.agentID + bodyHex + eventsDigest
	mac := hmac.New(sha256.New, []byte(c.secret))
	mac.Write([]byte(raw))
	return hex.EncodeToString(mac.Sum(nil))
}

// doRequest 底层带签名 + 重试的 HTTP 请求。
//
// opts 可选参数：
//   - "nonce":       V2 Nonce（一次性令牌），为空则 V1 签名
//   - "events_digest": V2 事件摘要，为空则忽略
func (c *HTTPClient) doRequest(method, path string, body interface{}, extraHeaders map[string]string, opts ...map[string]string) (*http.Response, error) {
	var bodyBytes []byte
	var err error

	if body != nil {
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal body: %w", err)
		}
	}

	reqURL := c.baseURL + path
	var lastErr error

	for attempt := 0; attempt <= defaultRetryMax; attempt++ {
		resp, err := c.tryRequest(method, reqURL, bodyBytes, extraHeaders, opts...)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if attempt < defaultRetryMax {
			time.Sleep(defaultRetryInterval * time.Duration(attempt+1))
		}
	}

	return nil, fmt.Errorf("request %s %s failed after %d attempts: %w", method, path, defaultRetryMax+1, lastErr)
}

func (c *HTTPClient) tryRequest(method, reqURL string, bodyBytes []byte, extraHeaders map[string]string, opts ...map[string]string) (*http.Response, error) {
	// 合并 opts 到一个 map
	var nonce, eventsDigest, timestampOverride string
	if len(opts) > 0 && opts[0] != nil {
		nonce = opts[0]["nonce"]
		eventsDigest = opts[0]["events_digest"]
		timestampOverride = opts[0]["timestamp"] // V2: 由云端 Nonce 接口返回，避免 Agent 时钟偏移
	}

	// 优先使用云端返回的 timestamp；否则 fallback 到 Agent 本地时间
	var timestamp string
	if timestampOverride != "" {
		timestamp = timestampOverride
	} else {
		timestamp = fmt.Sprintf("%d", time.Now().Unix())
	}
	sig := c.Sign(nonce, eventsDigest, timestamp, bodyBytes)

	var bodyReader io.Reader
	if bodyBytes != nil {
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequest(method, reqURL, bodyReader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Id", c.agentID)
	req.Header.Set("X-Timestamp", timestamp)
	req.Header.Set("X-Signature", sig)
	if nonce != "" {
		req.Header.Set("X-Nonce", nonce)
	}
	if c.tenantID != "" {
		req.Header.Set("X-Tenant-Id", c.tenantID)
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	return c.httpClient.Do(req)
}

// parseResponse 读取响应体并解析 {code, msg, data} 包装。
// httpErr=true 表示 HTTP 状态码非 2xx；apiErr=true 表示 code != 200。
func parseResponse(resp *http.Response) (data json.RawMessage, httpErr error, apiErr error) {
	defer resp.Body.Close()

	// 限制响应体大小，防止被恶意或异常的大包拖垮
	limited := io.LimitReader(resp.Body, maxBodySize)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err), nil
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, string(raw)), nil
	}

	var wrapper Response
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		return nil, nil, fmt.Errorf("decode wrapper: %w", err)
	}
	if wrapper.Code != 200 {
		return nil, nil, fmt.Errorf("api code=%d msg=%s", wrapper.Code, wrapper.Msg)
	}

	return wrapper.Data, nil, nil
}