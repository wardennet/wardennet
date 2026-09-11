import DocLayout from "@/components/DocLayout";

export default function Configuration() {
  return (
    <DocLayout current="/docs/configuration">
      <h2 className="text-3xl font-bold mb-6">配置详解</h2>

      <h3 className="text-xl font-bold mb-4">完整配置参考</h3>
      <pre>{`detector:
  score_high: 50          # 触发本地拉黑候选的风险分阈值
  sensitivity: medium    # low / medium / high
  mode: block             # block / report
  observe_window_sec: 30  # 观察窗口（秒）
  merge_window_sec: 5     # 事件合并窗口（秒）

# 5 维一致性模型（有程序默认值，通常无需调整）
  consistency:
    enable: true
    threshold_benign: 4

sources:
  nginx_access:
    paths:
      - /var/log/nginx/access.log
    format: combined      # combined / custom

ipset:
  blacklist: wardennet_blacklist
  whitelist: wardennet_whitelist
  whitelist_type: hash:net
  whitelist:
    - 127.0.0.1
    - ::1

cloud:
  enabled: false
  base_url: "https://api.wardenet.example.com"
  tenant_id: ""
  agent_secret: ""`}</pre>

      <h3 className="text-xl font-bold mb-4 mt-8">detector 段详解</h3>
      <table>
        <thead><tr><th>字段</th><th>类型</th><th>默认值</th><th>说明</th></tr></thead>
        <tbody>
          <tr><td><code className="inline">score_high</code></td><td>int</td><td>50</td><td>触发本地拉黑候选的风险分阈值</td></tr>
          <tr><td><code className="inline">sensitivity</code></td><td>string</td><td>medium</td><td>灵敏度分档（low / medium / high）</td></tr>
          <tr><td><code className="inline">mode</code></td><td>string</td><td>block</td><td>block = 直接封禁；report = 只告警不封禁</td></tr>
          <tr><td><code className="inline">observe_window_sec</code></td><td>int</td><td>30</td><td>滑动窗口长度</td></tr>
          <tr><td><code className="inline">merge_window_sec</code></td><td>int</td><td>5</td><td>事件合并时间窗口</td></tr>
        </tbody>
      </table>

      <h3 className="text-xl font-bold mb-4 mt-8">ipset 段详解</h3>
      <table>
        <thead><tr><th>字段</th><th>说明</th></tr></thead>
        <tbody>
          <tr><td><code className="inline">blacklist</code></td><td>黑名单 ipset 名称（默认 wardennet_blacklist）</td></tr>
          <tr><td><code className="inline">whitelist</code></td><td>白名单 ipset 名称（默认 wardennet_whitelist，类型 hash:net 支持 CIDR）</td></tr>
          <tr><td>白名单的绝对优先级</td><td>本地白名单优先于任何云端黑名单，ForceBlock 命令可覆盖</td></tr>
        </tbody>
      </table>

      <h3 className="text-xl font-bold mb-4 mt-8">cloud 段详解</h3>
      <div className="alert alert-warning">
        <strong>注意：</strong> Cloud SaaS 为闭源商业服务，需单独购买授权。云端认证信息（tenant_id / agent_secret）保存在本地配置中，不会泄露。
      </div>
      <table>
        <thead><tr><th>字段</th><th>说明</th></tr></thead>
        <tbody>
          <tr><td><code className="inline">enabled</code></td><td>是否启用云端协同。false 时完全本地运行</td></tr>
          <tr><td><code className="inline">base_url</code></td><td>Cloud API 地址</td></tr>
          <tr><td><code className="inline">tenant_id</code></td><td>租户 ID</td></tr>
          <tr><td><code className="inline">agent_secret</code></td><td>Agent 共享密钥</td></tr>
        </tbody>
      </table>
    </DocLayout>
  );
}