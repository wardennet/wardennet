import DocLayout from "@/components/DocLayout";

export default function Troubleshooting() {
  return (
    <DocLayout current="/docs/troubleshooting">
      <h2 className="text-3xl font-bold mb-6">故障排查</h2>

      <h3 className="text-xl font-bold mb-4">Agent 启动失败，报 ipset 不存在</h3>
      <pre>{`# 确认 ipset 已安装
which ipset || apt install ipset

# 确认内核模块加载
lsmod | grep ip_set`}</pre>

      <h3 className="text-xl font-bold mb-4 mt-8">日志读不到（Detector 不评分）</h3>
      <pre>{`# 1. 检查路径是否正确
ls -la /var/log/nginx/access.log

# 2. 确认 Agent 有权限读日志
sudo -u root ./wardennet ...

# 3. 查看 Agent 日志里有没有 "tail open failed"
journalctl -u wardennet -f | grep tail`}</pre>

      <h3 className="text-xl font-bold mb-4 mt-8">封禁了误封 IP，想立刻解封</h3>
      <pre>{`# 手动从 ipset 删除
sudo ipset del wardennet_blacklist 1.2.3.4

# 永久白名单化
# 在 config.yaml 的 ipset.whitelist 段加一行
ipset:
  whitelist:
    - 1.2.3.4
sudo systemctl restart wardennet`}</pre>

      <h3 className="text-xl font-bold mb-4 mt-8">与 WAF 串联后看不到攻击者真实 IP</h3>
      <div className="alert alert-warning">
        <strong>关键：</strong> 部署 WAF 串联时必须配置 WAF 将真实 IP 通过 HTTP Header 传递给源站，并在 Nginx 配置中提取这个 Header 写入 access log。
      </div>
      <pre>{`# Nginx 配置 log_format 提取真实 IP
log_format wardennet_real_ip '$http_cf_connecting_ip'
  '$http_true_client_ip'
  '$http_x_forwarded_for'
  '$remote_addr';

# 在 server {} 里使用
access_log /var/log/nginx/access.log wardennet_real_ip;`}</pre>

      <h3 className="text-xl font-bold mb-4 mt-8">Cloud Plugin 连不上云端</h3>
      <pre>{`# 1. 检查 cloud.enabled 是否开启
# 2. 确认 base_url / tenant_id / agent_secret 正确
# 3. 直接 curl 测连通性
curl -v https://your-cloud-api/ping
# 4. Agent 日志里搜 auth / nonce / handshake
journalctl -u wardennet -f | grep -i "cloud\|auth\|sync"`}</pre>
    </DocLayout>
  );
}