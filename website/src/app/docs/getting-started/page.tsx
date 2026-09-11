import DocLayout from "@/components/DocLayout";

export default function GettingStarted() {
  return (
    <DocLayout current="/docs/getting-started">
      <h2 className="text-3xl font-bold mb-6">快速上手</h2>
      <p className="text-gray-600 mb-8">3 步完成单机部署，让你的服务器获得智能防护。</p>

      <h3 className="text-xl font-bold mb-4">前置条件</h3>
      <ul className="list-disc pl-6 text-gray-700 mb-8 space-y-1">
        <li>Linux 服务器（需要 ipset + iptables 支持）</li>
        <li>Nginx / Apache 等 Web 服务器</li>
        <li>Go 1.21+ 编译环境（或直接下载编译好的二进制）</li>
        <li>root 权限（ipset/iptables 需要）</li>
      </ul>

      <h3 className="text-xl font-bold mb-4">第 1 步：编译 Agent</h3>
      <pre>{`git clone https://github.com/wardenet/agent.git
cd agent
go build -o wardennet ./cmd/wardennet`}</pre>

      <h3 className="text-xl font-bold mb-4 mt-8">第 2 步：配置</h3>
      <pre>{`cp configs/wardennet.yaml.example /etc/wardenet/config.yaml

# 关键配置示例
detector:
  score_high: 50        # 触发本地拉黑候选的风险分阈值
  sensitivity: medium  # low / medium / high
  mode: block           # block / report

# 告诉 Agent 去哪读日志
sources:
  nginx_access:
    paths:
      - /var/log/nginx/access.log

ipset:
  whitelist:
    - 127.0.0.1
    - 你的管理 IP

cloud:
  enabled: false  # 单机模式先关，想协同再开`}</pre>

      <h3 className="text-xl font-bold mb-4 mt-8">第 3 步：启动</h3>
      <pre>{`# 方式 A：直接运行
sudo ./wardennet -config /etc/wardenet/config.yaml

# 方式 B：systemd 服务（推荐）
sudo cp configs/wardennet.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wardennet

# 查看运行状态
systemctl status wardennet
journalctl -u wardennet -f`}</pre>

      <div className="alert alert-info mt-8">
        <strong>下一步：</strong> 查看 <a href="/docs/configuration" className="text-green-700 underline">配置详解</a> 或 <a href="/docs/waf-integration" className="text-green-700 underline">与 WAF 协同</a>。
      </div>
    </DocLayout>
  );
}