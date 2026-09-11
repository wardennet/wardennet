import DocLayout from "@/components/DocLayout";

export default function Installation() {
  return (
    <DocLayout current="/docs/installation">
      <h2 className="text-3xl font-bold mb-6">安装部署</h2>

      <h3 className="text-xl font-bold mb-4">系统要求</h3>
      <table>
        <tbody>
          <tr><td className="font-medium">操作系统</td><td>Linux（Kernel 3.10+）</td></tr>
          <tr><td className="font-medium">依赖</td><td>ipset, iptables</td></tr>
          <tr><td className="font-medium">Web 服务器</td><td>Nginx / Apache / Caddy / 其他（兼容自定义日志格式）</td></tr>
          <tr><td className="font-medium">Go 版本（编译时）</td><td>1.21+</td></tr>
          <tr><td className="font-medium">运行时权限</td><td>root 或 CAP_NET_ADMIN</td></tr>
        </tbody>
      </table>

      <h3 className="text-xl font-bold mb-4 mt-10">安装 ipset</h3>
      <pre>{`# Debian/Ubuntu
apt install ipset

# CentOS/RHEL
yum install ipset`}</pre>

      <h3 className="text-xl font-bold mb-4 mt-10">从源码编译</h3>
      <pre>{`git clone https://github.com/wardenet/agent.git
cd agent

# 构建（纯静态，零 glibc 依赖）
go build -o wardennet ./cmd/wardennet

# 带集成 Cloud Plugin 的静态构建
CGO_ENABLED=0 go build -tags plugin -o wardennet ./cmd/wardennet`}</pre>

      <h3 className="text-xl font-bold mb-4 mt-10">systemd 服务文件</h3>
      <pre>{`[Unit]
Description=WardenNet Agent - 本地恶意扫描防护
After=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/opt/wardenet/wardennet --config /etc/wardenet/config.yaml
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target`}</pre>

      <h3 className="text-xl font-bold mb-4 mt-10">目录布局</h3>
      <pre>{`/etc/wardenet/config.yaml       # 主配置
/opt/wardenet/wardennet         # Agent 二进制
/var/log/wardenet/              # Agent 日志
/usr/share/ipset/               # ipset 持久化`}</pre>
    </DocLayout>
  );
}