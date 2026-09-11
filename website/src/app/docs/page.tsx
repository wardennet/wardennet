import Link from "next/link";
import DocLayout from "@/components/DocLayout";

export default function DocsHome() {
  return (
    <DocLayout current="/docs">
      <h2 className="text-3xl font-bold mb-6">文档中心</h2>
      <p className="text-gray-600 mb-8">欢迎使用 WardenNet。以下是快速导航：</p>

      <div className="grid md:grid-cols-2 gap-4 mb-10">
        {[
          { href: "/docs/getting-started", icon: "🚀", title: "快速上手", desc: "5 分钟跑通首个防护流程" },
          { href: "/docs/installation", icon: "📦", title: "安装部署", desc: "编译、安装、systemd 配置详解" },
          { href: "/docs/configuration", icon: "⚙️", title: "配置详解", desc: "所有配置项说明和最佳实践" },
          { href: "/docs/architecture", icon: "🏗️", title: "架构设计", desc: "系统架构、模块说明、数据流" },
          { href: "/docs/waf-integration", icon: "🛡️", title: "与 WAF 协同", desc: "商业 WAF + WardenNet 串联部署" },
          { href: "/docs/troubleshooting", icon: "🔧", title: "故障排查", desc: "常见问题定位与解决" },
        ].map((item) => (
          <Link
            key={item.href}
            href={item.href}
            className="block bg-gray-50 border border-gray-100 rounded-lg p-5 hover:border-green-700 hover:shadow-md transition-all"
          >
            <div className="text-2xl mb-2">{item.icon}</div>
            <h4 className="font-semibold mb-1">{item.title}</h4>
            <p className="text-sm text-gray-500">{item.desc}</p>
          </Link>
        ))}
      </div>

      <h3 className="text-xl font-bold mb-4">核心概念</h3>
      <div className="alert alert-info">
        <strong>WardenNet Agent</strong> 是一个 Go 编写的守护进程，读取 Web 服务器访问日志，通过多层智能评分引擎（特征库 + 统计学 + 形态学 + 行为模式学）识别攻击行为，在 Linux 内核层面（ipset/iptables）实现秒级封禁。
      </div>
    </DocLayout>
  );
}
