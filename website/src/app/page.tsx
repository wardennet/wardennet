import Link from "next/link";
import SiteLayout from "@/components/SiteLayout";

const features = [
  { icon: "🔓", title: "开源免费", desc: "Agent 完全开源，单机永久免费。代码透明可审计，无隐藏后门。" },
  { icon: "🌐", title: "协同防御", desc: "多节点交叉验证，一处发现威胁全网受益。置信度分级，防误封传染。" },
  { icon: "🤖", title: "智能检测引擎", desc: "6 层防御体系 + 基线自学习，精准识别扫描器、爬虫和恶意攻击。" },
  { icon: "💨", title: "轻量无感", desc: "Go 单二进制，CPU/内存占用极低。读取日志文件不代理流量，零性能损耗。" },
  { icon: "🛡️", title: "专业防护", desc: "覆盖目录扫描、漏洞探测、后门爆破、小流量 CC 等常见攻击。" },
  { icon: "👥", title: "社区驱动", desc: "持续迭代更新，威胁情报动态扩展。开源社区反馈驱动产品优化。" },
];

const steps = [
  { num: 1, title: "编译 Agent", code: "# 克隆仓库并编译\ncd agent\ngo build -o wardennet ./cmd/wardennet" },
  { num: 2, title: "准备配置", code: "# 复制配置模板\ncp configs/wardennet.yaml.example config.yaml\n\n# 关键配置\ndetector:\n  score_high: 50          # 触发本地拉黑候选\n  sensitivity: medium    # 灵敏度分档\n  mode: block             # block / report\nipset:\n  whitelist:\n    - 127.0.0.1" },
  { num: 3, title: "启动防护", code: "# 直接运行\nsudo ./wardennet -config config.yaml\n\n# 或 systemd 服务\nsudo cp configs/wardennet.service /etc/systemd/system/\nsudo systemctl enable --now wardennet" },
];

export default function HomePage() {
  return (
    <SiteLayout>
      {/* Hero */}
      <section className="bg-gradient-to-br from-[#0A1628] via-[#0D2818] to-[#0A1628] text-[#E8F5E9] py-20 relative overflow-hidden">
        <div className="absolute inset-0 opacity-30" style={{ background: "radial-gradient(circle at 80% 30%, rgba(0,255,136,0.25), transparent 60%)" }} />
        <div className="max-w-4xl mx-auto px-6 relative text-center">
          <span className="inline-block bg-green-500/10 border border-green-400 text-green-400 px-4 py-1 rounded-full text-sm mb-6">
            🛡️ 开源协同防御 · Collaborative Defense Network
          </span>
          <h1 className="text-5xl font-extrabold leading-tight mb-6">
            WardenNet <span className="text-green-400">卫枢</span>
          </h1>
          <div className="text-2xl text-green-400 font-semibold mb-4">One detects. All defend.</div>
          <div className="text-lg text-[#A0AEC0] mb-2">一处发现，全网御敌。让每一台服务器都成为你的哨兵。</div>
          <p className="text-base text-[#718096] mb-10 max-w-2xl mx-auto">
            开源分布式 Web 服务器攻击 IP 联防平台。轻量 Go Agent 单机可用，多节点协同更强大。多层智能评分引擎（特征库 + 统计学 + 形态学 + 行为模式学）精准识别扫描、撞库、慢速 CC 等威胁，内核级 ipset 封禁秒级响应。
          </p>
          <div className="flex gap-4 flex-wrap justify-center">
            <Link href="#" className="bg-green-600 text-white px-7 py-3 rounded-md font-semibold hover:bg-green-500 transition-colors">
              ⚡ GitHub 开源
            </Link>
            <Link href="/docs/getting-started" className="border-2 border-green-400 text-green-400 px-7 py-3 rounded-md font-semibold hover:bg-green-600 hover:text-white transition-colors">
              🚀 快速开始
            </Link>
          </div>
        </div>
      </section>

      {/* 行业痛点 */}
      <section className="py-16 bg-white">
        <div className="max-w-5xl mx-auto px-6">
          <h2 className="text-3xl font-bold text-center mb-12">中小站长的共同困境</h2>
          <div className="grid md:grid-cols-4 gap-6">
            {[
              { icon: "🔒", title: "孤立无援", desc: "单台服务器独自判断攻击，无法知晓这个 IP 是否已在其他服务器上被标记" },
              { icon: "💰", title: "方案昂贵", desc: "商业 WAF 每年数千到数万元，对中小站长性价比极低" },
              { icon: "⚠️", title: "误报困扰", desc: "简单封禁脚本频繁误伤真实访客，导致用户投诉" },
              { icon: "🧩", title: "配置复杂", desc: "安全产品配置门槛高，文档晦涩难懂" },
            ].map((p) => (
              <div key={p.title} className="bg-gray-50 rounded-lg p-6 border border-gray-100">
                <div className="text-3xl mb-3">{p.icon}</div>
                <h4 className="font-semibold mb-2">{p.title}</h4>
                <p className="text-sm text-gray-600 leading-relaxed">{p.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* 核心优势 */}
      <section className="py-16 bg-[#0A1628] text-[#E8F5E9]">
        <div className="max-w-6xl mx-auto px-6">
          <h2 className="text-3xl font-bold text-center mb-4 text-white">6 大核心优势</h2>
          <p className="text-center text-[#718096] mb-12">让安全不再是奢侈品</p>
          <div className="grid md:grid-cols-3 gap-6">
            {features.map((f) => (
              <div key={f.title} className="bg-[#111D30] border border-[#2D3748] rounded-lg p-6 hover:border-green-400 transition-colors">
                <div className="text-3xl mb-3">{f.icon}</div>
                <h3 className="text-lg font-semibold mb-2 text-[#E8F5E9]">{f.title}</h3>
                <p className="text-sm text-[#718096] leading-relaxed">{f.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* 快速开始 */}
      <section className="py-16 bg-gray-50">
        <div className="max-w-3xl mx-auto px-6">
          <h2 className="text-3xl font-bold text-center mb-12">3 步快速部署</h2>
          <div className="space-y-6">
            {steps.map((s) => (
              <div key={s.num} className="flex gap-4">
                <div className="w-10 h-10 bg-green-600 text-white rounded-full flex items-center justify-center font-bold flex-shrink-0">{s.num}</div>
                <div className="flex-1">
                  <h4 className="font-semibold mb-2">第 {s.num} 步：{s.title}</h4>
                  <pre>{s.code}</pre>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* 防护范围 */}
      <section className="py-16 bg-white">
        <div className="max-w-4xl mx-auto px-6">
          <h2 className="text-3xl font-bold text-center mb-4">防护范围</h2>
          <p className="text-center text-gray-600 mb-10">明确能力边界，合规透明</p>
          <div className="grid md:grid-cols-2 gap-4 mb-8">
            {[
              { icon: "✅", text: "目录扫描：识别自动化扫描器探测敏感路径" },
              { icon: "✅", text: "漏洞探测：SQL 注入、XSS、命令执行等攻击特征" },
              { icon: "✅", text: "后门爆破：识别后台登录暴力破解" },
              { icon: "✅", text: "小流量 CC + 集群打散型 CC" },
            ].map((f) => (
              <div key={f.text} className="flex items-start gap-3 bg-green-50 rounded-md p-4 border border-green-200">
                <span className="text-green-600 text-xl">{f.icon}</span>
                <span className="text-gray-700 text-sm">{f.text}</span>
              </div>
            ))}
          </div>
          <div className="alert alert-warning">
            <div className="font-semibold mb-1">⚠️ 能力边界声明</div>
            <p>WardenNet 专注于 Web 应用层威胁检测与 IP 封禁，不提供网络层带宽防护。SYN/UDP 洪水、带宽耗尽型攻击仍需依赖云厂商高防服务。</p>
          </div>
        </div>
      </section>

      {/* 对比 */}
      <section className="py-16 bg-gray-50">
        <div className="max-w-5xl mx-auto px-6">
          <h2 className="text-3xl font-bold text-center mb-10">对比优势</h2>
          <div className="overflow-x-auto">
            <table>
              <thead>
                <tr>
                  <th>对比维度</th>
                  <th>商业 WAF</th>
                  <th>传统开源脚本</th>
                  <th className="text-green-400">WardenNet</th>
                </tr>
              </thead>
              <tbody>
                {[
                  ["费用", "数千～数万/年", "免费", "开源免费 + SaaS 增值"],
                  ["协同防御", "闭源", "单机孤岛", "一处发现，全网御敌"],
                  ["检测逻辑", "规则库 + URL 解码", "硬编码正则 + 固定阈值", "基线自学习 + 危险模式解码"],
                  ["误报控制", "一般", "差（易封正常 IP）", "成熟的防误杀降权机制"],
                  ["封禁位置", "云端返回 403", "源站内核", "源站内核"],
                ].map((row, i) => (
                  <tr key={i}>
                    <td className="font-medium text-gray-800">{row[0]}</td>
                    <td className="text-gray-600">{row[1]}</td>
                    <td className="text-gray-600">{row[2]}</td>
                    <td className="bg-green-50 text-green-800 font-medium border-l-2 border-green-500">{row[3]}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="py-16 text-center">
        <div className="max-w-2xl mx-auto px-6">
          <h2 className="text-3xl font-bold mb-4">开始你的安全之旅</h2>
          <p className="text-gray-600 mb-8">加入 WardenNet 社区，让每一台服务器都成为哨兵</p>
          <div className="flex gap-4 justify-center flex-wrap">
            <Link href="#" className="bg-green-600 text-white px-7 py-3 rounded-md font-semibold">⭐ GitHub Star</Link>
            <Link href="/docs/getting-started" className="border-2 border-green-600 text-green-700 px-7 py-3 rounded-md font-semibold">📖 阅读文档</Link>
          </div>
        </div>
      </section>
    </SiteLayout>
  );
}
