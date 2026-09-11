import SiteLayout from "@/components/SiteLayout";

export default function AboutPage() {
  return (
    <SiteLayout>
      {/* Hero */}
      <section className="bg-gradient-to-br from-[#0A1628] via-[#0D2818] to-[#0A1628] text-[#E8F5E9] py-16">
        <div className="max-w-4xl mx-auto px-6 text-center">
          <h1 className="text-4xl font-extrabold mb-4">关于 WardenNet 卫枢</h1>
          <p className="text-green-400 text-lg">让每一台服务器都成为哨兵，让孤岛连成防线。</p>
        </div>
      </section>

      {/* 品牌故事 */}
      <section className="py-16">
        <div className="max-w-3xl mx-auto px-6">
          <h2 className="text-2xl font-bold mb-6">品牌故事</h2>
          <p className="text-gray-700 leading-relaxed mb-4">
            每一台服务器都是一个哨兵，但让它们独自面对全网的扫描、探测和攻击，它们就是一座座孤岛。
          </p>
          <p className="text-gray-700 leading-relaxed mb-4">
            WardenNet 的愿景，就是把这些孤岛连成防线。当成千上万台服务器的威胁感知汇聚在一起，攻击者再无处藏身。
          </p>
          <blockquote className="border-l-4 border-green-600 pl-4 text-gray-600 italic mt-6">
            One detects. All defend.
          </blockquote>
        </div>
      </section>

      {/* 价值观 */}
      <section className="py-16 bg-gray-50">
        <div className="max-w-5xl mx-auto px-6">
          <h2 className="text-2xl font-bold text-center mb-10">我们的价值观</h2>
          <div className="grid md:grid-cols-4 gap-6">
            {[
              { icon: "🔍", title: "透明", desc: "核心 Agent 代码开源可审计，不玩黑盒安全" },
              { icon: "🤝", title: "协作", desc: "相信集体智慧胜过单机孤岛" },
              { icon: "🪶", title: "轻量", desc: "Go 单二进制，不代理流量，零性能损耗" },
              { icon: "🧠", title: "智能", desc: "多学科融合的智能评分引擎，精准识别不误伤" },
            ].map((v) => (
              <div key={v.title} className="text-center bg-white rounded-lg p-6 border border-gray-100">
                <div className="text-3xl mb-3">{v.icon}</div>
                <h4 className="font-semibold mb-2">{v.title}</h4>
                <p className="text-sm text-gray-600">{v.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* 团队 */}
      <section className="py-16">
        <div className="max-w-3xl mx-auto px-6">
          <h2 className="text-2xl font-bold mb-6">团队</h2>
          <p className="text-gray-700 leading-relaxed">
            WardenNet 由一群关心中小站长处境的安全工程师发起。我们深知，绝大多数网站面临的威胁，不是国家级 APT，而是互联网上每天随机发生的自动化扫描、撞库和 CC 攻击。我们的目标，是让中小站长用极小的成本获得专业级的防护。
          </p>
        </div>
      </section>

      {/* 开源协议 */}
      <section id="license" className="py-16 bg-gray-50">
        <div className="max-w-3xl mx-auto px-6">
          <h2 className="text-2xl font-bold mb-6">开源协议</h2>
          <div className="bg-white rounded-lg p-6 border border-gray-200">
            <table>
              <tbody>
                <tr>
                  <td className="font-medium">Agent（开源）</td>
                  <td>AGPLv3</td>
                </tr>
                <tr>
                  <td className="font-medium">Cloud SaaS（闭源）</td>
                  <td>商业授权</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* 合规声明 */}
      <section id="compliance" className="py-16">
        <div className="max-w-3xl mx-auto px-6">
          <h2 className="text-2xl font-bold mb-6">合规与隐私</h2>
          <div className="space-y-4 text-gray-700 leading-relaxed">
            <p>• Agent 单机模式不向任何外部服务器发送数据，完全本地运行。</p>
            <p>• Cloud SaaS 模式仅上报聚合后的威胁情报，不采集任何业务数据或用户隐私数据。</p>
            <p>• 威胁情报 TTL 机制：威胁数据自动过期清理，最长保留期 72 小时。</p>
          </div>
        </div>
      </section>
    </SiteLayout>
  );
}
