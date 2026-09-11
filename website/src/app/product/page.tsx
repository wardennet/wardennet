import SiteLayout from "@/components/SiteLayout";

export default function ProductPage() {
  return (
    <SiteLayout>
      <section className="bg-gradient-to-br from-[#0A1628] via-[#0D2818] to-[#0A1628] text-[#E8F5E9] py-16">
        <div className="max-w-4xl mx-auto px-6 text-center">
          <h1 className="text-4xl font-extrabold mb-4">产品介绍</h1>
          <p className="text-green-400 text-lg">开源协同防御 · 单机可用 · 多机更强</p>
        </div>
      </section>

      {/* 工作原理 */}
      <section className="py-16">
        <div className="max-w-5xl mx-auto px-6">
          <h2 className="text-3xl font-bold text-center mb-10">WardenNet 如何工作？</h2>

          {/* 纯 CSS 架构图 */}
          <div className="relative rounded-2xl overflow-hidden shadow-2xl border border-gray-800/20 bg-gradient-to-br from-[#0A1628] via-[#0D1B2A] to-[#0A1628] p-8 md:p-12">
            {/* 背景光晕 */}
            <div className="absolute inset-0 opacity-40 pointer-events-none" style={{ background: "radial-gradient(circle at 50% 30%, rgba(74,222,128,0.15), transparent 60%), radial-gradient(circle at 50% 80%, rgba(74,222,128,0.10), transparent 50%)" }} />

            <div className="relative text-center space-y-0">
              {/* Layer 1: Cloud SaaS */}
              <div className="mb-6">
                <h3 className="text-lg font-bold text-green-400 mb-3 tracking-wide">WardenNet Cloud SaaS</h3>
                <div className="max-w-md mx-auto bg-gradient-to-b from-[#132035] to-[#0D1B2A] border border-green-400/40 rounded-2xl p-5 shadow-[0_0_40px_rgba(74,222,128,0.15)]">
                  <div className="space-y-2">
                    {["威胁情报聚合", "智能同步引擎", "云端风控", "多信号融合决策", "双向鉴权"].map((item) => (
                      <div key={item} className="bg-green-500/10 border border-green-400/30 rounded-full py-1.5 text-sm text-green-200">{item}</div>
                    ))}
                  </div>
                </div>
              </div>

              {/* 连接箭头 */}
              <div className="flex justify-center my-2">
                <svg width="32" height="32" viewBox="0 0 32 32" className="text-green-400">
                  <path d="M16 4 L16 24 M10 18 L16 28 L22 18" stroke="currentColor" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </div>

              {/* Layer 2: Agent */}
              <div className="mb-4">
                <h3 className="text-lg font-bold text-green-400 mb-3 tracking-wide">WardenNet Agent</h3>
                <div className="max-w-md mx-auto bg-gradient-to-b from-[#15253d] to-[#0D1B2A] border border-green-500/50 rounded-xl p-5 shadow-[0_0_40px_rgba(74,222,128,0.2)]">
                  <div className="space-y-2">
                    <div className="bg-slate-700/50 border border-slate-500/40 rounded-lg py-2 text-sm text-slate-200">日志采集 (Tail)</div>
                    <div className="bg-green-500/20 border border-green-400/60 rounded-lg py-2 text-sm text-green-100 font-medium relative">
                      6 层智能评分引擎
                      <span className="absolute -right-1 -top-1 w-3 h-3 bg-green-400 rounded-full animate-pulse"></span>
                    </div>
                    <div className="bg-slate-700/50 border border-slate-500/40 rounded-lg py-2 text-sm text-slate-200">内核级封禁 (ipset)</div>
                  </div>
                </div>
                <div className="text-center mt-3 text-xs text-slate-400">单机运行 // 可选协同</div>
              </div>

              {/* 连接箭头 */}
              <div className="flex justify-center my-2">
                <svg width="32" height="32" viewBox="0 0 32 32" className="text-green-400">
                  <path d="M16 4 L16 24 M10 18 L16 28 L22 18" stroke="currentColor" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </div>

              {/* Layer 3: Linux Kernel */}
              <div>
                <h3 className="text-lg font-bold text-green-400 mb-3 tracking-wide">Linux Kernel</h3>
                <div className="max-w-md mx-auto bg-gradient-to-r from-[#132035] to-[#1a3050] border border-green-400/40 rounded-full py-3 px-6 flex items-center justify-center gap-3 text-green-200 text-sm shadow-[0_0_30px_rgba(74,222,128,0.15)]">
                  <span>ipset / iptables</span>
                  <span className="text-green-400">⚡</span>
                  <span>DROP SYN packets</span>
                </div>
              </div>
            </div>

            {/* 底部 slogan */}
            <div className="text-center mt-8 text-green-400/80 italic text-sm">One detects. All defend.</div>
          </div>

          <p className="text-center text-gray-500 text-sm mt-6">
            开源 Agent 单机独立运行，可选接入 Cloud SaaS 实现协同防御。
          </p>
        </div>
      </section>

      {/* 6 层引擎 */}
      <section className="py-16 bg-gray-50">
        <div className="max-w-5xl mx-auto px-6">
          <h2 className="text-3xl font-bold text-center mb-12">6 层智能防御引擎</h2>
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
            {[
              { icon: "📡", title: "日志采集层", desc: "实时读取 Nginx、Apache 等 Web 服务器访问日志，支持自定义正则解析" },
              { icon: "🎯", title: "危险模式解码", desc: "基于特征库精准识别 SQL 注入、XSS、命令执行等已知攻击特征" },
              { icon: "📊", title: "统计学基线", desc: "滑动窗口统计 QPS 分布、状态码比例等指标，建立站点行为基线，偏离度触发评分提升" },
              { icon: "🧬", title: "形态学一致性", desc: "5 维模型（前缀连贯度、新颖度饱和、路径集中度、状态同质性、方法语义）识别扫描器形状" },
              { icon: "🛡️", title: "行为模式学降权", desc: "空 Referer 硬封顶、401 降权、协同信号动态调整等多层防误报机制" },
              { icon: "⚡", title: "内核级封禁", desc: "通过 ipset + iptables 直接在网络层丢弃，秒级响应零损耗" },
            ].map((e, i) => (
              <div key={e.title} className="bg-white rounded-lg p-6 border border-gray-100 shadow-sm hover:shadow-md transition-shadow">
                <div className="flex items-center gap-3 mb-3">
                  <div className="w-10 h-10 bg-green-100 rounded-lg flex items-center justify-center text-xl">{e.icon}</div>
                  <h3 className="font-semibold text-lg">0{i + 1}</h3>
                </div>
                <h4 className="font-semibold mb-2">{e.title}</h4>
                <p className="text-sm text-gray-600 leading-relaxed">{e.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* 部署模式 */}
      <section className="py-16">
        <div className="max-w-5xl mx-auto px-6">
          <h2 className="text-3xl font-bold text-center mb-12">两种部署模式</h2>
          <div className="grid md:grid-cols-2 gap-6">
            <div className="bg-gray-50 rounded-lg p-8 border border-gray-200">
              <div className="text-2xl mb-4">🔌 单机模式（默认）</div>
              <h3 className="text-xl font-bold mb-3">开源 Agent · 单机独立运行</h3>
              <p className="text-gray-600 mb-4 leading-relaxed">
                不依赖云端即可运行。读取本地 Web 日志，本地评分本地封禁。适合个人站点、独立博客、单节点企业官网。
              </p>
              <ul className="list-none space-y-2 text-sm">
                <li className="flex items-center gap-2"><span className="text-green-500">✓</span> 5 分钟部署</li>
                <li className="flex items-center gap-2"><span className="text-green-500">✓</span> 零外部依赖</li>
                <li className="flex items-center gap-2"><span className="text-green-500">✓</span> 永久免费</li>
                <li className="flex items-center gap-2"><span className="text-gray-400">-</span> 无协同防御</li>
              </ul>
            </div>
            <div className="bg-[#0A1628] text-[#E8F5E9] rounded-lg p-8 border border-[#2D3748]">
              <div className="text-2xl mb-4">🌐 协同模式（可选）</div>
              <h3 className="text-xl font-bold mb-3 text-green-400">Agent + Cloud SaaS</h3>
              <p className="text-[#718096] mb-4 leading-relaxed">
                接入云端后，多节点共享威胁情报。一个 IP 在某台服务器被识别为恶意，全网节点自动获取情报，协同封禁。
              </p>
              <ul className="list-none space-y-2 text-sm">
                <li className="flex items-center gap-2"><span className="text-green-400">✓</span> 一处发现全网御敌</li>
                <li className="flex items-center gap-2"><span className="text-green-400">✓</span> 智能同步引擎自动更新</li>
                <li className="flex items-center gap-2"><span className="text-green-400">✓</span> 云端风控 + 防投毒算法</li>
                <li className="flex items-center gap-2"><span className="text-green-400">✓</span> 安全双向鉴权</li>
              </ul>
            </div>
          </div>
        </div>
      </section>
    </SiteLayout>
  );
}
