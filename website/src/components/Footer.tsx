import Link from "next/link";

export default function Footer() {
  return (
    <footer className="bg-[#0A1628] text-[#E8F5E9] mt-16 pt-16 pb-8">
      <div className="max-w-6xl mx-auto px-6">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-10 mb-12">
          <div>
            <div className="text-green-400 font-bold text-lg mb-4">WardenNet 卫枢</div>
            <p className="text-[#718096] text-sm leading-relaxed">
              开源协同防御网络。一处发现，全网御敌。让每一台服务器都成为你的哨兵。
            </p>
          </div>
          <div>
            <h4 className="text-sm text-[#E8F5E9] mb-4 font-semibold uppercase tracking-wider">产品</h4>
            <ul className="list-none space-y-2">
              <li><Link href="/product" className="text-[#718096] text-sm hover:text-green-400">产品介绍</Link></li>
              <li><Link href="/docs/getting-started" className="text-[#718096] text-sm hover:text-green-400">快速开始</Link></li>
              <li><Link href="/docs/architecture" className="text-[#718096] text-sm hover:text-green-400">架构设计</Link></li>
            </ul>
          </div>
          <div>
            <h4 className="text-sm text-[#E8F5E9] mb-4 font-semibold uppercase tracking-wider">文档</h4>
            <ul className="list-none space-y-2">
              <li><Link href="/docs/installation" className="text-[#718096] text-sm hover:text-green-400">安装部署</Link></li>
              <li><Link href="/docs/configuration" className="text-[#718096] text-sm hover:text-green-400">配置详解</Link></li>
              <li><Link href="/docs/waf-integration" className="text-[#718096] text-sm hover:text-green-400">与 WAF 协同</Link></li>
            </ul>
          </div>
          <div>
            <h4 className="text-sm text-[#E8F5E9] mb-4 font-semibold uppercase tracking-wider">关于</h4>
            <ul className="list-none space-y-2">
              <li><Link href="/about" className="text-[#718096] text-sm hover:text-green-400">关于我们</Link></li>
              <li><Link href="/about#license" className="text-[#718096] text-sm hover:text-green-400">开源协议</Link></li>
              <li><Link href="/about#compliance" className="text-[#718096] text-sm hover:text-green-400">合规声明</Link></li>
            </ul>
          </div>
        </div>
        <div className="border-t border-[#2D3748] pt-6 flex flex-wrap justify-between items-center gap-4 text-[13px]">
          <div className="text-[#718096]">© 2026 WardenNet · 开源 Agent（AGPLv3）· Cloud SaaS（闭源）</div>
          <div className="text-[#718096] text-xs max-w-md text-right leading-relaxed">
            免责声明：WardenNet 不提供网络层带宽防护，SYN/UDP 洪水、带宽耗尽型攻击仍需依赖云厂商高防服务。
          </div>
        </div>
      </div>
    </footer>
  );
}
