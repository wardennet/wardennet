import Link from "next/link";
import SiteLayout from "@/components/SiteLayout";

const sidebarItems = [
  { href: "/docs", label: "文档首页" },
  { href: "/docs/getting-started", label: "快速上手" },
  { href: "/docs/installation", label: "安装部署" },
  { href: "/docs/configuration", label: "配置详解" },
  { href: "/docs/faq", label: "常见问题" },
  { href: "/docs/architecture", label: "架构设计" },
  { href: "/docs/troubleshooting", label: "故障排查" },
  { href: "/docs/waf-integration", label: "与商业 WAF 协同" },
];

export default function DocLayout({
  children,
  current,
}: {
  children: React.ReactNode;
  current: string;
}) {
  return (
    <SiteLayout>
      <div className="bg-gradient-to-br from-[#0A1628] via-[#0D2818] to-[#0A1628] text-[#E8F5E9] py-10">
        <div className="max-w-5xl mx-auto px-6">
          <div className="text-[#718096] text-sm mb-2">文档中心</div>
          <h1 className="text-2xl font-bold text-white">WardenNet 文档</h1>
        </div>
      </div>

      <div className="max-w-5xl mx-auto px-6 py-12 grid md:grid-cols-[220px_1fr] gap-8">
        <aside className="md:sticky md:top-20 h-fit">
          <div className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">文档导航</div>
          <ul className="list-none space-y-1">
            {sidebarItems.map((item) => {
              const active = current === item.href;
              return (
                <li key={item.href}>
                  <Link
                    href={item.href}
                    className={`block px-3 py-2 rounded-md text-sm transition-colors whitespace-nowrap overflow-hidden text-ellipsis ${
                      active
                        ? "bg-[#E6FFF2] text-[#007A3D] font-medium"
                        : "text-gray-600 hover:text-green-700 hover:bg-gray-50"
                    }`}
                  >
                    {item.label}
                  </Link>
                </li>
              );
            })}
          </ul>
        </aside>

        <article className="prose-doc min-w-0">{children}</article>
      </div>
    </SiteLayout>
  );
}
