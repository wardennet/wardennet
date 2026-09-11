import DocLayout from "@/components/DocLayout";

export default function FAQ() {
  const items = [
    { q: "WardenNet 会影响我的网站性能吗？", a: "几乎不会。Agent 读取日志文件（不代理流量），CPU/内存占用极低。也不参与请求转发。" },
    { q: "用了 Cloudflare / 阿里云 WAF 还需要 WardenNet 吗？", a: "需要。WAF 和 WardenNet 互补。WAF 拦截已知特征的内容攻击，WardenNet 填补行为分析、内核级处置和协同防御三个维度的空白。详见 <a href='/docs/waf-integration' className='text-green-700 underline'>与商业 WAF 协同</a>。" },
    { q: "WardenNet 误封正常用户怎么办？", a: "有多层防误报机制：空 Referer 硬封顶、401 降权、基线自学习、5 维一致性模型 BENIGN 降权到 ScoreMedium、白名单绝对优先。" },
    { q: "WardenNet 能否防 DDoS？", a: "WardenNet 专注于 Web 应用层威胁（扫描、撞库、小流量 CC）。SYN/UDP 洪水、带宽耗尽型攻击需要云厂商高防服务。详见首页能力边界声明。" },
    { q: "单机模式和协同模式怎么选？", a: "个人站点 / 独立博客 / 单节点企业官网 → 单机模式足够。多节点集群 / 有协同防御需求 → 协同模式。" },
    { q: "Windows 能用吗？", a: "不行。ipset + iptables 是 Linux 内核特性，WardenNet Agent 只能在 Linux 上运行。" },
  ];
  return (
    <DocLayout current="/docs/faq">
      <h2 className="text-3xl font-bold mb-6">常见问题</h2>
      <div className="space-y-6">
        {items.map((item, i) => (
          <div key={i} className="bg-gray-50 rounded-lg p-6 border border-gray-100">
            <h4 className="font-semibold mb-2">Q: {item.q}</h4>
            <div className="text-gray-700 leading-relaxed" dangerouslySetInnerHTML={{ __html: "A: " + item.a }} />
          </div>
        ))}
      </div>
    </DocLayout>
  );
}