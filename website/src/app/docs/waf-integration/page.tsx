import DocLayout from "@/components/DocLayout";

export default function WafIntegration() {
  return (
    <DocLayout current="/docs/waf-integration">
      <h2 className="text-3xl font-bold mb-6">WardenNet 与商业 WAF 的协同关系</h2>

      <h3 className="text-xl font-bold mb-4">核心结论</h3>
      <div className="alert alert-info">
        <strong>WardenNet 与商业 WAF 是互补关系，不是替代关系。</strong>
        WardenNet 填补了商业 WAF 在行为分析、内核级处置和协同防御三个维度的空白。最专业的架构是「商业 WAF + WardenNet Agent」的串联防御体系。
      </div>

      <h3 className="text-xl font-bold mb-4">商业 WAF 的天然盲区</h3>
      <table>
        <thead><tr><th>盲区</th><th>原因</th><th className="text-green-400">WardenNet 如何填补</th></tr></thead>
        <tbody>
          <tr><td>高频撞库/慢速 CC</td><td>WAF 是规则匹配，不做行为形状识别</td><td className="bg-green-50 text-green-800 font-medium">6 层智能评分引擎 + 统计学基线自学习</td></tr>
          <tr><td>扫描行为检测</td><td>WAF 不统计 QPS 分布和 4xx 比例</td><td className="bg-green-50 text-green-800 font-medium">滑动窗口统计 + 5 维一致性模型</td></tr>
          <tr><td>集群打散型 CC</td><td>单个 IP 可能未达阈值，WAF 触发不了</td><td className="bg-green-50 text-green-800 font-medium">协同信号：多节点 IP 重合度触发升级</td></tr>
          <tr><td>攻击绕过 WAF</td><td>直连源站 IP 攻击（DNS 记录暴露）</td><td className="bg-green-50 text-green-800 font-medium">WardenNet 直接读源站日志，绕过 WAF 也能封</td></tr>
          <tr><td>日志分析的业务层异常</td><td>WAF 不理解业务语义</td><td className="bg-green-50 text-green-800 font-medium">Agent 是源站守护者，理解上下文</td></tr>
          <tr><td>内核级封禁</td><td>WAF 返回 403 仍然消耗源站资源</td><td className="bg-green-50 text-green-800 font-medium">ipset/iptables 内核层直接丢弃 SYN 包</td></tr>
        </tbody>
      </table>

      <h3 className="text-xl font-bold mb-4 mt-8">WAF 串联场景下 WardenNet 是否有效？</h3>
      <p className="mb-4">关键在于 <strong>真实 IP 提取</strong>。如果 WAF 正确透传了客户端真实 IP 的 Header，WardenNet 的 pickRealIP() 就能拿到攻击者真实 IP。</p>
      <pre>{`// 真实 IP 提取优先级
CF-Connecting-IP > True-Client-IP > X-Forwarded-For > remote_addr`}</pre>
      <div className="alert alert-warning mt-4">
        <strong>部署前必须验证：</strong> WAF 是否透传了真实 IP Header，以及 Nginx 的 access_log 是否配置了正确的 log_format 来提取这些 Header。
      </div>
      <pre>{`# Nginx log_format 示例（从 WAF Header 提取真实 IP）
log_format wardennet '$http_cf_connecting_ip $remote_addr [$time_local] '
                     '"$request" $status $body_bytes_sent '
                     '"$http_referer" "$http_user_agent"';`}</pre>

      <h3 className="text-xl font-bold mb-4 mt-8">最佳实践：三层串联防御</h3>
      <pre>{`Layer 1: 商业 WAF (Cloudflare / 阿里云 / 腾讯云 ...)
         │ 拦截已知特征的内容攻击
         │ 返回 403，清洗恶意请求
         ▼
Layer 2: WardenNet Agent (源站内核级)
         │ 读取 WAF 清洗后的 access log
         │ 智能引擎识别扫描/撞库/慢速 CC 等行为攻击
         ├──▶ ipset wardennet_blacklist add → iptables DROP SYN
         │   （内核层直接丢弃，不消耗源站资源）
         │
Layer 3: WardenNet Cloud SaaS (协同层)
         │ 多节点威胁情报聚合
         │ 智能同步引擎 → 全网封禁`}</pre>

      <h3 className="text-xl font-bold mb-4 mt-8">与替代方案对比</h3>
      <table>
        <thead><tr><th>维度</th><th>商业 WAF</th><th>传统开源脚本</th><th className="text-green-400">WardenNet</th></tr></thead>
        <tbody>
          <tr><td>费用</td><td>数千～数万/年</td><td>免费</td><td className="bg-green-50 text-green-800 font-medium border-l-2 border-green-500">开源免费 + SaaS 增值</td></tr>
          <tr><td>协同防御</td><td>闭源</td><td>单机孤岛</td><td className="bg-green-50 text-green-800 font-medium border-l-2 border-green-500">一处发现，全网御敌</td></tr>
          <tr><td>检测逻辑</td><td>规则库 + URL 解码</td><td>硬编码正则 + 固定阈值</td><td className="bg-green-50 text-green-800 font-medium border-l-2 border-green-500">基线自学习 + 危险模式解码</td></tr>
          <tr><td>误报控制</td><td>一般</td><td>差</td><td className="bg-green-50 text-green-800 font-medium border-l-2 border-green-500">成熟的防误杀降权机制</td></tr>
          <tr><td>封禁位置</td><td>云端返回 403</td><td>源站内核</td><td className="bg-green-50 text-green-800 font-medium border-l-2 border-green-500">源站内核</td></tr>
          <tr><td>部署门槛</td><td>DNS 切换 + 规则</td><td>装脚本就行</td><td className="bg-green-50 text-green-800 font-medium border-l-2 border-green-500">Go 编译 + 配置文件</td></tr>
          <tr><td>防护范围</td><td>内容攻击为主</td><td>只防单一攻击类型</td><td className="bg-green-50 text-green-800 font-medium border-l-2 border-green-500">扫描/撞库/CC/爬虫</td></tr>
          <tr><td>响应速度</td><td>毫秒级但会回源</td><td>秒级</td><td className="bg-green-50 text-green-800 font-medium border-l-2 border-green-500">秒级 + 内核层 DROP</td></tr>
          <tr><td>可审计</td><td>黑盒</td><td>源码可改</td><td className="bg-green-50 text-green-800 font-medium border-l-2 border-green-500">核心 Agent 开源可审计</td></tr>
          <tr><td>持续进化</td><td>厂商更新</td><td>自己改脚本</td><td className="bg-green-50 text-green-800 font-medium border-l-2 border-green-500">开源社区迭代 + 云端情报</td></tr>
        </tbody>
      </table>

      <h3 className="text-xl font-bold mb-4 mt-8">常见误解澄清</h3>
      <div className="space-y-4">
        <div className="bg-gray-50 rounded-lg p-5 border border-gray-100">
          <strong className="block mb-1">Q1: 用了 Cloudflare 就不需要 WardenNet 了？</strong>
          <span className="text-gray-700">A: 不是。Cloudflare 拦截已知特征的内容攻击，WardenNet 填补行为分析、内核级处置和协同防御三个维度的空白。</span>
        </div>
        <div className="bg-gray-50 rounded-lg p-5 border border-gray-100">
          <strong className="block mb-1">Q2: WAF 串联时 WardenNet 看不到攻击者真实 IP？</strong>
          <span className="text-gray-700">A: 只要 WAF 正确透传了 CF-Connecting-IP / True-Client-IP / X-Forwarded-For 等 Header，就能拿到真实 IP。</span>
        </div>
        <div className="bg-gray-50 rounded-lg p-5 border border-gray-100">
          <strong className="block mb-1">Q3: WardenNet 会和 WAF 打架，重复封禁？</strong>
          <span className="text-gray-700">A: 不会。WardenNet 在 WAF 之后运行，读取的是 WAF 清洗后的日志，两者在不同层面工作。</span>
        </div>
        <div className="bg-gray-50 rounded-lg p-5 border border-gray-100">
          <strong className="block mb-1">Q4: 商业 WAF 太贵，但开源脚本够用？</strong>
          <span className="text-gray-700">A: 传统开源脚本功能单一、固定阈值、无协同。WardenNet 是 6 层智能评分引擎（特征库 + 统计学 + 形态学 + 行为模式学）+ 协同防御，不是简单的封禁脚本。</span>
        </div>
      </div>

      <h3 className="text-xl font-bold mb-4 mt-10">一句话总结</h3>
      <div className="alert alert-info">
        <strong>商业 WAF 是你的门卫，WardenNet 是你的神经中枢。</strong> 两者不在一个维度，是黄金搭档。
      </div>
    </DocLayout>
  );
}