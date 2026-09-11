import DocLayout from "@/components/DocLayout";

export default function Architecture() {
  return (
    <DocLayout current="/docs/architecture">
      <h2 className="text-3xl font-bold mb-6">架构设计</h2>

      <h3 className="text-xl font-bold mb-4">系统架构</h3>
      <pre>{`┌───────────────────────────────────────────────────────────────────────┐
│                     WardenNet System Architecture                      │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                         Cloud SaaS                              │   │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐   │   │
│  │  │ Sync Engine│ │ Decision   │ │ Threat     │ │ Feature    │   │   │
│  │  │ (双层 Diff) │ │ Engine     │ │ Score      │ │ Center     │   │   │
│  │  └────────────┘ └────────────┘ └────────────┘ └────────────┘   │   │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐   │   │
│  │  │ Nonce Auth │ │ Heartbeat  │ │ Cmd Polling│ │ Anti-Poison│   │   │
│  │  └────────────┘ └────────────┘ └────────────┘ └────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                             ▲                                          │
│                    HMAC-SHA256 安全双向鉴权                               │
│                             │                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    Cloud Plugin (libcloudplugin.so)              │   │
│  │  编译时可选集成，运行时可热插拔，零 HTTP 代码在主程序里                 │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                             ▲                                          │
│                             │                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                      WardenNet Agent                            │   │
│  │  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────────────┐ │   │
│  │  │ Log Tailer│ │ Detector  │ │ Decider   │ │ IPSet Manager    │ │   │
│  │  └───────────┘ └───────────┘ └───────────┘ └─────────────────┘ │   │
│  └─────────────────────────┬───────────────────────────────────────┘   │
│                            ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ Linux Kernel: ipset wardennet_blacklist + iptables DROP SYN    │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────────────────┘`}</pre>

      <h3 className="text-xl font-bold mb-4 mt-8">模块职责</h3>
      <table>
        <thead><tr><th>模块</th><th>职责</th></tr></thead>
        <tbody>
          <tr><td>Log Tailer</td><td>实时读取 Nginx/Apache 日志，支持自定义正则解析日志格式</td></tr>
          <tr><td>Detector</td><td>6 层评分引擎：危险模式解码 → 基线自学习 → 5 维一致性模型 → 防误报降权</td></tr>
          <tr><td>Decider</td><td>本地决策：score ≥ threshold → 候选封禁；白名单绝对优先</td></tr>
          <tr><td>IPSet Manager</td><td>操作 ipset + iptables 内核层封禁，管理白名单/ForceBlock</td></tr>
          <tr><td>Cloud Plugin</td><td>云端通信插件（可选），独立进程零 HTTP 代码</td></tr>
        </tbody>
      </table>

      <h3 className="text-xl font-bold mb-4 mt-8">数据流</h3>
      <pre>{`Access Log
     │
     ▼
Log Tailer (tail -F)
     │  原始日志行
     ▼
Log Parser (解析 + 提取 IP / Path / Status / Method)
     │  LogEntry
     ▼
Detector (6 层评分引擎)
     │  ThreatScore (0-100)
     ▼
Decider (本地决策 + 白名单检查)
     │  Blocked / Alert / Ignore
     ▼
IPSet Manager (ipset add + iptables DROP)
     │
     ▼
(可选) Cloud Plugin → Cloud SaaS 情报聚合`}</pre>
    </DocLayout>
  );
}