import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "WardenNet 卫枢 — 一处发现，全网御敌",
  description:
    "开源分布式 Web 服务器攻击 IP 联防平台。轻量 Agent + 云端协同，让每一台服务器都成为你的哨兵。",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="zh-CN" className="h-full">
      <body className="min-h-full flex flex-col bg-white text-[#1A1A1A]">
        {children}
      </body>
    </html>
  );
}
