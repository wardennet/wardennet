"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";

const navLinks = [
  { href: "/", label: "首页" },
  { href: "/product", label: "产品" },
  { href: "/docs", label: "文档" },
  { href: "/about", label: "关于" },
];

export default function Navbar() {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);

  const isActive = (href: string) => {
    if (href === "/") return pathname === "/";
    return pathname.startsWith(href);
  };

  return (
    <nav className="sticky top-0 z-50 bg-[#0A1628]/95 backdrop-blur border-b border-[#2D3748]">
      <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
        <Link href="/" className="flex items-center gap-2 text-green-400 font-bold text-xl">
          <span className="w-8 h-8 bg-green-500 rounded-md flex items-center justify-center text-[#0A1628] font-extrabold text-lg">W</span>
          WardenNet
        </Link>

        <ul className="hidden md:flex gap-8 list-none">
          {navLinks.map((l) => (
            <li key={l.href}>
              <Link
                href={l.href}
                className={`text-[15px] font-medium transition-colors ${
                  isActive(l.href) ? "text-green-400" : "text-[#E8F5E9] hover:text-green-400"
                }`}
              >
                {l.label}
              </Link>
            </li>
          ))}
        </ul>

        <Link
          href="#"
          className="hidden md:inline-flex bg-green-600 text-white px-5 py-2 rounded-md font-semibold hover:bg-green-500 transition-colors"
        >
          GitHub
        </Link>

        <button className="md:hidden text-[#E8F5E9] text-2xl" onClick={() => setOpen(!open)}>
          {open ? "✕" : "☰"}
        </button>
      </div>

      {open && (
        <div className="md:hidden bg-[#0A1628] border-t border-[#2D3748] px-6 py-4">
          <ul className="flex flex-col gap-4 list-none">
            {navLinks.map((l) => (
              <li key={l.href}>
                <Link
                  href={l.href}
                  onClick={() => setOpen(false)}
                  className={`block py-1 ${
                    isActive(l.href) ? "text-green-400" : "text-[#E8F5E9]"
                  }`}
                >
                  {l.label}
                </Link>
              </li>
            ))}
          </ul>
        </div>
      )}
    </nav>
  );
}
