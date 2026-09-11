#!/usr/bin/env python3
"""
WardenNet Agent CLI 客户端
通过 Unix Socket 与 Agent 通信，无需 socat。

用法:
  ./wardennet_cli.py status
  ./wardennet_cli.py blocklist add <ip> [--force]
  ./wardennet_cli.py blocklist del <ip>
  ./wardennet_cli.py blocklist status
  ./wardennet_cli.py reload

也可以直接用 Python 一行:
  python3 -c "import socket,json; s=socket.socket(socket.AF_UNIX); s.connect('/var/run/wardennet.sock'); s.sendall(json.dumps({'command':'status'}).encode()+b'\n'); print(s.recv(4096).decode())"
"""

import socket
import json
import sys
import os
import argparse

SOCKET_PATH = "/var/run/wardennet.sock"


def send_command(command: str, args: dict | None = None) -> dict:
    """发送命令到 Agent Unix Socket 并返回响应。"""
    if not os.path.exists(SOCKET_PATH):
        print(f"错误: Agent Socket 不存在 ({SOCKET_PATH})")
        print("请确认 Agent 正在运行")
        sys.exit(1)

    req = {"command": command}
    if args:
        req["args"] = args

    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(SOCKET_PATH)
        s.sendall(json.dumps(req).encode() + b"\n")
        data = s.recv(4096)
        s.close()
        if data:
            return json.loads(data.decode())
        return {"ok": False, "error": "empty response"}
    except ConnectionRefusedError:
        print(f"错误: 无法连接到 Agent ({SOCKET_PATH})")
        print("请确认 Agent 正在运行")
        sys.exit(1)
    except socket.timeout:
        print("错误: 命令执行超时")
        sys.exit(1)
    except Exception as e:
        print(f"错误: {e}")
        sys.exit(1)


def print_response(resp: dict):
    """格式化打印响应。"""
    if resp.get("ok"):
        msg = resp.get("message", "")
        data = resp.get("data")

        # blocklist.add 的特殊消息
        if msg == "already blocked":
            print(f"IP 已在黑名单中: {data.get('ip', '')}")
            return

        if msg:
            print(msg)

        if data:
            if isinstance(data, list):
                for item in data:
                    print(f"  {item}")
            elif isinstance(data, dict):
                # blocklist status 特殊格式化
                if "blocked_count" in data:
                    print(f"  黑名单数量: {data.get('blocked_count', 0)}")
                    print(f"  白名单数量: {data.get('whitelist_count', 0)}")
                    print(f"  TTL 条目:  {data.get('ttl_entries', 0)}")
                    if "version" in data:
                        print(f"  版本:      {data.get('version', '')}")
                    if "uptime" in data:
                        print(f"  运行时间:  {data.get('uptime', '')}")
                    if "detector_enabled" in data:
                        print(f"  检测引擎:  {'启用' if data['detector_enabled'] else '禁用'}")
                elif "expires_at" in data:
                    import datetime
                    ts = data.get("expires_at", 0)
                    dt = datetime.datetime.fromtimestamp(ts) if ts else "N/A"
                    print(f"  IP:          {data.get('ip', '')}")
                    print(f"  已接受:      {data.get('accepted', False)}")
                    print(f"  TTL (秒):    {data.get('ttl', 0)}")
                    print(f"  过期时间:    {dt}")
                elif "accepted" in data:
                    print(f"  IP:     {data.get('ip', '')}")
                    print(f"  已接受: {data.get('accepted', False)}")
                else:
                    for k, v in data.items():
                        print(f"  {k}: {v}")
            else:
                print(f"  {data}")
    else:
        err = resp.get("error", "unknown error")
        if "SKIP" in err:
            print(f"跳过: {err}")
        else:
            print(f"失败: {err}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="WardenNet Agent CLI 客户端",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s status                    # 查看 Agent 状态
  %(prog)s blocklist add 1.2.3.4     # 手动拉黑 IP
  %(prog)s blocklist add 1.2.3.4 -f  # 强制拉黑 (覆盖白名单)
  %(prog)s blocklist del 1.2.3.4     # 手动解封 IP
  %(prog)s blocklist status          # 查看黑名单状态
  %(prog)s reload                    # 重新加载配置
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="可用命令")

    # status 命令
    subparsers.add_parser("status", help="查看 Agent 状态")

    # reload 命令
    subparsers.add_parser("reload", help="重新加载配置文件")

    # blocklist 子命令
    bl_parser = subparsers.add_parser("blocklist", help="黑名单管理")
    bl_sub = bl_parser.add_subparsers(dest="action")

    # blocklist add
    bl_add = bl_sub.add_parser("add", help="添加 IP 到黑名单")
    bl_add.add_argument("ip", help="IP 地址")
    bl_add.add_argument("-f", "--force", action="store_true",
                        help="强制添加（覆盖白名单豁免）")

    # blocklist del
    bl_del = bl_sub.add_parser("del", help="从黑名单移除 IP")
    bl_del.add_argument("ip", help="IP 地址")

    # blocklist status
    bl_sub.add_parser("status", help="查看黑名单状态")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    # status
    if args.command == "status":
        resp = send_command("status")
        print_response(resp)

    # reload
    elif args.command == "reload":
        resp = send_command("reload")
        print_response(resp)

    # blocklist
    elif args.command == "blocklist":
        if not args.action:
            print("用法: blocklist {add|del|status} [args]")
            print("  blocklist add <ip> [-f]   添加 IP 到黑名单")
            print("  blocklist del <ip>        从黑名单移除")
            print("  blocklist status         查看黑名单状态")
            sys.exit(1)

        if args.action == "add":
            cmd_args = {"ip": args.ip}
            if args.force:
                cmd_args["force"] = True
            resp = send_command("blocklist.add", cmd_args)
            print_response(resp)

        elif args.action == "del":
            resp = send_command("blocklist.del", {"ip": args.ip})
            print_response(resp)

        elif args.action == "status":
            resp = send_command("blocklist.status")
            print_response(resp)


if __name__ == "__main__":
    main()
