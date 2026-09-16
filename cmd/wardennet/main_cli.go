// Package main - main_cli.go 实现 Agent 二进制内置 CLI 子命令。
// 让 wardennet 二进制同时作为服务端和 CLI 客户端使用，不再依赖 socat/python/curl。
//
// 使用示例:
//   wardennet                          # 启动 Agent 服务端
//   wardennet --version                # 打印版本
//   wardennet status                   # CLI: 查看状态
//   wardennet reload                   # CLI: 热重载配置
//   wardennet blocklist add 1.2.3.4    # CLI: 手动拉黑
//   wardennet blocklist add 1.2.3.4 -f # CLI: 强制拉黑（覆盖白名单）
//   wardennet blocklist del 1.2.3.4    # CLI: 手动解封
//   wardennet blocklist status         # CLI: 黑名单统计
//   wardennet --socket /tmp/custom.sock status  # CLI: 指定 socket 路径
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/wardennet/agent/internal/unixsocket"
)

// cliCommands 内置 CLI 子命令列表（用于判断是否进入 CLI 模式）。
var cliCommands = map[string]bool{
	"status":    true,
	"reload":    true,
	"blocklist": true,
	"help":      true,
	"-h":        true,
	"--help":    true,
}

// isCLIMode 判断第一个非 flag 参数是否是 CLI 子命令。
func isCLIMode(args []string) bool {
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		return cliCommands[a]
	}
	return false
}

// runCLI 执行 CLI 子命令模式。返回退出码。
func runCLI(args []string) int {
	// 解析 --socket / --json 全局参数
	socketPath := unixsocket.DefaultSocketPath
	rawJSON := false
	var positional []string
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--socket" && i+1 < len(args):
			socketPath = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--socket="):
			socketPath = strings.TrimPrefix(args[i], "--socket=")
		case args[i] == "--json":
			rawJSON = true
		default:
			positional = append(positional, args[i])
		}
	}

	if len(positional) == 0 {
		printCLIHelp()
		return 0
	}

	client := unixsocket.NewClient(socketPath, 0)
	out := &outputConfig{rawJSON: rawJSON}

	switch positional[0] {
	case "help", "-h", "--help":
		printCLIHelp()
		return 0
	case "status":
		return cliSend(client, "status", nil, out)
	case "reload":
		return cliSend(client, "reload", nil, out)
	case "blocklist":
		return cliBlocklist(client, positional[1:], out)
	default:
		fmt.Fprintf(os.Stderr, "未知命令: %s\n\n", positional[0])
		printCLIHelp()
		return 1
	}
}

// outputConfig CLI 输出配置。
type outputConfig struct {
	rawJSON bool // 输出原始 JSON（跳过友好格式化）
}

// cliBlocklist 处理 blocklist 子命令。
func cliBlocklist(client *unixsocket.Client, args []string, out *outputConfig) int {
	if len(args) == 0 {
		fmt.Println("用法: wardennet blocklist {add|del|status} [args]")
		fmt.Println("  blocklist add <ip> [-f]   添加 IP 到黑名单")
		fmt.Println("  blocklist del <ip>        从黑名单移除")
		fmt.Println("  blocklist status          查看黑名单状态")
		return 1
	}

	switch args[0] {
	case "add":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "缺少 IP 参数: wardennet blocklist add <ip> [-f]")
			return 1
		}
		ip := args[1]
		force := false
		for _, a := range args[2:] {
			if a == "-f" || a == "--force" {
				force = true
			}
		}
		cargs := map[string]interface{}{"ip": ip}
		if force {
			cargs["force"] = true
		}
		return cliSend(client, "blocklist.add", cargs, out)

	case "del":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "缺少 IP 参数: wardennet blocklist del <ip>")
			return 1
		}
		return cliSend(client, "blocklist.del", map[string]interface{}{"ip": args[1]}, out)

	case "status":
		return cliSend(client, "blocklist.status", nil, out)

	default:
		fmt.Fprintf(os.Stderr, "未知 blocklist 子命令: %s\n", args[0])
		return 1
	}
}

// cliSend 发送命令并格式化输出响应。返回退出码。
func cliSend(client *unixsocket.Client, cmd string, args map[string]interface{}, out *outputConfig) int {
	resp, err := client.Send(cmd, args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		return 1
	}
	return printResponse(resp, out)
}

// printResponse 格式化输出 CLI 响应。返回退出码（0=成功，1=失败）。
func printResponse(resp *unixsocket.Response, out *outputConfig) int {
	// --json 模式：直接输出原始 JSON
	if out != nil && out.rawJSON {
		data, err := json.MarshalIndent(resp, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "JSON 序列化失败: %v\n", err)
			return 1
		}
		fmt.Println(string(data))
		if !resp.Ok {
			return 1
		}
		return 0
	}

	if !resp.Ok {
		err := resp.Error
		if strings.Contains(err, "SKIP") {
			fmt.Printf("跳过: %s\n", err)
		} else {
			fmt.Printf("失败: %s\n", err)
		}
		return 1
	}

	// 消息优先（如 "reloaded successfully"）
	if resp.Message != "" {
		fmt.Println(resp.Message)
	}

	// 数据格式化
	if resp.Data != nil {
		if err := prettyPrint(resp.Data); err != nil {
			// fallback: 直接打印
			fmt.Printf("%v\n", resp.Data)
		}
	}
	return 0
}

// prettyPrint 格式化打印响应数据。
func prettyPrint(data interface{}) error {
	switch d := data.(type) {
	case map[string]interface{}:
		// 特定命令的美化输出
		if _, ok := d["blocked_count"]; ok {
			return printBlocklistStatus(d)
		}
		if _, ok := d["expires_at"]; ok {
			return printBlocklistAdd(d)
		}
		if _, ok := d["accepted"]; ok && d["accepted"] != nil {
			return printBlocklistDel(d)
		}
		// 通用：JSON 美化
		return printJSON(data)
	default:
		return printJSON(data)
	}
}

// printBlocklistStatus 美化 blocklist.status / status 输出。
func printBlocklistStatus(d map[string]interface{}) error {
	var b strings.Builder
	if v, ok := d["version"]; ok {
		fmt.Fprintf(&b, "Agent 版本:   %v\n", v)
	}
	if v, ok := d["uptime"]; ok {
		fmt.Fprintf(&b, "运行时间:     %v\n", v)
	}
	if v, ok := d["blocked_count"]; ok {
		fmt.Fprintf(&b, "黑名单数量:   %v\n", v)
	}
	if v, ok := d["whitelist_count"]; ok {
		fmt.Fprintf(&b, "白名单数量:   %v\n", v)
	}
	if v, ok := d["ttl_entries"]; ok {
		fmt.Fprintf(&b, "TTL 条目:     %v\n", v)
	}
	if v, ok := d["detector_enabled"]; ok {
		fmt.Fprintf(&b, "检测引擎:     %v\n", map[bool]string{true: "启用", false: "禁用"}[v.(bool)])
	}

	// 防御统计（仅在有数据时展示）
	if total := intVal(d, "total_events"); total > 0 {
		fmt.Fprintf(&b, "\n--- 检测统计 ---\n")
		fmt.Fprintf(&b, "总事件数:     %d\n", total)
		if v := intVal(d, "total_ips"); v > 0 {
			fmt.Fprintf(&b, "独立 IP 数:   %d\n", v)
		}
		fmt.Fprintf(&b, "高危事件:     %d\n", intVal(d, "high_score_count"))
		fmt.Fprintf(&b, "中危事件:     %d\n", intVal(d, "medium_count"))
		fmt.Fprintf(&b, "低危事件:     %d\n", intVal(d, "low_score_count"))
		fmt.Fprintf(&b, "4xx 响应:     %d\n", intVal(d, "status_4xx"))
		fmt.Fprintf(&b, "5xx 响应:     %d\n", intVal(d, "status_5xx"))
		// Top Blocked IP 列表
		if top, ok := d["top_blocked"]; ok {
			if list, ok := top.([]interface{}); ok && len(list) > 0 {
				fmt.Fprintf(&b, "\n--- Top %d 高危 IP ---\n", len(list))
				for i, item := range list {
					if m, ok := item.(map[string]interface{}); ok {
						ip, _ := m["ip"].(string)
						score := intVal(m, "score")
						fmt.Fprintf(&b, "  %d. %-20s score=%d\n", i+1, ip, score)
					}
				}
			}
		}
	}

	fmt.Print(b.String())
	return nil
}

// intVal 从 map 中安全提取整数值（兼容 JSON 反序列化后的 float64/int64/int）。
func intVal(m map[string]interface{}, key string) int64 {
	v, ok := m[key]
	if !ok || v == nil {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return int64(n)
	case float32:
		return int64(n)
	case int:
		return int64(n)
	case int64:
		return n
	case int32:
		return int64(n)
	case uint64:
		return int64(n)
	}
	return 0
}

// printBlocklistAdd 美化 blocklist.add 输出。
func printBlocklistAdd(d map[string]interface{}) error {
	accepted, _ := d["accepted"].(bool)
	ip, _ := d["ip"].(string)
	if !accepted {
		fmt.Printf("IP 已在黑名单中: %s\n", ip)
		return nil
	}
	fmt.Printf("已拉黑: %s\n", ip)
	if ttl, ok := d["ttl"]; ok {
		fmt.Printf("TTL:    %v 秒\n", ttl)
	}
	if exp, ok := d["expires_at"]; ok {
		fmt.Printf("过期:   %v\n", exp)
	}
	return nil
}

// printBlocklistDel 美化 blocklist.del 输出。
func printBlocklistDel(d map[string]interface{}) error {
	if ip, ok := d["ip"]; ok {
		fmt.Printf("已解封: %s\n", ip)
	}
	return nil
}

// printJSON JSON 美化打印（fallback）。
func printJSON(v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

// printCLIHelp 打印 CLI 帮助信息。
func printCLIHelp() {
	fmt.Println("WardenNet Agent CLI")
	fmt.Println()
	fmt.Println("用法:")
	fmt.Println("  wardennet                              启动 Agent 服务端")
	fmt.Println("  wardennet --version                    打印版本")
	fmt.Println("  wardennet [flags] <command>            CLI 管理命令")
	fmt.Println()
	fmt.Println("全局标志:")
	fmt.Println("  --socket <path>   指定 Unix Socket 路径 (默认 /var/run/wardennet.sock)")
	fmt.Println("  --json            输出原始 JSON 响应（跳过友好格式化）")
	fmt.Println()
	fmt.Println("CLI 命令:")
	fmt.Println("  status                   查看 Agent 状态")
	fmt.Println("  reload                   热重载配置文件")
	fmt.Println("  blocklist add <ip> [-f]  添加 IP 到黑名单 (-f / --force 强制覆盖白名单)")
	fmt.Println("  blocklist del <ip>       从黑名单移除 IP")
	fmt.Println("  blocklist status         查看黑名单统计")
	fmt.Println()
	fmt.Println("示例:")
	fmt.Println("  wardennet status")
	fmt.Println("  wardennet status --json")
	fmt.Println("  wardennet blocklist add 192.168.1.100 -f")
	fmt.Println("  wardennet --socket /tmp/custom.sock status")
	fmt.Println()
	fmt.Println("说明: CLI 通过 Unix Socket 与 Agent 通信，无需 socat/python/curl。")
}
