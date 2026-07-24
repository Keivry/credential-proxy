// Package cmd — get revoke / list / status 子命令
package cmd

import (
	"flag"
	"fmt"
	"os"

	"github.com/keivry/credential-proxy/get/internal"
)

// Revoke 吊销注册
// Usage: get revoke --name <名称>
func Revoke(args []string) {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	name := fs.String("name", "", "注册名称（必填）")
	fs.Parse(args)

	if *name == "" {
		fmt.Fprintln(os.Stderr, "用法: get revoke --name <名称>")
		fs.PrintDefaults()
		os.Exit(1)
	}

	if err := internal.RevokeCaller(*name); err != nil {
		fmt.Fprintln(os.Stderr, "吊销失败:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "✅ 已吊销: %s\n", *name)
}

// ListRegistrations 列出所有注册
// Usage: get list
func ListRegistrations(args []string) {
	regs, err := internal.ListRegistrations()
	if err != nil {
		fmt.Fprintln(os.Stderr, "查询失败:", err)
		os.Exit(1)
	}
	if len(regs) == 0 {
		fmt.Println("（无注册）")
		return
	}
	for _, r := range regs {
		mode := r.AllowMode
		if mode == "auto" {
			mode = "自动放行"
		} else {
			mode = "普通授权"
		}
		status := "✅ 已启用"
		if !r.Enabled {
			status = "❌ 已禁用"
		}
		fmt.Printf("  %s (%s) — %s — %s\n", r.Name, r.Type, status, mode)
		for entry, fields := range r.Entries {
			if len(fields) == 0 {
				fmt.Printf("    · %s → 全部属性\n", entry)
			} else {
				fmt.Printf("    · %s → %s\n", entry, joinStrings(fields, ", "))
			}
		}
	}
}

func joinStrings(items []string, sep string) string {
	if len(items) == 0 {
		return ""
	}
	s := ""
	for _, it := range items {
		if s != "" {
			s += sep
		}
		s += it
	}
	return s
}

// Status 查询 Proxy 状态
// Usage: get status
func Status(args []string) {
	st, err := internal.FetchStatus()
	if err != nil {
		fmt.Fprintln(os.Stderr, "查询失败:", err)
		os.Exit(1)
	}
	fmt.Printf("状态: %s\n", st.Status)
	if st.Unlocked {
		fmt.Println("解锁: ✅ 已解锁")
	} else {
		fmt.Println("解锁: 🔒 未解锁")
	}
	fmt.Printf("待审批: %d\n", st.Pending)
	fmt.Printf("LLM 凭据: %d\n", st.LlmSecrets)
}
