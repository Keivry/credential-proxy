// Package cmd — get register 子命令
package cmd

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/keivry/credential-proxy/get/internal"
)

// Register 注册当前脚本到 Proxy
// Usage: get register --entry <条目> --name <名称> [--desc <描述>] [--auto]
func Register(args []string) {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	name := fs.String("name", "", "注册名称（必填）")
	entry := fs.String("entry", "", "允许访问的条目（必填，逗号分隔）")
	desc := fs.String("desc", "", "程序用途描述")
	auto := fs.Bool("auto", false, "启用自动放行")
	fs.Parse(args)

	if *name == "" || *entry == "" {
		fmt.Fprintln(os.Stderr, "用法: get register --name <名称> --entry <条目> [--desc <描述>] [--auto]")
		fs.PrintDefaults()
		os.Exit(1)
	}

	// 读取调用者信息
	caller := internal.GetCallerInfo()
	if caller == nil || caller.ScriptHash == "" {
		fmt.Fprintln(os.Stderr, "警告: 无法读取脚本信息（/proc 不可读），降级到 Token 模式")
		fmt.Fprintln(os.Stderr, "请设置 CREDENTIAL_TOKEN 环境变量后使用 Token 注册")
		os.Exit(1)
	}

	// 构建 entries 字典（每个条目允许全部字段）
	entries := make(map[string][]string)
	for _, e := range strings.Split(*entry, ",") {
		e = strings.TrimSpace(e)
		if e != "" {
			entries[e] = []string{}
		}
	}

	allowMode := "manual"
	if *auto {
		allowMode = "auto"
	}

	req := &internal.RegisterCallerRequest{
		Name:          *name,
		Description:   *desc,
		ScriptPath:    caller.ScriptPath,
		ScriptHash:    caller.ScriptHash,
		Entries:       entries,
		AllowMode:     allowMode,
		CanAutoUnlock: *auto,
	}

	regID, err := internal.RegisterCaller(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "注册失败:", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "✅ 注册请求已发送 (ID: %s)\n", regID)
	fmt.Fprintln(os.Stderr, "请在 Matrix 中审批该请求")
	fmt.Fprintf(os.Stderr, "  程序: %s\n", *name)
	fmt.Fprintf(os.Stderr, "  脚本: %s\n", caller.ScriptPath)
	fmt.Fprintf(os.Stderr, "  条目: %s\n", *entry)
}
