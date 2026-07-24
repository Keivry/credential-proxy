// Package cmd — get revoke / list / status 子命令
package cmd

import (
	"flag"
	"fmt"
	"os"
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

	fmt.Fprintf(os.Stderr, "⚠️  吊销请求: %s 的自动放行权限\n", *name)
	fmt.Fprintln(os.Stderr, "请在 Matrix 中确认吊销")
}

// ListRegistrations 列出所有注册
// Usage: get list
func ListRegistrations(args []string) {
	fmt.Fprintln(os.Stderr, "列出注册功能需要 Proxy API 支持，请使用:")
	fmt.Fprintln(os.Stderr, "  curl http://127.0.0.1:8877/registrations")
}

// Status 查询 Proxy 状态
// Usage: get status
func Status(args []string) {
	fmt.Fprintln(os.Stderr, "查询 Proxy 状态功能需要 Proxy API 支持，请使用:")
	fmt.Fprintln(os.Stderr, "  curl http://127.0.0.1:8877/health")
}
