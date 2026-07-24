// Package main — CLI 入口：get credential <entry> [field]
package main

import (
	"fmt"
	"os"

	"github.com/keivry/credential-proxy/get/cmd"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	subcommand := os.Args[1]
	args := os.Args[2:]

	switch subcommand {
	case "credential":
		cmd.Credential(args)
	case "register":
		cmd.Register(args)
	case "revoke":
		cmd.Revoke(args)
	case "list":
		cmd.ListRegistrations(args)
	case "status":
		cmd.Status(args)
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `用法:
  get credential <条目> [字段]    获取凭据
  get register --entry <条目> --name <名称>  注册脚本
  get revoke --name <名称>                  吊销注册
  get list                                  列出注册
  get status                                Proxy 状态

环境变量:
  CREDENTIAL_TOKEN   自动放行 Token
  PROXY_URL          Proxy 地址（默认 http://127.0.0.1:8877）
  PROXY_HTTP_TIMEOUT HTTP 超时秒数（默认 30）
`)
}
