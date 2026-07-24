// Package cmd — get credential 子命令
package cmd

import (
	"fmt"
	"os"

	"github.com/keivry/credential-proxy/get/internal"
)

// Credential 获取凭据
// Usage: get credential <条目> [字段] [--raw]
func Credential(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "用法: get credential <条目> [字段] [--raw]")
		os.Exit(1)
	}

	entry := args[0]
	field := ""
	raw := false

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--raw":
			raw = true
		default:
			if field == "" {
				field = args[i]
			}
		}
	}

	// 构建 auth 对象
	auth := make(map[string]string)

	// Phase 2: 自动检测调用者哈希
	caller := internal.GetCallerInfo()
	if caller != nil && caller.ScriptHash != "" {
		auth["caller_hash"] = caller.ScriptHash
		auth["caller_path"] = caller.ScriptPath
	}

	// Phase 1: Token 兜底
	token := os.Getenv("CREDENTIAL_TOKEN")
	if token != "" {
		auth["token"] = token
	}

	if len(auth) == 0 && os.Getenv("PROXY_URL") != "" {
		// 无认证环境，尝试获取 token
	}

	result, err := internal.FetchCredential(entry, field, raw, auth)
	if err != nil {
		if result != nil && result.Error != "" {
			fmt.Fprintln(os.Stderr, "错误:", result.Error)
		} else {
			fmt.Fprintln(os.Stderr, "错误:", err)
		}
		os.Exit(1)
	}

	if field != "" {
		fmt.Println(result.Value)
	} else {
		// 完整条目模式
		fmt.Printf("标题: %s\n", result.Title)
		fmt.Printf("用户名: %s\n", result.Username)
		fmt.Printf("密码: %s\n", result.Password)
		fmt.Printf("URL: %s\n", result.URL)
		for k, v := range result.CustomProperties {
			fmt.Printf("%s: %s\n", k, v)
		}
	}
}
