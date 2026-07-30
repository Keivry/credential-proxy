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
	auth := internal.BuildAuth()

	// ── 安全：禁止终端直接调用 --raw ──
	// 当 caller_hash == get_binary_hash 时，表示 get 被终端/bash 直接调用
	// （而不是从脚本中通过 subprocess.run 调用）。此时 --raw 应被拒绝，
	// 强制用户通过脚本文件获取原始凭据，防止 LLM 上下文直接接触明文。
	if raw {
		callerHash, _ := auth["caller_hash"]
		binaryHash, _ := auth["get_binary_hash"]
		if callerHash != "" && callerHash == binaryHash {
			fmt.Fprintln(os.Stderr, "错误: --raw 只允许在脚本文件中使用。")
			fmt.Fprintln(os.Stderr, "请在脚本内通过 subprocess.run 调用 get，而不是直接在终端输入。")
			os.Exit(1)
		}
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
