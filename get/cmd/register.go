// Package cmd — get register 子命令
package cmd

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/keivry/credential-proxy/get/internal"
)

// Register 注册当前脚本到 Proxy
// Usage: get register --name <名称> --entry <条目> [--desc <描述>] [--auto] [--fields <字段1,字段2>] [--script-path <路径>]
func Register(args []string) {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	name := fs.String("name", "", "注册名称（必填）")
	entry := fs.String("entry", "", "允许访问的条目（必填，逗号分隔）")
	desc := fs.String("desc", "", "程序用途描述")
	auto := fs.Bool("auto", false, "启用自动放行")
	fields := fs.String("fields", "", "允许的字段名（逗号分隔，默认全部属性）")
	scriptPath := fs.String("script-path", "", "脚本文件路径（直接指定，自动计算哈希）")
	fs.Parse(args)

	if *name == "" || *entry == "" {
		fmt.Fprintln(os.Stderr, "用法: get register --name <名称> --entry <条目> [--desc <描述>] [--auto] [--fields <字段1,字段2>] [--script-path <路径>]")
		fs.PrintDefaults()
		os.Exit(1)
	}

	// 解析允许的字段列表
	var allowedFields []string
	if *fields != "" {
		for _, f := range strings.Split(*fields, ",") {
			f = strings.TrimSpace(f)
			if f != "" {
				allowedFields = append(allowedFields, f)
			}
		}
	}

	// 获取脚本路径和哈希
	scriptPathVal := ""
	scriptHashVal := ""

	if *scriptPath != "" {
		// 直接模式：从指定文件计算哈希
		realPath, err := filepath.EvalSymlinks(*scriptPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "错误: 无法解析脚本路径:", err)
			os.Exit(1)
		}
		if fi, err := os.Stat(realPath); err != nil || !fi.Mode().IsRegular() {
			fmt.Fprintln(os.Stderr, "错误: 文件不存在或不是常规文件:", realPath)
			os.Exit(1)
		}
		scriptHashVal = internal.Sha256File(realPath)
		if scriptHashVal == "" {
			fmt.Fprintln(os.Stderr, "错误: 无法读取脚本文件:", realPath)
			os.Exit(1)
		}
		scriptPathVal = realPath
	} else {
		// 自动检测模式：从父进程读取
		caller := internal.GetCallerInfo()
		if caller == nil || caller.ScriptHash == "" {
			fmt.Fprintln(os.Stderr, "错误: 无法自动检测调用者脚本")
			fmt.Fprintln(os.Stderr, "请使用 --script-path 参数指定脚本路径后重试")
			os.Exit(1)
		}
		scriptPathVal = caller.ScriptPath
		scriptHashVal = caller.ScriptHash
	}

	// 构建 entries 字典
	entries := make(map[string][]string)
	for _, e := range strings.Split(*entry, ",") {
		e = strings.TrimSpace(e)
		if e != "" {
			if len(allowedFields) > 0 {
				entries[e] = allowedFields
			} else {
				entries[e] = []string{} // 空 slice = 全部属性
			}
		}
	}

	allowMode := "manual"
	if *auto {
		allowMode = "auto"
	}

	req := &internal.RegisterCallerRequest{
		Name:          *name,
		Description:   *desc,
		ScriptPath:    scriptPathVal,
		ScriptHash:    scriptHashVal,
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
	fmt.Fprintf(os.Stderr, "  脚本: %s\n", scriptPathVal)
	fmt.Fprintf(os.Stderr, "  条目: %s\n", *entry)
}
