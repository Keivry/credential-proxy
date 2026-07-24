// Package internal — 内部共享包：调用者识别、哈希计算、Proxy HTTP 客户端、配置
package internal

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CallerInfo 存储调用者（父进程）的信息
type CallerInfo struct {
	ScriptPath     string
	ScriptHash     string
	InterpreterPath string
	InterpreterHash string
}

// GetCallerInfo 读取调用者信息（通过 /proc/PPID）
// 如果 /proc 不可读（受限容器），返回 nil
func GetCallerInfo() *CallerInfo {
	ppid := os.Getppid()

	// 读解释器路径
	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", ppid))
	if err != nil {
		return nil
	}

	// 读 cmdline 提取脚本路径
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", ppid))
	if err != nil {
		return nil
	}

	args := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
	if len(args) == 0 {
		return nil
	}

	info := &CallerInfo{
		InterpreterPath: exePath,
		InterpreterHash: Sha256File(exePath),
	}

	// 尝试提取脚本路径
	// args[0] = 解释器 (python3/bash)
	// args[1] = 脚本路径（如果存在且不是选项）
	if len(args) > 1 && !strings.HasPrefix(args[1], "-") {
		scriptPath := args[1]
		if !filepath.IsAbs(scriptPath) {
			cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", ppid))
			if err == nil {
				scriptPath = filepath.Join(cwd, scriptPath)
			}
		}
		// 解析符号链接
		realPath, err := filepath.EvalSymlinks(scriptPath)
		if err == nil {
			scriptPath = realPath
		}
		// 文件存在且是常规文件
		if fi, err := os.Stat(scriptPath); err == nil && fi.Mode().IsRegular() {
			info.ScriptPath = scriptPath
			info.ScriptHash = Sha256File(scriptPath)
		}
	}

	return info
}

// Sha256File 计算文件的 SHA256 哈希，返回 "sha256:hex" 格式
func Sha256File(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", h)
}
