// Package internal — 认证构建：get_binary_hash + get_binary_secret + caller_hash + caller_path
package internal

import (
	"os"
)

// GetBinarySecret 读取部署密钥（环境变量，非编译嵌入）
func GetBinarySecret() string {
	return os.Getenv("GET_BINARY_SECRET")
}

// GetBinaryHash 计算 get 二进制自身的 SHA256 哈希
func GetBinaryHash() string {
	exePath, err := os.Executable()
	if err != nil {
		return ""
	}
	return Sha256File(exePath)
}

// BuildAuth 构建三个认证因子，用于 POST 请求的 auth dict
func BuildAuth() map[string]string {
	auth := make(map[string]string)

	// 因子 1：二进制完整性
	if hash := GetBinaryHash(); hash != "" {
		auth["get_binary_hash"] = hash
	}

	// 因子 2：部署密钥（环境变量）
	if secret := GetBinarySecret(); secret != "" {
		auth["get_binary_secret"] = secret
	}

	// 因子 3：调用者身份
	caller := GetCallerInfo()
	if caller != nil && caller.ScriptHash != "" {
		auth["caller_hash"] = caller.ScriptHash
		auth["caller_path"] = caller.ScriptPath
	} else {
		// fallback：直接调用（terminal / 无脚本上下文）
		if hash := GetBinaryHash(); hash != "" {
			auth["caller_hash"] = hash
			if exePath, err := os.Executable(); err == nil {
				auth["caller_path"] = exePath
			}
		}
	}

	return auth
}

// AuthHeaders 构建用于 GET 请求的 HTTP header 映射
func AuthHeaders() map[string]string {
	auth := BuildAuth()
	headers := make(map[string]string)
	for k, v := range auth {
		switch k {
		case "get_binary_hash":
			headers["X-Get-Binary-Hash"] = v
		case "get_binary_secret":
			headers["X-Get-Binary-Secret"] = v
		case "caller_hash":
			headers["X-Caller-Hash"] = v
		case "caller_path":
			headers["X-Caller-Path"] = v
		}
	}
	return headers
}
