// Package internal — Proxy HTTP 客户端
package internal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

// ProxyURL 默认 Proxy 地址
var ProxyURL = getEnv("PROXY_URL", "http://127.0.0.1:8877")

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// CredentialRequest 向 Proxy 发送凭据请求
type CredentialRequest struct {
	Entry  string `json:"entry"`
	Field  string `json:"field,omitempty"`
	Token  bool   `json:"token"`
	Auth   map[string]string `json:"auth,omitempty"`
}

// CredentialResponse Proxy 响应
type CredentialResponse struct {
	Value string `json:"value,omitempty"`
	Error string `json:"error,omitempty"`
	// 完整条目模式
	Title            string            `json:"title,omitempty"`
	Username         string            `json:"username,omitempty"`
	Password         string            `json:"password,omitempty"`
	URL              string            `json:"url,omitempty"`
	CustomProperties map[string]string `json:"custom_properties,omitempty"`
}

// FetchCredential 获取凭据
func FetchCredential(entry, field string, raw bool, auth map[string]string) (*CredentialResponse, error) {
	body := CredentialRequest{
		Entry: entry,
		Token: !raw,
	}
	if field != "" {
		body.Field = field
	}
	if auth != nil {
		body.Auth = auth
	}

	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("序列化请求失败: %w", err)
	}

	url := ProxyURL + "/credential"
	resp, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	var result CredentialResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}

	if resp.StatusCode >= 400 {
		return &result, fmt.Errorf("状态 %d: %s", resp.StatusCode, result.Error)
	}

	return &result, nil
}

// RegisterCallerRequest 注册调用者
type RegisterCallerRequest struct {
	Name          string              `json:"name"`
	Description   string              `json:"description,omitempty"`
	ScriptPath    string              `json:"script_path"`
	ScriptHash    string              `json:"script_hash"`
	Entries       map[string][]string `json:"entries"`
	AllowMode     string              `json:"allow_mode"`
	CanAutoUnlock bool                `json:"can_auto_unlock,omitempty"`
}

// RegisterCaller 注册调用者
func RegisterCaller(req *RegisterCallerRequest) (string, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("序列化失败: %w", err)
	}

	url := ProxyURL + "/register-caller"
	resp, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	var result struct {
		RegID  string `json:"reg_id"`
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	json.Unmarshal(respBody, &result)

	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("注册失败 (%d): %s", resp.StatusCode, result.Error)
	}
	return result.RegID, nil
}
