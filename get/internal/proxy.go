// Package internal — Proxy HTTP 客户端
package internal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// ProxyURL 默认 Proxy 地址
var ProxyURL = getEnv("PROXY_URL", "http://127.0.0.1:8877")

// httpClientTimeoutSeconds 默认 HTTP 超时，可通过 PROXY_HTTP_TIMEOUT 环境变量覆盖。
// 支持 "30"（秒）或 "1m30s"（Go Duration 格式）两种输入。
var httpClientTimeoutSeconds = func() time.Duration {
	s := getEnv("PROXY_HTTP_TIMEOUT", "300")
	// 先试直接解析（支持 "1m30s", "5s" 等标准 Go Duration 格式）
	if d, err := time.ParseDuration(s); err == nil {
		return d
	}
	// 再试纯数字秒数
	if d, err := time.ParseDuration(s + "s"); err == nil {
		return d
	}
	return 30 * time.Second
}()

// httpClient 带超时的共享 HTTP 客户端
var httpClient = &http.Client{
	Timeout: httpClientTimeoutSeconds,
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// CredentialRequest 向 Proxy 发送凭据请求
type CredentialRequest struct {
	Entry string            `json:"entry"`
	Field string            `json:"field,omitempty"`
	Token bool              `json:"token"`
	Auth  map[string]string `json:"auth,omitempty"`
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
	resp, err := httpClient.Post(url, "application/json", bytes.NewReader(data))
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

// RegisterCallerResponse Proxy 注册响应
type RegisterCallerResponse struct {
	RegID  string `json:"reg_id"`
	Status string `json:"status"`
	Error  string `json:"error"`
}

// RegisterCaller 注册调用者
func RegisterCaller(req *RegisterCallerRequest) (string, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("序列化失败: %w", err)
	}

	url := ProxyURL + "/register-caller"
	resp, err := httpClient.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取响应失败: %w", err)
	}

	var result RegisterCallerResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("解析响应失败: %w", err)
	}

	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("注册失败 (%d): %s", resp.StatusCode, result.Error)
	}
	if result.RegID == "" {
		return "", fmt.Errorf("注册返回空 reg_id")
	}
	return result.RegID, nil
}

// RevokeRequest 吊销请求
type RevokeRequest struct {
	Name string `json:"name"`
}

// RevokeResponse 吊销响应
type RevokeResponse struct {
	Status string `json:"status"`
	Name   string `json:"name"`
	Error  string `json:"error,omitempty"`
}

// RevokeCaller 吊销注册
func RevokeCaller(name string) error {
	data, err := json.Marshal(RevokeRequest{Name: name})
	if err != nil {
		return fmt.Errorf("序列化失败: %w", err)
	}

	url := ProxyURL + "/revoke"
	resp, err := httpClient.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取响应失败: %w", err)
	}
	var result RevokeResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("解析响应失败: %w", err)
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("吊销失败 (%d): %s", resp.StatusCode, result.Error)
	}
	return nil
}

// ListRegistrations 列出注册
type RegistrationItem struct {
	Name      string            `json:"name"`
	Type      string            `json:"type"`
	Entries   map[string][]string `json:"entries,omitempty"`
	AllowMode string            `json:"allow_mode"`
	Enabled   bool              `json:"enabled"`
}

type ListResponse struct {
	Registrations []RegistrationItem `json:"registrations,omitempty"`
	Error         string            `json:"error,omitempty"`
}

func ListRegistrations() ([]RegistrationItem, error) {
	url := ProxyURL + "/registrations"
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}
	var result ListResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("查询失败 (%d): %s", resp.StatusCode, result.Error)
	}
	return result.Registrations, nil
}

// ProxyStatus Proxy /health 响应
type ProxyStatus struct {
	Status     string `json:"status"`
	Unlocked   bool   `json:"unlocked"`
	Pending    int    `json:"pending"`
	LlmSecrets int    `json:"llm_secrets"`
	Error      string `json:"error,omitempty"`
}

func FetchStatus() (*ProxyStatus, error) {
	url := ProxyURL + "/health"
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}
	var result ProxyStatus
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("查询失败 (%d): %s", resp.StatusCode, result.Error)
	}
	return &result, nil
}
