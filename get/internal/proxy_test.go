// Package internal — unit tests for Proxy HTTP client
package internal

import (
	"encoding/json"
	"os"
	"testing"
)

func TestGetEnvDefault(t *testing.T) {
	os.Unsetenv("TEST_PROXY_VAR")
	result := getEnv("TEST_PROXY_VAR", "fallback_val")
	if result != "fallback_val" {
		t.Fatalf("expected fallback, got %q", result)
	}
}

func TestGetEnvOverride(t *testing.T) {
	os.Setenv("TEST_PROXY_VAR", "override_val")
	defer os.Unsetenv("TEST_PROXY_VAR")

	result := getEnv("TEST_PROXY_VAR", "fallback")
	if result != "override_val" {
		t.Fatalf("expected override_val, got %q", result)
	}
}

func TestGetEnvEmptyFallback(t *testing.T) {
	os.Unsetenv("TEST_PROXY_VAR_EMPTY")
	result := getEnv("TEST_PROXY_VAR_EMPTY", "")
	if result != "" {
		t.Fatalf("expected empty, got %q", result)
	}
}

func TestGetEnvEmptyEnvVar(t *testing.T) {
	os.Setenv("TEST_PROXY_VAR_EMPTY2", "")
	defer os.Unsetenv("TEST_PROXY_VAR_EMPTY2")

	result := getEnv("TEST_PROXY_VAR_EMPTY2", "fallback")
	if result != "fallback" {
		t.Fatalf("expected fallback for empty env, got %q", result)
	}
}

func TestProxyURLDefault(t *testing.T) {
	orig := ProxyURL
	defer func() { ProxyURL = orig }()

	os.Unsetenv("PROXY_URL")
	ProxyURL = getEnv("PROXY_URL", "http://127.0.0.1:8877")
	if ProxyURL != "http://127.0.0.1:8877" {
		t.Fatalf("unexpected default ProxyURL: %q", ProxyURL)
	}
}

func TestProxyURLOverride(t *testing.T) {
	orig := ProxyURL
	defer func() { ProxyURL = orig }()

	os.Setenv("PROXY_URL", "http://custom:9999")
	defer os.Unsetenv("PROXY_URL")

	ProxyURL = getEnv("PROXY_URL", "http://127.0.0.1:8877")
	if ProxyURL != "http://custom:9999" {
		t.Fatalf("expected override, got %q", ProxyURL)
	}
}

func TestCredentialRequestMarshal(t *testing.T) {
	req := CredentialRequest{
		Entry: "test_entry",
		Field: "password",
		Token: true,
		Auth:  map[string]string{"caller_hash": "sha256:abc"},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if parsed["entry"] != "test_entry" {
		t.Errorf("expected test_entry, got %v", parsed["entry"])
	}
	if parsed["field"] != "password" {
		t.Errorf("expected password, got %v", parsed["field"])
	}
	if parsed["token"] != true {
		t.Errorf("expected token=true, got %v", parsed["token"])
	}
}

func TestCredentialResponseUnmarshal(t *testing.T) {
	jsonStr := `{"value":"__VG_CRED_0001__","title":"网易"}`
	var resp CredentialResponse
	if err := json.Unmarshal([]byte(jsonStr), &resp); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if resp.Value != "__VG_CRED_0001__" {
		t.Errorf("expected __VG_CRED_0001__, got %q", resp.Value)
	}
	if resp.Title != "网易" {
		t.Errorf("expected 网易, got %q", resp.Title)
	}
}

func TestRegisterCallerRequestMarshal(t *testing.T) {
	req := RegisterCallerRequest{
		Name:       "test-script",
		ScriptPath: "/tmp/test.py",
		ScriptHash: "sha256:def456",
		Entries:    map[string][]string{"网易": {"password"}},
		AllowMode:  "auto",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if parsed["name"] != "test-script" {
		t.Errorf("expected test-script, got %v", parsed["name"])
	}
	if parsed["allow_mode"] != "auto" {
		t.Errorf("expected auto, got %v", parsed["allow_mode"])
	}
}

func TestRevokeRequestMarshal(t *testing.T) {
	req := RevokeRequest{Name: "test-script"}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if parsed["name"] != "test-script" {
		t.Errorf("expected test-script, got %v", parsed["name"])
	}
}

func TestRevokeResponseUnmarshal(t *testing.T) {
	jsonStr := `{"status":"revoked","name":"test-script"}`
	var resp RevokeResponse
	if err := json.Unmarshal([]byte(jsonStr), &resp); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if resp.Status != "revoked" {
		t.Errorf("expected revoked, got %q", resp.Status)
	}
	if resp.Name != "test-script" {
		t.Errorf("expected test-script, got %q", resp.Name)
	}
}
