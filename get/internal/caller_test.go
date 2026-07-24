// Package internal — unit tests for caller identification and file hashing
package internal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSha256File(t *testing.T) {
	// Create temp file with known content
	dir := t.TempDir()
	path := filepath.Join(dir, "test_script.sh")
	content := "#!/bin/bash\necho hello\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	hash := Sha256File(path)
	if hash == "" {
		t.Fatal("Sha256File returned empty")
	}
	if !strings.HasPrefix(hash, "sha256:") {
		t.Fatalf("expected sha256: prefix, got %q", hash)
	}
	if len(hash) != 64+7 { // "sha256:" (7) + hex (64)
		t.Fatalf("unexpected hash length: %d", len(hash))
	}
}

func TestSha256FileNotExists(t *testing.T) {
	hash := Sha256File("/nonexistent/file")
	if hash != "" {
		t.Fatalf("expected empty for missing file, got %q", hash)
	}
}

func TestSha256FileEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.bin")
	if err := os.WriteFile(path, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}

	hash := Sha256File(path)
	if hash == "" {
		t.Fatal("Sha256File returned empty for empty file")
	}
	// SHA256 of empty string
	expectedPrefix := "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if hash != expectedPrefix {
		t.Fatalf("expected %q, got %q", expectedPrefix, hash)
	}
}

func TestSha256FileConsistency(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.bin")
	content := "consistent data across runs"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	h1 := Sha256File(path)
	h2 := Sha256File(path)
	if h1 != h2 {
		t.Fatalf("same file produced different hashes: %q vs %q", h1, h2)
	}
}

func TestGetCallerInfoNoProc(t *testing.T) {
	// When /proc is not available (or PPID info is incomplete),
	// GetCallerInfo should return nil gracefully.
	// We can test the function without mocking /proc by relying on
	// the fact that our test runner (go test) has a valid /proc/self.
	info := GetCallerInfo()
	if info == nil {
		t.Log("GetCallerInfo returned nil (expected in restricted environments)")
		return
	}
	// In a normal test environment, /proc/PPID should be available
	// and point to the 'go test' binary
	if info.InterpreterPath == "" {
		t.Error("expected non-empty InterpreterPath")
	}
	if info.InterpreterHash == "" {
		t.Error("expected non-empty InterpreterHash")
	}
	if !strings.HasPrefix(info.InterpreterHash, "sha256:") {
		t.Errorf("expected sha256: prefix, got %q", info.InterpreterHash)
	}
}
