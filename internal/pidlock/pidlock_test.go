package pidlock

import (
	"os"
	"path/filepath"
	"testing"
)

// TestAcquire_Release 基础获取 + 释放路径。所有平台都能跑（非 Linux 走 no-op stub）。
func TestAcquire_Release(t *testing.T) {
	lock, err := Acquire()
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if lock.Path() == "" {
		t.Error("Path() should be non-empty")
	}
	if err := lock.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
}

// TestReadPidFromFile 边界情况
func TestReadPidFromFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "pid")

	tests := []struct {
		name    string
		content string
		want    int
	}{
		{"valid", "12345\n", 12345},
		{"with whitespace", "  999 \n", 999},
		{"zero", "0", 0},
		{"negative", "-5", 0},
		{"non-numeric", "abc", 0},
		{"empty", "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = os.WriteFile(path, []byte(tt.content), 0644)
			got := readPidFromFile(path)
			if got != tt.want {
				t.Errorf("readPidFromFile(%q) = %d, want %d", tt.content, got, tt.want)
			}
		})
	}
}
