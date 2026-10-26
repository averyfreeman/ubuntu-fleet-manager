package controlplane

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func testEncryptionKeyFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "file-action-key")
	if err := os.WriteFile(path, bytes.Repeat([]byte{0x4a}, 32), 0o600); err != nil {
		t.Fatalf("write application encryption key fixture: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("set application encryption key fixture mode: %v", err)
	}
	return path
}
