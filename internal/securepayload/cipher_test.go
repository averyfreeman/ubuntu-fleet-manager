package securepayload

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCipherEncryptsAndAuthenticatesPayloads(t *testing.T) {
	key := bytes.Repeat([]byte{0x37}, KeyBytes)
	cipher, err := New(key)
	if err != nil {
		t.Fatalf("create cipher: %v", err)
	}
	plaintext := []byte("private file contents")
	associatedData := []byte("file-action:tenant:host:action")
	sealed, err := cipher.Seal(plaintext, associatedData)
	if err != nil {
		t.Fatalf("seal payload: %v", err)
	}
	if bytes.Contains(sealed, plaintext) {
		t.Fatalf("sealed payload contains plaintext: %s", sealed)
	}
	opened, err := cipher.Open(sealed, associatedData)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("opened payload = %q, error = %v, want original plaintext", opened, err)
	}
	if _, err := cipher.Open(sealed, []byte("different tenant")); err == nil {
		t.Fatal("cipher opened a payload under different associated data")
	}
	var encoded envelope
	if err := json.Unmarshal(sealed, &encoded); err != nil {
		t.Fatalf("decode envelope fixture: %v", err)
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(encoded.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[0] ^= 0x80
	encoded.Ciphertext = base64.RawStdEncoding.EncodeToString(ciphertext)
	tampered, err := json.Marshal(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cipher.Open(tampered, associatedData); err == nil {
		t.Fatal("cipher opened a payload whose ciphertext was modified")
	}
	if _, err := New(bytes.Repeat([]byte{0x38}, KeyBytes)); err != nil {
		t.Fatalf("create second cipher: %v", err)
	} else if _, err := mustCipher(t, bytes.Repeat([]byte{0x38}, KeyBytes)).Open(sealed, associatedData); err == nil {
		t.Fatal("cipher opened a payload encrypted with another key")
	}
}

func TestNewRequiresExactlyOneAES256Key(t *testing.T) {
	if _, err := New(make([]byte, KeyBytes-1)); err == nil {
		t.Fatal("cipher accepted a key shorter than 32 bytes")
	}
	if _, err := New(make([]byte, KeyBytes+1)); err == nil {
		t.Fatal("cipher accepted a key longer than 32 bytes")
	}
}

func TestLoadKeyFileRequiresPrivateRegularThirtyTwoByteFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "key")
	if err := os.WriteFile(path, bytes.Repeat([]byte{0xa1}, KeyBytes), 0o600); err != nil {
		t.Fatalf("write key fixture: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("set key fixture mode: %v", err)
	}
	key, err := LoadKeyFile(path)
	if err != nil || len(key) != KeyBytes {
		t.Fatalf("load key = %d bytes, error = %v, want %d bytes", len(key), err, KeyBytes)
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("set broad key mode: %v", err)
	}
	if _, err := LoadKeyFile(path); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("LoadKeyFile with broad permissions error = %v, want permission error", err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatalf("set non-secret key mode: %v", err)
	}
	if _, err := LoadKeyFile(path); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("LoadKeyFile with owner execute mode error = %v, want permission error", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("restore key fixture mode: %v", err)
	}
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatalf("write invalid key fixture: %v", err)
	}
	if _, err := LoadKeyFile(path); err == nil || !strings.Contains(err.Error(), "32 bytes") {
		t.Fatalf("LoadKeyFile with short contents error = %v, want length error", err)
	}

	link := filepath.Join(directory, "key-link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatalf("create key symlink: %v", err)
	}
	if _, err := LoadKeyFile(link); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("LoadKeyFile with symlink error = %v, want regular-file error", err)
	}
}

func mustCipher(t *testing.T, key []byte) *Cipher {
	t.Helper()
	cipher, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}
