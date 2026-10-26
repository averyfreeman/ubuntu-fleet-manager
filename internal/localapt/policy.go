// Package localapt provides explicit, local-stdio APT policy and encrypted
// action storage. It never exposes apt-get arguments to MCP callers.
package localapt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/averyfreeman/ubuntu-fleet-manager/internal/hostops"
)

const MaxPolicyFileBytes = 64 << 10

// LoadPolicyFile loads a private, strict JSON APT policy. The policy is an
// explicit opt-in: it must be enabled and contain at least one bounded
// operation allowlist.
func LoadPolicyFile(path string) (hostops.APTPolicy, error) {
	if !filepath.IsAbs(path) {
		return hostops.APTPolicy{}, fmt.Errorf("local APT policy path must be absolute")
	}
	linkInfo, err := os.Lstat(path)
	if err != nil {
		return hostops.APTPolicy{}, fmt.Errorf("inspect local APT policy file: %w", err)
	}
	if !linkInfo.Mode().IsRegular() || !privateFileMode(linkInfo.Mode().Perm()) || !ownedByCurrentUser(linkInfo) {
		return hostops.APTPolicy{}, fmt.Errorf("local APT policy file must be a private regular file owned by the current user")
	}
	file, err := os.Open(path)
	if err != nil {
		return hostops.APTPolicy{}, fmt.Errorf("open local APT policy file: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !os.SameFile(linkInfo, info) || !info.Mode().IsRegular() || !privateFileMode(info.Mode().Perm()) || !ownedByCurrentUser(info) {
		return hostops.APTPolicy{}, fmt.Errorf("local APT policy file changed while it was opened")
	}
	encoded, err := io.ReadAll(io.LimitReader(file, MaxPolicyFileBytes+1))
	if err != nil {
		return hostops.APTPolicy{}, fmt.Errorf("read local APT policy file: %w", err)
	}
	if len(encoded) > MaxPolicyFileBytes {
		return hostops.APTPolicy{}, fmt.Errorf("local APT policy file exceeds %d bytes", MaxPolicyFileBytes)
	}
	var policy hostops.APTPolicy
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return hostops.APTPolicy{}, fmt.Errorf("decode local APT policy file: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return hostops.APTPolicy{}, fmt.Errorf("local APT policy file must contain one JSON object")
	}
	policy, err = hostops.NormalizeAPTPolicy(policy)
	if err != nil {
		return hostops.APTPolicy{}, fmt.Errorf("invalid local APT policy: %w", err)
	}
	if !policy.Enabled {
		return hostops.APTPolicy{}, fmt.Errorf("local APT policy must explicitly enable at least one operation")
	}
	return policy, nil
}

// DefaultActionStorePath returns the private application-state path used by
// local stdio APT actions.
func DefaultActionStorePath() (string, error) {
	configDirectory, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("find user configuration directory: %w", err)
	}
	return filepath.Join(configDirectory, "ubuntu-fleet-manager", "apt-actions.json"), nil
}

func privateFileMode(mode os.FileMode) bool {
	return mode == 0o400 || mode == 0o600
}

func ownedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid()
}
