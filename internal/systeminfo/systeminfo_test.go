//go:build linux

package systeminfo

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadOSReleaseOrUnknownForMinimalRuntime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "os-release")
	release, err := readOSReleaseOrUnknown(path)
	if err != nil {
		t.Fatalf("read missing os-release: %v", err)
	}
	if release.ID != "unknown" || release.PrettyName != "Unknown Linux distribution" || release.VersionID != "" {
		t.Fatalf("minimal-runtime release = %#v", release)
	}
}

func TestReadOSReleaseOrUnknownPreservesReleaseData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "os-release")
	contents := "ID=ubuntu\nPRETTY_NAME=\"Ubuntu 26.04 LTS\"\nVERSION_ID=\"26.04\"\nVERSION_CODENAME=resolute\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write os-release: %v", err)
	}
	release, err := readOSReleaseOrUnknown(path)
	if err != nil {
		t.Fatalf("read os-release: %v", err)
	}
	if release.ID != "ubuntu" || release.PrettyName != "Ubuntu 26.04 LTS" || release.VersionID != "26.04" || release.VersionCodename != "resolute" {
		t.Fatalf("release = %#v", release)
	}
}
