package hostops

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type fakeAPTCommandRunner struct {
	name   string
	args   []string
	output []byte
	err    error
}

func (r *fakeAPTCommandRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.name = name
	r.args = append([]string(nil), args...)
	return r.output, r.err
}

func TestSearchPackagesUsesAPTCacheAndBoundsResults(t *testing.T) {
	runner := &fakeAPTCommandRunner{output: []byte("lib++-dev - development files\nlib++-runtime - runtime files\nlib++-docs - documentation\n")}
	result, err := SearchPackages(context.Background(), "lib++", 2, runner)
	if err != nil {
		t.Fatalf("search configured APT indexes: %v", err)
	}
	pkgCache := aptOptionPath(runner.args, "Dir::Cache::pkgcache")
	srcCache := aptOptionPath(runner.args, "Dir::Cache::srcpkgcache")
	if runner.name != "apt-cache" || pkgCache == "" || srcCache == "" || containsArgs(runner.args, "--no-generate") {
		t.Fatalf("APT command = %s %v, want apt-cache with private temporary cache paths", runner.name, runner.args)
	}
	cacheDirectory := filepath.Dir(pkgCache)
	if cacheDirectory != filepath.Dir(srcCache) || !filepath.IsAbs(cacheDirectory) || !strings.HasPrefix(filepath.Base(cacheDirectory), "ubuntu-fleet-manager-apt-cache-") {
		t.Fatalf("APT cache paths = %q and %q, want one isolated temporary directory", pkgCache, srcCache)
	}
	if _, err := os.Stat(cacheDirectory); !os.IsNotExist(err) {
		t.Fatalf("temporary APT cache directory still exists after search (stat error = %v)", err)
	}
	if len(result.Packages) != 2 || !result.Truncated || result.Packages[0].Name != "lib++-dev" {
		t.Fatalf("search result = %#v, want two sorted matches and truncated=true", result)
	}
	if !containsArgs(runner.args, "lib\\+\\+") {
		t.Fatalf("APT regex args = %v, want literal query escaping", runner.args)
	}
}

func TestSearchPackagesRejectsInvalidQueryAndLimit(t *testing.T) {
	runner := &fakeAPTCommandRunner{}
	for _, query := range []string{"", " \n", strings.Repeat("a", MaxPackageQueryBytes+1), string([]byte{0xff})} {
		if _, err := SearchPackages(context.Background(), query, 10, runner); err == nil {
			t.Errorf("query %q was accepted", query)
		}
	}
	for _, limit := range []int{-1, MaxPackageSearchResults + 1} {
		if _, err := SearchPackages(context.Background(), "apt", limit, runner); err == nil {
			t.Errorf("limit %d was accepted", limit)
		}
	}
}

func TestSearchPackagesUsesConfiguredUbuntuAPTIndex(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("APT package indexes are available only on Linux")
	}
	if _, err := exec.LookPath("apt-cache"); err != nil {
		t.Skip("apt-cache is not installed")
	}
	info, err := os.ReadFile("/etc/os-release")
	if err != nil || !strings.Contains(string(info), "VERSION_ID=\"26.04\"") || !strings.Contains(string(info), "ID=ubuntu") {
		t.Skip("live package-index search runs in the Ubuntu 26.04 CI job")
	}
	result, err := SearchPackages(context.Background(), "apt", 50, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range result.Packages {
		if candidate.Name == "apt" {
			return
		}
	}
	t.Fatalf("configured APT indexes did not return package apt: %#v", result)
}

func containsArgs(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}

func aptOptionPath(args []string, option string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-o" && strings.HasPrefix(args[i+1], option+"=") {
			return strings.TrimPrefix(args[i+1], option+"=")
		}
	}
	return ""
}

func ExampleSearchPackages() {
	fmt.Println(DefaultPackageSearchResults, MaxPackageSearchResults)
	// Output: 50 100
}
