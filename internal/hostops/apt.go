package hostops

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

const (
	DefaultPackageSearchResults = 50
	MaxPackageSearchResults     = 100
	MaxPackageQueryBytes        = 128
	MaxPackageOutputBytes       = 2 << 20
	MaxPackageNameBytes         = 255
	MaxPackageDescriptionBytes  = 4096
	packageSearchTimeout        = 10 * time.Second
)

type PackageSearchEntry struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type PackageSearchResult struct {
	Query     string               `json:"query"`
	Packages  []PackageSearchEntry `json:"packages"`
	Truncated bool                 `json:"truncated"`
}

type APTCommandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type execAPTCommandRunner struct{}

func SearchPackages(ctx context.Context, query string, limit int, runner APTCommandRunner) (PackageSearchResult, error) {
	query, limit, err := ValidatePackageSearchInput(query, limit)
	if err != nil {
		return PackageSearchResult{}, err
	}
	if runner == nil {
		runner = execAPTCommandRunner{}
	}
	cacheDirectory, err := os.MkdirTemp("", "ubuntu-fleet-manager-apt-cache-")
	if err != nil {
		return PackageSearchResult{}, fmt.Errorf("create temporary APT cache directory: %w", err)
	}
	searchCtx, cancel := context.WithTimeout(ctx, packageSearchTimeout)
	defer cancel()
	output, runErr := runner.Run(searchCtx, "apt-cache", "-q",
		"-o", "Dir::Cache::pkgcache="+filepath.Join(cacheDirectory, "pkgcache.bin"),
		"-o", "Dir::Cache::srcpkgcache="+filepath.Join(cacheDirectory, "srcpkgcache.bin"),
		"search", regexp.QuoteMeta(query),
	)
	if err := os.RemoveAll(cacheDirectory); err != nil {
		return PackageSearchResult{}, fmt.Errorf("remove temporary APT cache directory: %w", err)
	}
	if runErr != nil {
		if searchCtx.Err() != nil {
			return PackageSearchResult{}, fmt.Errorf("APT package search exceeded the %s time limit", packageSearchTimeout)
		}
		return PackageSearchResult{}, fmt.Errorf("APT package search failed: %w", runErr)
	}
	if len(output) > MaxPackageOutputBytes {
		return PackageSearchResult{}, fmt.Errorf("APT package search output exceeds the %d-byte limit; narrow the query", MaxPackageOutputBytes)
	}
	if !utf8.Valid(output) {
		return PackageSearchResult{}, fmt.Errorf("APT package search returned invalid UTF-8 output")
	}
	result := PackageSearchResult{Query: query, Packages: make([]PackageSearchEntry, 0, min(limit, 32))}
	for _, line := range strings.Split(string(output), "\n") {
		if line == "" {
			continue
		}
		if len(line) > MaxPackageNameBytes+MaxPackageDescriptionBytes+3 {
			return PackageSearchResult{}, fmt.Errorf("APT package search returned an oversized result line")
		}
		name, description, found := strings.Cut(line, " - ")
		if !found || name == "" || len(name) > MaxPackageNameBytes || len(description) > MaxPackageDescriptionBytes {
			return PackageSearchResult{}, fmt.Errorf("APT package search returned a malformed result")
		}
		if len(result.Packages) == limit {
			result.Truncated = true
			break
		}
		result.Packages = append(result.Packages, PackageSearchEntry{Name: name, Description: description})
	}
	return result, nil
}

func ValidatePackageSearchInput(query string, limit int) (string, int, error) {
	query = strings.TrimSpace(query)
	if query == "" || len(query) > MaxPackageQueryBytes || !utf8.ValidString(query) {
		return "", 0, fmt.Errorf("package search query must contain 1 to %d bytes", MaxPackageQueryBytes)
	}
	for _, character := range query {
		if character < 0x20 || character == 0x7f {
			return "", 0, fmt.Errorf("package search query cannot contain control characters")
		}
	}
	if limit == 0 {
		limit = DefaultPackageSearchResults
	}
	if limit < 1 || limit > MaxPackageSearchResults {
		return "", 0, fmt.Errorf("package result limit must be between 1 and %d", MaxPackageSearchResults)
	}
	return query, limit, nil
}

func (execAPTCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.WaitDelay = 3 * time.Second
	var timerMu sync.Mutex
	var forceKill *time.Timer
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		pid := command.Process.Pid
		if err := syscall.Kill(-pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
			return err
		}
		timerMu.Lock()
		forceKill = time.AfterFunc(2*time.Second, func() {
			_ = syscall.Kill(-pid, syscall.SIGKILL)
		})
		timerMu.Unlock()
		return nil
	}
	defer func() {
		timerMu.Lock()
		if forceKill != nil {
			forceKill.Stop()
		}
		timerMu.Unlock()
	}()
	stdout := &boundedOutput{limit: MaxPackageOutputBytes}
	stderr := &boundedOutput{limit: 8 << 10}
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		message := strings.TrimSpace(string(stderr.bytes))
		if message == "" {
			return nil, fmt.Errorf("%s exited unsuccessfully: %w", filepath.Base(name), err)
		}
		return nil, fmt.Errorf("%s exited unsuccessfully: %s", filepath.Base(name), message)
	}
	if stdout.exceeded {
		return nil, fmt.Errorf("%s output exceeded the configured limit", filepath.Base(name))
	}
	return stdout.bytes, nil
}

type boundedOutput struct {
	bytes    []byte
	limit    int
	exceeded bool
}

func (o *boundedOutput) Write(input []byte) (int, error) {
	remaining := o.limit - len(o.bytes)
	if remaining <= 0 {
		o.exceeded = true
		return len(input), nil
	}
	if len(input) > remaining {
		o.bytes = append(o.bytes, input[:remaining]...)
		o.exceeded = true
		return len(input), nil
	}
	o.bytes = append(o.bytes, input...)
	return len(input), nil
}
