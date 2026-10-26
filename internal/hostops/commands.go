package hostops

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

type CommandPolicy struct {
	Enabled bool          `json:"enabled"`
	Rules   []CommandRule `json:"rules,omitempty"`
}

type CommandRule struct {
	Executable         string     `json:"executable"`
	AllowedArguments   [][]string `json:"allowed_arguments"`
	WorkingDirectories []string   `json:"working_directories,omitempty"`
	UseSudo            bool       `json:"use_sudo,omitempty"`
}

type CommandInput struct {
	Executable       string   `json:"executable"`
	Arguments        []string `json:"args"`
	WorkingDirectory string   `json:"working_directory,omitempty"`
}

type CommandInvocation struct {
	Executable       string
	Arguments        []string
	WorkingDirectory string
	UseSudo          bool
}

type CommandExecution struct {
	ExitCode        int
	Stdout          []byte
	Stderr          []byte
	OutputTruncated bool
}

type CommandResult struct {
	ExitCode        int    `json:"exit_code"`
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	OutputTruncated bool   `json:"output_truncated"`
}

type CommandRunner interface {
	Run(context.Context, CommandInvocation) (CommandExecution, error)
}

const (
	MaxCommandRules        = 100
	MaxCommandArgumentSets = 100
	MaxCommandArguments    = 64
	MaxCommandArgumentSize = 4096
	MaxCommandOutputBytes  = 64 << 10
	CommandTimeout         = 30 * time.Second
)

var (
	sensitiveAssignmentPattern = regexp.MustCompile(`(?i)([a-z0-9_.-]*(?:password|passwd|secret|token|api[_-]?key|authorization)[a-z0-9_.-]*[ \t]*[:=][ \t]*)("[^"\r\n]*"|'[^'\r\n]*'|[^,;\s}\r\n]+)`)
	bearerCredentialPattern    = regexp.MustCompile(`(?i)\bBearer[ \t]+[A-Za-z0-9._~+/-]+=*`)
	privateKeyPattern          = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)
	providerTokenPattern       = regexp.MustCompile(`(?i)\b(?:gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,}|sk-[A-Za-z0-9_-]{16,})\b`)
)

// NormalizeCommandPolicy validates the exact executable and argument vectors
// permitted by one host's command policy.
func NormalizeCommandPolicy(policy CommandPolicy) (CommandPolicy, error) {
	if !policy.Enabled {
		if len(policy.Rules) != 0 {
			return CommandPolicy{}, fmt.Errorf("disabled command policy cannot contain rules")
		}
		return CommandPolicy{}, nil
	}
	if len(policy.Rules) == 0 || len(policy.Rules) > MaxCommandRules {
		return CommandPolicy{}, fmt.Errorf("enabled command policy must contain one to %d rules", MaxCommandRules)
	}
	seen := make(map[string]struct{}, len(policy.Rules))
	for index := range policy.Rules {
		rule := &policy.Rules[index]
		if err := validateCommandPath(rule.Executable); err != nil {
			return CommandPolicy{}, fmt.Errorf("command rule %d executable is invalid", index+1)
		}
		if err := validateCommandExecutable(rule.Executable, rule.UseSudo); err != nil {
			return CommandPolicy{}, fmt.Errorf("command rule %d executable is invalid: %w", index+1, err)
		}
		if len(rule.AllowedArguments) == 0 || len(rule.AllowedArguments) > MaxCommandArgumentSets {
			return CommandPolicy{}, fmt.Errorf("command rule %d must contain one to %d exact argument vectors", index+1, MaxCommandArgumentSets)
		}
		for _, arguments := range rule.AllowedArguments {
			if arguments == nil {
				return CommandPolicy{}, fmt.Errorf("command rule %d argument vectors must be arrays", index+1)
			}
			if err := validateCommandArguments(arguments); err != nil {
				return CommandPolicy{}, fmt.Errorf("command rule %d has invalid allowed arguments", index+1)
			}
			key := rule.Executable + "\x00" + fmt.Sprintf("%q", arguments)
			if _, duplicate := seen[key]; duplicate {
				return CommandPolicy{}, fmt.Errorf("command policy contains an ambiguous executable and argument rule")
			}
			seen[key] = struct{}{}
		}
		seenDirectories := make(map[string]struct{}, len(rule.WorkingDirectories))
		for _, directory := range rule.WorkingDirectories {
			if err := validateCommandDirectory(directory); err != nil {
				return CommandPolicy{}, fmt.Errorf("command rule %d has an invalid working directory", index+1)
			}
			if rule.UseSudo && !rootOwnedPath(directory) {
				return CommandPolicy{}, fmt.Errorf("sudo command working directories must be root-owned and not writable by group or others")
			}
			if _, duplicate := seenDirectories[directory]; duplicate {
				return CommandPolicy{}, fmt.Errorf("command policy contains a duplicate working directory")
			}
			seenDirectories[directory] = struct{}{}
		}
	}
	return policy, nil
}

// ExecuteCommand only runs an exact executable and argv vector enabled by the
// host's command policy. A nil runner executes the absolute program directly.
func ExecuteCommand(ctx context.Context, policy CommandPolicy, input CommandInput, runner CommandRunner) (CommandResult, error) {
	normalized, err := NormalizeCommandPolicy(policy)
	if err != nil {
		return CommandResult{}, err
	}
	policy = normalized
	if !policy.Enabled {
		return CommandResult{}, fmt.Errorf("host command execution is disabled by policy")
	}
	if err := validateCommandPath(input.Executable); err != nil {
		return CommandResult{}, err
	}
	if input.WorkingDirectory != "" {
		if err := validateCommandDirectory(input.WorkingDirectory); err != nil {
			return CommandResult{}, err
		}
	}
	if err := validateCommandArguments(input.Arguments); err != nil {
		return CommandResult{}, err
	}
	if err := validateCommandExecutable(input.Executable, false); err != nil {
		return CommandResult{}, err
	}
	var matched *CommandRule
	for _, rule := range policy.Rules {
		if rule.Executable != input.Executable {
			continue
		}
		for _, arguments := range rule.AllowedArguments {
			if slices.Equal(arguments, input.Arguments) {
				if input.WorkingDirectory == "" || containsCommandDirectory(rule.WorkingDirectories, input.WorkingDirectory) {
					matched = &rule
				}
				break
			}
		}
	}
	if matched == nil {
		return CommandResult{}, fmt.Errorf("command executable or arguments are not allowed by host policy")
	}
	workingDirectory := input.WorkingDirectory
	if matched.UseSudo && workingDirectory == "" {
		workingDirectory = string(os.PathSeparator)
	}
	if runner == nil {
		runner = execCommandRunner{}
	}
	commandCtx, cancel := context.WithTimeout(ctx, CommandTimeout)
	defer cancel()
	execution, err := runner.Run(commandCtx, CommandInvocation{
		Executable: input.Executable, Arguments: append([]string(nil), input.Arguments...),
		WorkingDirectory: workingDirectory, UseSudo: matched.UseSudo,
	})
	if err != nil {
		if errors.Is(commandCtx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
			return CommandResult{}, fmt.Errorf("command exceeded the %s time limit: %w", CommandTimeout, context.DeadlineExceeded)
		}
		if errors.Is(commandCtx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
			return CommandResult{}, context.Canceled
		}
		return CommandResult{}, fmt.Errorf("command execution failed")
	}
	stdout, stderr, truncated := boundAndRedactCommandOutput(execution.Stdout, execution.Stderr)
	return CommandResult{
		ExitCode: execution.ExitCode, Stdout: stdout, Stderr: stderr,
		OutputTruncated: execution.OutputTruncated || truncated,
	}, nil
}

func validateCommandPath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, '\x00') {
		return fmt.Errorf("command executable must be an absolute, clean path")
	}
	return nil
}

func validateCommandArguments(arguments []string) error {
	if arguments == nil {
		return fmt.Errorf("command args must be an array, even when empty")
	}
	if len(arguments) > MaxCommandArguments {
		return fmt.Errorf("command has more than %d arguments", MaxCommandArguments)
	}
	for _, argument := range arguments {
		if !utf8.ValidString(argument) || strings.ContainsFunc(argument, func(character rune) bool {
			return character < 0x20 || character == 0x7f
		}) || len(argument) > MaxCommandArgumentSize {
			return fmt.Errorf("command argument contains a control character or exceeds %d bytes", MaxCommandArgumentSize)
		}
	}
	return nil
}

func validateCommandExecutable(path string, useSudo bool) error {
	base := strings.ToLower(filepath.Base(path))
	switch base {
	case "sh", "dash", "bash", "zsh", "fish", "csh", "tcsh", "ksh", "ash", "busybox",
		"sudo", "su", "runuser", "doas", "pkexec", "env":
		return fmt.Errorf("shells, privilege launchers, and environment wrappers cannot be run by execute_command")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return fmt.Errorf("command executable must not be a symlink or alias")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("command executable must be an existing regular executable file")
	}
	if useSudo && !rootOwnedPath(path) {
		return fmt.Errorf("sudo command executable and its parent directories must be root-owned and not writable by group or others")
	}
	return nil
}

func validateCommandDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, '\x00') {
		return fmt.Errorf("command working directory must be an absolute, clean path")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return fmt.Errorf("command working directory must not be a symlink or alias")
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("command working directory must be an existing directory")
	}
	return nil
}

func rootOwnedPath(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	if path == string(os.PathSeparator) {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
			return false
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		return ok && stat.Uid == 0
	}
	current := string(os.PathSeparator)
	components := strings.Split(strings.TrimPrefix(path, current), current)
	for index, component := range components {
		if component == "" {
			return false
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
			return false
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return false
		}
		if index < len(components)-1 && !info.IsDir() {
			return false
		}
	}
	return true
}

func containsCommandDirectory(directories []string, candidate string) bool {
	for _, directory := range directories {
		if directory == candidate {
			return true
		}
	}
	return false
}

func boundAndRedactCommandOutput(stdout, stderr []byte) (string, string, bool) {
	truncated := false
	if len(stdout) > MaxCommandOutputBytes {
		stdout = stdout[:MaxCommandOutputBytes]
		stderr = nil
		truncated = true
	} else if len(stdout)+len(stderr) > MaxCommandOutputBytes {
		stderr = stderr[:MaxCommandOutputBytes-len(stdout)]
		truncated = true
	}
	stdoutText := redactCommandOutput(strings.ToValidUTF8(string(stdout), "�"))
	stderrText := redactCommandOutput(strings.ToValidUTF8(string(stderr), "�"))
	stdoutText, stdoutCut := truncateCommandText(stdoutText, MaxCommandOutputBytes)
	remaining := MaxCommandOutputBytes - len(stdoutText)
	stderrText, stderrCut := truncateCommandText(stderrText, remaining)
	return stdoutText, stderrText, truncated || stdoutCut || stderrCut
}

func redactCommandOutput(output string) string {
	output = privateKeyPattern.ReplaceAllString(output, "[REDACTED PRIVATE KEY]")
	output = bearerCredentialPattern.ReplaceAllString(output, "Bearer [REDACTED]")
	output = providerTokenPattern.ReplaceAllString(output, "[REDACTED TOKEN]")
	return sensitiveAssignmentPattern.ReplaceAllString(output, "${1}[REDACTED]")
}

func truncateCommandText(output string, limit int) (string, bool) {
	if limit < 0 {
		return "", true
	}
	if len(output) <= limit {
		return output, false
	}
	output = output[:limit]
	for !utf8.ValidString(output) {
		output = output[:len(output)-1]
	}
	return output, true
}

// SanitizeCommandResult bounds remote output and redacts common credential
// patterns before an MCP response is returned or a job result is retained.
func SanitizeCommandResult(result CommandResult) CommandResult {
	stdout, stderr, truncated := boundAndRedactCommandOutput([]byte(result.Stdout), []byte(result.Stderr))
	result.Stdout = stdout
	result.Stderr = stderr
	result.OutputTruncated = result.OutputTruncated || truncated
	return result
}

type execCommandRunner struct{}

func (execCommandRunner) Run(ctx context.Context, invocation CommandInvocation) (CommandExecution, error) {
	name := invocation.Executable
	arguments := invocation.Arguments
	if invocation.UseSudo {
		name = sudoPath
		arguments = append([]string{"-n", "--", invocation.Executable}, arguments...)
	}
	command := exec.CommandContext(ctx, name, arguments...)
	command.Dir = invocation.WorkingDirectory
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
		forceKill = time.AfterFunc(2*time.Second, func() { _ = syscall.Kill(-pid, syscall.SIGKILL) })
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
	stdout := &boundedOutput{limit: MaxCommandOutputBytes}
	stderr := &boundedOutput{limit: MaxCommandOutputBytes}
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return CommandExecution{}, ctx.Err()
		}
		if exitError, ok := err.(*exec.ExitError); ok {
			return CommandExecution{
				ExitCode: exitError.ExitCode(), Stdout: stdout.bytes, Stderr: stderr.bytes,
				OutputTruncated: stdout.exceeded || stderr.exceeded,
			}, nil
		}
		return CommandExecution{}, fmt.Errorf("command execution failed")
	}
	return CommandExecution{
		ExitCode: 0, Stdout: stdout.bytes, Stderr: stderr.bytes,
		OutputTruncated: stdout.exceeded || stderr.exceeded,
	}, nil
}
