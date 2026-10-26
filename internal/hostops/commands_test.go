package hostops_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/averyfreeman/ubuntu-fleet-manager/internal/hostops"
)

type commandRunnerStub struct {
	invocation hostops.CommandInvocation
	called     bool
	execution  hostops.CommandExecution
	err        error
	run        func(context.Context, hostops.CommandInvocation) (hostops.CommandExecution, error)
}

func (runner *commandRunnerStub) Run(ctx context.Context, invocation hostops.CommandInvocation) (hostops.CommandExecution, error) {
	runner.called = true
	runner.invocation = invocation
	if runner.run != nil {
		return runner.run(ctx, invocation)
	}
	return runner.execution, runner.err
}

func TestExecuteCommandPassesAllowlistedArgvLiterally(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "allowed-command")
	if err := os.WriteFile(executable, []byte("test executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	arguments := []string{";", "$HOME", "&&", "$(id)"}
	policy := hostops.CommandPolicy{
		Enabled: true,
		Rules:   []hostops.CommandRule{{Executable: executable, AllowedArguments: [][]string{arguments}}},
	}
	runner := &commandRunnerStub{execution: hostops.CommandExecution{ExitCode: 0, Stdout: []byte("literal argv received\n")}}

	result, err := hostops.ExecuteCommand(context.Background(), policy, hostops.CommandInput{
		Executable: executable,
		Arguments:  arguments,
	}, runner)
	if err != nil {
		t.Fatalf("execute exact allowlisted command: %v", err)
	}
	if !runner.called || runner.invocation.Executable != executable || !reflect.DeepEqual(runner.invocation.Arguments, arguments) || runner.invocation.UseSudo {
		t.Fatalf("runner invocation = %#v, called=%v; want the exact executable and literal argv without sudo", runner.invocation, runner.called)
	}
	if result.ExitCode != 0 || result.Stdout != "literal argv received\n" || result.Stderr != "" {
		t.Fatalf("command result = %#v", result)
	}
}

func TestExecuteCommandDeniesUnlistedPathsShellsAndArguments(t *testing.T) {
	directory := t.TempDir()
	allowedExecutable := writeTestCommand(t, directory, "report")
	otherExecutable := writeTestCommand(t, directory, "other")
	shellExecutable := writeTestCommand(t, directory, "sh")
	bashExecutable := writeTestCommand(t, directory, "bash")
	privilegeExecutable := writeTestCommand(t, directory, "sudo")
	environmentExecutable := writeTestCommand(t, directory, "env")
	alias := filepath.Join(directory, "report-alias")
	if err := os.Symlink(allowedExecutable, alias); err != nil {
		t.Fatal(err)
	}
	policy := hostops.CommandPolicy{Enabled: true, Rules: []hostops.CommandRule{{
		Executable: allowedExecutable, AllowedArguments: [][]string{{"--version"}},
	}}}
	runner := &commandRunnerStub{}

	for _, test := range []struct {
		name   string
		policy hostops.CommandPolicy
		input  hostops.CommandInput
	}{
		{name: "policy disabled", policy: hostops.CommandPolicy{}, input: hostops.CommandInput{Executable: allowedExecutable, Arguments: []string{"--version"}}},
		{name: "argument differs from exact allowlist", policy: policy, input: hostops.CommandInput{Executable: allowedExecutable, Arguments: []string{"--version", ";", "id"}}},
		{name: "unlisted executable", policy: policy, input: hostops.CommandInput{Executable: otherExecutable}},
		{name: "symlink path substitution", policy: policy, input: hostops.CommandInput{Executable: alias, Arguments: []string{"--version"}}},
		{name: "shell executable", policy: hostops.CommandPolicy{Enabled: true, Rules: []hostops.CommandRule{{Executable: shellExecutable, AllowedArguments: [][]string{{"-c", "id"}}}}}, input: hostops.CommandInput{Executable: shellExecutable, Arguments: []string{"-c", "id"}}},
		{name: "bash executable", policy: hostops.CommandPolicy{Enabled: true, Rules: []hostops.CommandRule{{Executable: bashExecutable, AllowedArguments: [][]string{{"-c", "id"}}}}}, input: hostops.CommandInput{Executable: bashExecutable, Arguments: []string{"-c", "id"}}},
		{name: "sudo executable", policy: hostops.CommandPolicy{Enabled: true, Rules: []hostops.CommandRule{{Executable: privilegeExecutable, AllowedArguments: [][]string{{"-n"}}}}}, input: hostops.CommandInput{Executable: privilegeExecutable, Arguments: []string{"-n"}}},
		{name: "env executable", policy: hostops.CommandPolicy{Enabled: true, Rules: []hostops.CommandRule{{Executable: environmentExecutable, AllowedArguments: [][]string{{"REPORT=1"}}}}}, input: hostops.CommandInput{Executable: environmentExecutable, Arguments: []string{"REPORT=1"}}},
		{name: "relative executable path", policy: policy, input: hostops.CommandInput{Executable: "report", Arguments: []string{"--version"}}},
		{name: "NUL in argument", policy: policy, input: hostops.CommandInput{Executable: allowedExecutable, Arguments: []string{"--version\x00"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := hostops.ExecuteCommand(context.Background(), test.policy, test.input, runner); err == nil {
				t.Fatal("unsafe or unallowed command was accepted")
			}
		})
	}
	if runner.called {
		t.Fatalf("policy denials reached the command runner: %#v", runner.invocation)
	}
}

func TestExecuteCommandHonorsWorkingDirectoryAndPolicySudo(t *testing.T) {
	workingDirectory := string(os.PathSeparator)
	policy := hostops.CommandPolicy{Enabled: true, Rules: []hostops.CommandRule{{
		Executable:         "/usr/bin/apt-get",
		AllowedArguments:   [][]string{{}},
		WorkingDirectories: []string{workingDirectory},
		UseSudo:            true,
	}}}
	runner := &commandRunnerStub{execution: hostops.CommandExecution{ExitCode: 0}}
	result, err := hostops.ExecuteCommand(context.Background(), policy, hostops.CommandInput{
		Executable:       "/usr/bin/apt-get",
		Arguments:        []string{},
		WorkingDirectory: workingDirectory,
	}, runner)
	if err != nil {
		t.Fatalf("run command in its configured directory through sudo: %v", err)
	}
	if result.ExitCode != 0 || runner.invocation.WorkingDirectory != workingDirectory || !runner.invocation.UseSudo {
		t.Fatalf("command invocation/result = %#v / %#v", runner.invocation, result)
	}

	deniedRunner := &commandRunnerStub{}
	_, err = hostops.ExecuteCommand(context.Background(), policy, hostops.CommandInput{
		Executable:       "/usr/bin/apt-get",
		Arguments:        []string{},
		WorkingDirectory: "/tmp",
	}, deniedRunner)
	if err == nil || deniedRunner.called {
		t.Fatalf("unlisted working directory was accepted or executed: error=%v invocation=%#v", err, deniedRunner.invocation)
	}

	defaultDirectoryRunner := &commandRunnerStub{execution: hostops.CommandExecution{ExitCode: 0}}
	policy.Rules[0].WorkingDirectories = nil
	if _, err := hostops.ExecuteCommand(context.Background(), policy, hostops.CommandInput{
		Executable: "/usr/bin/apt-get", Arguments: []string{},
	}, defaultDirectoryRunner); err != nil {
		t.Fatalf("execute sudo rule with its default working directory: %v", err)
	}
	if defaultDirectoryRunner.invocation.WorkingDirectory != string(os.PathSeparator) {
		t.Fatalf("sudo command default working directory = %q, want root directory", defaultDirectoryRunner.invocation.WorkingDirectory)
	}

	unsafeDirectory := t.TempDir()
	unsafePolicy := hostops.CommandPolicy{Enabled: true, Rules: []hostops.CommandRule{{
		Executable: "/usr/bin/apt-get", AllowedArguments: [][]string{{}},
		WorkingDirectories: []string{unsafeDirectory}, UseSudo: true,
	}}}
	unsafeRunner := &commandRunnerStub{}
	if _, err := hostops.ExecuteCommand(context.Background(), unsafePolicy, hostops.CommandInput{
		Executable: "/usr/bin/apt-get", Arguments: []string{}, WorkingDirectory: unsafeDirectory,
	}, unsafeRunner); err == nil || unsafeRunner.called {
		t.Fatalf("sudo command accepted a non-root-owned working directory or executed: error=%v invocation=%#v", err, unsafeRunner.invocation)
	}
}

func TestExecuteCommandReportsSudoDenialWithoutLeakingRunnerError(t *testing.T) {
	policy := hostops.CommandPolicy{Enabled: true, Rules: []hostops.CommandRule{{
		Executable: "/usr/bin/apt-get", AllowedArguments: [][]string{{}}, UseSudo: true,
	}}}
	runner := &commandRunnerStub{err: fmt.Errorf("sudo: a password is required for private-token-value")}
	result, err := hostops.ExecuteCommand(context.Background(), policy, hostops.CommandInput{Executable: "/usr/bin/apt-get", Arguments: []string{}}, runner)
	if err == nil || strings.Contains(err.Error(), "private-token-value") || result.Stdout != "" || !runner.invocation.UseSudo {
		t.Fatalf("sudo denial result=%#v error=%v invocation=%#v; want a safe error and no output", result, err, runner.invocation)
	}
}

func TestExecuteCommandTimesOutBoundsOutputAndRedactsCommonSecrets(t *testing.T) {
	policy := hostops.CommandPolicy{Enabled: true, Rules: []hostops.CommandRule{{
		Executable: "/usr/bin/apt-get", AllowedArguments: [][]string{{}},
	}}}
	secretOutput := []byte("password=private-value\nAuthorization: Bearer bearer-private-value\n" + strings.Repeat("x", hostops.MaxCommandOutputBytes))
	runner := &commandRunnerStub{execution: hostops.CommandExecution{ExitCode: 0, Stdout: secretOutput}}
	result, err := hostops.ExecuteCommand(context.Background(), policy, hostops.CommandInput{Executable: "/usr/bin/apt-get", Arguments: []string{}}, runner)
	if err != nil {
		t.Fatalf("execute command with bounded output: %v", err)
	}
	if !result.OutputTruncated || len(result.Stdout)+len(result.Stderr) > hostops.MaxCommandOutputBytes || strings.Contains(result.Stdout, "private-value") {
		t.Fatalf("command output was not bounded and redacted: len=%d result=%#v", len(result.Stdout)+len(result.Stderr), result)
	}

	timeoutRunner := &commandRunnerStub{run: func(ctx context.Context, _ hostops.CommandInvocation) (hostops.CommandExecution, error) {
		<-ctx.Done()
		return hostops.CommandExecution{}, ctx.Err()
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err = hostops.ExecuteCommand(ctx, policy, hostops.CommandInput{Executable: "/usr/bin/apt-get", Arguments: []string{}}, timeoutRunner)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timed command error=%v, want deadline exceeded", err)
	}
}

func writeTestCommand(t *testing.T, directory, name string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte("test executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}
