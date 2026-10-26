package hostops

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
)

type packageStateAPTCommandRunner struct {
	packages map[string]string
	commands []string
	failOn   string
}

func (runner *packageStateAPTCommandRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	command := name + " " + strings.Join(args, " ")
	runner.commands = append(runner.commands, command)
	if name == "/usr/bin/dpkg-query" {
		var output strings.Builder
		packageNames := make([]string, 0, len(runner.packages))
		for packageName := range runner.packages {
			packageNames = append(packageNames, packageName)
		}
		sort.Strings(packageNames)
		for _, packageName := range packageNames {
			version := runner.packages[packageName]
			fmt.Fprintf(&output, "%s\t%s\tii \n", packageName, version)
		}
		return []byte(output.String()), nil
	}
	if command == runner.failOn {
		return nil, fmt.Errorf("fake APT failure")
	}
	if name != "/usr/bin/sudo" || len(args) < 6 || args[0] != "-n" || args[1] != "/usr/local/bin/ubuntu-fleet-manager" || args[2] != "apt-helper" {
		return nil, fmt.Errorf("unexpected command: %s", command)
	}
	aptArgs := args[4:]
	operationIndex := -1
	for index, arg := range aptArgs {
		if arg == "update" || arg == "install" || arg == "remove" {
			operationIndex = index
			break
		}
	}
	if operationIndex < 0 {
		return nil, fmt.Errorf("package mutation command is missing an operation: %s", command)
	}
	separatorIndex := -1
	for index, arg := range aptArgs[operationIndex+1:] {
		if arg == "--" {
			separatorIndex = operationIndex + 1 + index
			break
		}
	}
	if separatorIndex < 0 || separatorIndex+1 >= len(aptArgs) {
		if aptArgs[operationIndex] == "update" {
			return []byte("completed"), nil
		}
		return nil, fmt.Errorf("package mutation command is missing package names: %s", command)
	}
	operation := aptArgs[operationIndex]
	packageSpecs := aptArgs[separatorIndex+1:]
	switch operation {
	case "install":
		for _, packageSpec := range packageSpecs {
			if name, version, ok := strings.Cut(packageSpec, "="); ok {
				runner.packages[name] = version
			} else {
				runner.packages[packageSpec] = "2.0"
			}
		}
	case "remove":
		for _, packageSpec := range packageSpecs {
			delete(runner.packages, packageSpec)
		}
	default:
		return nil, fmt.Errorf("unsupported fake APT operation: %s", operation)
	}
	return []byte("completed"), nil
}

func TestAPTPolicyRequiresExplicitBoundedOperationAndPackageAllowlist(t *testing.T) {
	policy := APTPolicy{
		Enabled:           true,
		AllowedOperations: []string{APTPolicyInstall, APTPolicyRemove, APTPolicyUpgrade, APTPolicyRollback},
		AllowedPackages:   []string{"curl", "jq"},
	}
	if _, err := ValidateAPTAction(policy, OperationAPTInstall, []string{"curl"}); err != nil {
		t.Fatalf("authorized package install rejected: %v", err)
	}
	for _, test := range []struct {
		name      string
		policy    APTPolicy
		operation string
		packages  []string
	}{
		{name: "disabled", operation: OperationAPTInstall, packages: []string{"curl"}},
		{name: "operation not allowed", policy: policy, operation: OperationAPTUpdate},
		{name: "package not allowlisted", policy: policy, operation: OperationAPTInstall, packages: []string{"wget"}},
		{name: "shell metacharacters", policy: policy, operation: OperationAPTInstall, packages: []string{"curl;id"}},
		{name: "option injection", policy: policy, operation: OperationAPTInstall, packages: []string{"--assume-yes"}},
		{name: "empty package set", policy: policy, operation: OperationAPTInstall},
		{name: "too many packages", policy: policy, operation: OperationAPTInstall, packages: strings.Fields(strings.Repeat("curl ", MaxAPTActionPackages+1))},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ValidateAPTAction(test.policy, test.operation, test.packages); err == nil {
				t.Fatal("unbounded or unauthorized APT request was accepted")
			}
		})
	}
}

func TestRunAPTActionUsesNonInteractiveSudoAndCapturesPackageState(t *testing.T) {
	runner := &packageStateAPTCommandRunner{packages: map[string]string{"curl": "1.0", "jq": "1.0"}}
	policy := APTPolicy{Enabled: true, AllowedOperations: []string{APTPolicyUpgrade, APTPolicyRollback}, AllowedPackages: []string{"curl"}}
	result, err := RunAPTAction(context.Background(), OperationAPTUpgrade, []string{"curl"}, policy, runner)
	if err != nil {
		t.Fatalf("upgrade allowed package: %v", err)
	}
	if result.Outcome != APTOutcomeSucceeded || !result.RollbackAvailable {
		t.Fatalf("APT result = %#v, want successful action with rollback data", result)
	}
	if len(result.Before) != 1 || result.Before[0] != (PackageState{Name: "curl", Installed: true, Version: "1.0"}) {
		t.Fatalf("pre-operation state = %#v, want curl 1.0", result.Before)
	}
	if len(result.After) != 1 || result.After[0] != (PackageState{Name: "curl", Installed: true, Version: "2.0"}) {
		t.Fatalf("post-operation state = %#v, want curl 2.0", result.After)
	}
	if len(runner.commands) != 3 || !strings.Contains(runner.commands[1], "/usr/bin/sudo -n /usr/local/bin/ubuntu-fleet-manager apt-helper upgrade") || !strings.Contains(runner.commands[1], "--only-upgrade install -- curl") {
		t.Fatalf("APT command sequence = %v, want snapshot, bounded sudo upgrade, snapshot", runner.commands)
	}
	for _, command := range runner.commands {
		if strings.Contains(command, "sh -c") || strings.Contains(command, "bash -c") || strings.Contains(command, "full-upgrade") {
			t.Fatalf("package command invoked an unsafe or unbounded operation: %q", command)
		}
	}
}

func TestRunAPTActionReportsFailedCommandWithoutLosingObservedOutcome(t *testing.T) {
	command := "/usr/bin/sudo -n /usr/local/bin/ubuntu-fleet-manager apt-helper upgrade -q -y --no-remove --only-upgrade install -- curl"
	runner := &packageStateAPTCommandRunner{packages: map[string]string{"curl": "1.0"}, failOn: command}
	policy := APTPolicy{Enabled: true, AllowedOperations: []string{APTPolicyUpgrade, APTPolicyRollback}, AllowedPackages: []string{"curl"}}
	result, err := RunAPTAction(context.Background(), OperationAPTUpgrade, []string{"curl"}, policy, runner)
	if err != nil {
		t.Fatalf("record failed upgrade outcome: %v", err)
	}
	if result.Outcome != APTOutcomeFailed || result.RollbackAvailable || !strings.Contains(result.Reason, "failed") {
		t.Fatalf("failed upgrade result = %#v, want failed outcome with no rollback", result)
	}
	if len(result.Before) != 1 || len(result.After) != 1 || result.Before[0] != result.After[0] {
		t.Fatalf("failed command package state = before %#v after %#v, want unchanged curl state", result.Before, result.After)
	}
}

func TestRunAPTActionRemovesOnlyAllowlistedPackagesWithoutPurgeOrAutoremove(t *testing.T) {
	runner := &packageStateAPTCommandRunner{packages: map[string]string{"curl": "1.0", "jq": "1.0"}}
	policy := APTPolicy{Enabled: true, AllowedOperations: []string{APTPolicyRemove, APTPolicyRollback}, AllowedPackages: []string{"curl"}}
	result, err := RunAPTAction(context.Background(), OperationAPTRemove, []string{"curl"}, policy, runner)
	if err != nil {
		t.Fatalf("remove allowed package: %v", err)
	}
	if result.Outcome != APTOutcomeSucceeded || !result.RollbackAvailable || len(result.Before) != 1 || !result.Before[0].Installed || len(result.After) != 1 || result.After[0].Installed {
		t.Fatalf("remove result = %#v, want captured installed to absent state", result)
	}
	command := runner.commands[1]
	if !strings.Contains(command, "apt-helper remove -q -y remove -- curl") || strings.Contains(command, "purge") || strings.Contains(command, "autoremove") || strings.Contains(command, "full-upgrade") {
		t.Fatalf("remove command = %q, want only the typed APT helper remove operation for curl", command)
	}
}

func TestRestoreAPTActionCompensatesAndPreservesLaterPackageChanges(t *testing.T) {
	policy := APTPolicy{Enabled: true, AllowedOperations: []string{APTPolicyUpgrade, APTPolicyRollback}, AllowedPackages: []string{"curl"}}
	runner := &packageStateAPTCommandRunner{packages: map[string]string{"curl": "2.0"}}
	result, err := RestoreAPTAction(context.Background(), []PackageState{{Name: "curl", Installed: true, Version: "1.0"}}, []PackageState{{Name: "curl", Installed: true, Version: "2.0"}}, policy, runner)
	if err != nil {
		t.Fatalf("restore captured package state: %v", err)
	}
	if result.Outcome != APTOutcomeSucceeded || len(result.Packages) != 1 || !result.Packages[0].Restored || !result.Packages[0].Exact {
		t.Fatalf("rollback result = %#v, want exact curl restoration", result)
	}
	if runner.packages["curl"] != "1.0" {
		t.Fatalf("curl version after rollback = %q, want captured version 1.0", runner.packages["curl"])
	}

	conflictRunner := &packageStateAPTCommandRunner{packages: map[string]string{"curl": "3.0"}}
	conflict, err := RestoreAPTAction(context.Background(), []PackageState{{Name: "curl", Installed: true, Version: "1.0"}}, []PackageState{{Name: "curl", Installed: true, Version: "2.0"}}, policy, conflictRunner)
	if err != nil || conflict.Outcome != APTOutcomePartial || len(conflict.Packages) != 1 || conflict.Packages[0].Restored || !strings.Contains(conflict.Packages[0].Reason, "changed") {
		t.Fatalf("conflicting rollback = %#v, error = %v, want later package state preserved", conflict, err)
	}
	if len(conflictRunner.commands) != 1 || conflictRunner.commands[0] != "/usr/bin/dpkg-query -W -f=${binary:Package}\\t${Version}\\t${db:Status-Abbrev}\\n" {
		t.Fatalf("conflicting rollback ran a mutation command: %v", conflictRunner.commands)
	}

	unavailableCommand := "/usr/bin/sudo -n /usr/local/bin/ubuntu-fleet-manager apt-helper rollback -q -y --no-remove install -- curl=1.0"
	unavailableRunner := &packageStateAPTCommandRunner{packages: map[string]string{"curl": "2.0"}, failOn: unavailableCommand}
	unavailable, err := RestoreAPTAction(context.Background(), []PackageState{{Name: "curl", Installed: true, Version: "1.0"}}, []PackageState{{Name: "curl", Installed: true, Version: "2.0"}}, policy, unavailableRunner)
	if err != nil || unavailable.Outcome != APTOutcomePartial || len(unavailable.Packages) != 1 || unavailable.Packages[0].Exact || !strings.Contains(unavailable.Packages[0].Reason, "repository versions or dependencies") {
		t.Fatalf("unavailable-version rollback = %#v, error = %v, want partial reversal reason", unavailable, err)
	}
}
