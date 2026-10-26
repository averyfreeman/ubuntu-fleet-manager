// Package apthelper validates and runs the root-owned APT helper command used
// by the unprivileged host agent and local stdio runtime.
package apthelper

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/averyfreeman/ubuntu-fleet-manager/internal/hostops"
	"github.com/averyfreeman/ubuntu-fleet-manager/internal/localapt"
)

const (
	PolicyFilePath = "/etc/ubuntu-fleet-manager/apt-policy.json"
	aptGetPath     = "/usr/bin/apt-get"
)

var aptVersionPattern = regexp.MustCompile(`^[A-Za-z0-9.+:~_-]{1,255}$`)

// Run requires root, loads the root-owned operator policy, validates the
// complete typed APT command, and then invokes apt-get with direct argv.
func Run(ctx context.Context, operation string, aptArgs []string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("APT helper must run as root through the configured sudo rule")
	}
	policy, err := localapt.LoadPolicyFile(PolicyFilePath)
	if err != nil {
		return fmt.Errorf("load root-owned APT policy: %w", err)
	}
	if err := ValidateArguments(policy, operation, aptArgs); err != nil {
		return err
	}
	command := exec.CommandContext(ctx, aptGetPath, aptArgs...)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("apt-get %s failed", operation)
	}
	return nil
}

// ValidateArguments ensures the helper accepts only the exact argv shapes
// emitted by hostops. The root policy independently checks operation and
// package allowlists so the sudo rule cannot be used to run general apt-get.
func ValidateArguments(policy hostops.APTPolicy, operation string, aptArgs []string) error {
	policy, err := hostops.NormalizeAPTPolicy(policy)
	if err != nil {
		return fmt.Errorf("invalid root APT policy: %w", err)
	}
	if !policy.Enabled {
		return fmt.Errorf("root APT policy is disabled")
	}
	switch operation {
	case hostops.APTPolicyUpdate:
		if err := requireExactArgs(aptArgs, "-q", "update"); err != nil {
			return err
		}
		if _, err := hostops.ValidateAPTAction(policy, hostops.OperationAPTUpdate, nil); err != nil {
			return err
		}
	case hostops.APTPolicyInstall:
		packages, err := packageArguments(aptArgs, "-q", "-y", "--no-remove", "--no-install-recommends", "install", "--")
		if err != nil {
			return err
		}
		if _, err := hostops.ValidateAPTAction(policy, hostops.OperationAPTInstall, packages); err != nil {
			return err
		}
	case hostops.APTPolicyRemove:
		packages, err := packageArguments(aptArgs, "-q", "-y", "remove", "--")
		if err != nil {
			return err
		}
		if _, err := hostops.ValidateAPTAction(policy, hostops.OperationAPTRemove, packages); err != nil {
			return err
		}
	case hostops.APTPolicyUpgrade:
		packages, err := packageArguments(aptArgs, "-q", "-y", "--no-remove", "--only-upgrade", "install", "--")
		if err != nil {
			return err
		}
		if _, err := hostops.ValidateAPTAction(policy, hostops.OperationAPTUpgrade, packages); err != nil {
			return err
		}
	case hostops.APTPolicyRollback:
		if !hasOperation(policy, hostops.APTPolicyRollback) {
			return fmt.Errorf("APT rollback is not allowed by the root policy")
		}
		if packages, err := packageArguments(aptArgs, "-q", "-y", "--no-remove", "install", "--"); err == nil {
			if len(packages) != 1 {
				return fmt.Errorf("APT rollback must restore one package at a time")
			}
			packageName, version, ok := strings.Cut(packages[0], "=")
			if !ok || !aptVersionPattern.MatchString(version) {
				return fmt.Errorf("APT rollback install argument is invalid")
			}
			if _, err := hostops.ValidateAPTActionInput(hostops.OperationAPTInstall, []string{packageName}); err != nil {
				return err
			}
			if !allowedPackage(policy, packageName) {
				return fmt.Errorf("APT rollback package is not allowed by the root policy")
			}
			return nil
		}
		packages, err := packageArguments(aptArgs, "-q", "-y", "remove", "--")
		if err != nil || len(packages) != 1 {
			return fmt.Errorf("APT rollback command arguments are invalid")
		}
		if _, err := hostops.ValidateAPTActionInput(hostops.OperationAPTRemove, packages); err != nil {
			return err
		}
		if !allowedPackage(policy, packages[0]) {
			return fmt.Errorf("APT rollback package is not allowed by the root policy")
		}
	default:
		return fmt.Errorf("unsupported root APT operation")
	}
	return nil
}

func packageArguments(actual []string, prefix ...string) ([]string, error) {
	if len(actual) <= len(prefix) {
		return nil, fmt.Errorf("APT package command is missing package names")
	}
	for index, expected := range prefix {
		if actual[index] != expected {
			return nil, fmt.Errorf("APT command arguments do not match the permitted operation")
		}
	}
	packages := actual[len(prefix):]
	if len(packages) > hostops.MaxAPTActionPackages {
		return nil, fmt.Errorf("APT action exceeds the %d-package limit", hostops.MaxAPTActionPackages)
	}
	return packages, nil
}

func requireExactArgs(actual []string, expected ...string) error {
	if len(actual) != len(expected) {
		return fmt.Errorf("APT command arguments do not match the permitted operation")
	}
	for index := range expected {
		if actual[index] != expected[index] {
			return fmt.Errorf("APT command arguments do not match the permitted operation")
		}
	}
	return nil
}

func hasOperation(policy hostops.APTPolicy, operation string) bool {
	for _, allowed := range policy.AllowedOperations {
		if allowed == operation {
			return true
		}
	}
	return false
}

func allowedPackage(policy hostops.APTPolicy, requested string) bool {
	for _, allowed := range policy.AllowedPackages {
		if requested == allowed || strings.HasPrefix(requested, allowed+":") || strings.HasPrefix(allowed, requested+":") {
			return true
		}
	}
	return false
}
