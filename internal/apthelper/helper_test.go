package apthelper

import (
	"strings"
	"testing"

	"github.com/averyfreeman/ubuntu-fleet-manager/internal/hostops"
)

func TestValidateArgumentsAllowsOnlyTypedAPTCommandsAndRootPolicyPackages(t *testing.T) {
	policy := hostops.APTPolicy{
		Enabled: true,
		AllowedOperations: []string{
			hostops.APTPolicyUpdate, hostops.APTPolicyInstall, hostops.APTPolicyRemove,
			hostops.APTPolicyUpgrade, hostops.APTPolicyRollback,
		},
		AllowedPackages: []string{"curl", "jq"},
	}
	for _, test := range []struct {
		name      string
		operation string
		args      []string
	}{
		{name: "update indexes", operation: hostops.APTPolicyUpdate, args: []string{"-q", "update"}},
		{name: "install allowlisted package", operation: hostops.APTPolicyInstall, args: []string{"-q", "-y", "--no-remove", "--no-install-recommends", "install", "--", "curl"}},
		{name: "remove without purge", operation: hostops.APTPolicyRemove, args: []string{"-q", "-y", "remove", "--", "curl"}},
		{name: "upgrade installed package", operation: hostops.APTPolicyUpgrade, args: []string{"-q", "-y", "--no-remove", "--only-upgrade", "install", "--", "curl"}},
		{name: "rollback installed version", operation: hostops.APTPolicyRollback, args: []string{"-q", "-y", "--no-remove", "install", "--", "curl=1.0-2ubuntu1"}},
		{name: "rollback package removal", operation: hostops.APTPolicyRollback, args: []string{"-q", "-y", "remove", "--", "curl"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateArguments(policy, test.operation, test.args); err != nil {
				t.Fatalf("valid typed APT command rejected: %v", err)
			}
		})
	}
	for _, test := range []struct {
		name      string
		operation string
		args      []string
	}{
		{name: "unlisted package", operation: hostops.APTPolicyInstall, args: []string{"-q", "-y", "--no-remove", "--no-install-recommends", "install", "--", "wget"}},
		{name: "apt options", operation: hostops.APTPolicyInstall, args: []string{"-q", "-y", "-o", "APT::Get::AllowUnauthenticated=true", "install", "--", "curl"}},
		{name: "purge operation", operation: hostops.APTPolicyRemove, args: []string{"-q", "-y", "purge", "--", "curl"}},
		{name: "extra command argument", operation: hostops.APTPolicyUpdate, args: []string{"-q", "update", "--allow-unauthenticated"}},
		{name: "rollback version injection", operation: hostops.APTPolicyRollback, args: []string{"-q", "-y", "--no-remove", "install", "--", "curl=1.0;id"}},
		{name: "rollback several packages", operation: hostops.APTPolicyRollback, args: []string{"-q", "-y", "--no-remove", "install", "--", "curl=1.0", "jq=1.0"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateArguments(policy, test.operation, test.args); err == nil {
				t.Fatal("unsafe or unbounded APT arguments were accepted")
			}
		})
	}
}

func TestValidateArgumentsRequiresIndependentRootPolicy(t *testing.T) {
	policy := hostops.APTPolicy{Enabled: true, AllowedOperations: []string{hostops.APTPolicyUpdate}}
	if err := ValidateArguments(policy, hostops.APTPolicyInstall, []string{"-q", "-y", "--no-remove", "--no-install-recommends", "install", "--", "curl"}); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("install outside root operation policy error = %v, want denial", err)
	}
	disabled := hostops.APTPolicy{}
	if err := ValidateArguments(disabled, hostops.APTPolicyUpdate, []string{"-q", "update"}); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("disabled root policy error = %v, want default denial", err)
	}
}
