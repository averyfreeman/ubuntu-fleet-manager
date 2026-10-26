package hostops

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	OperationAPTUpdate   = "apt_update"
	OperationAPTInstall  = "apt_install"
	OperationAPTRemove   = "apt_remove"
	OperationAPTUpgrade  = "apt_upgrade"
	OperationAPTRollback = "apt_rollback"

	APTPolicyUpdate   = "update"
	APTPolicyInstall  = "install"
	APTPolicyRemove   = "remove"
	APTPolicyUpgrade  = "upgrade"
	APTPolicyRollback = "rollback"

	MaxAPTActionPackages = 20
	MaxAPTPolicyPackages = 500
	MaxAPTActionStates   = 2000
	aptActionTimeout     = 10 * time.Minute
	dpkgQueryFormat      = "${binary:Package}\\t${Version}\\t${db:Status-Abbrev}\\n"
	sudoPath             = "/usr/bin/sudo"
	aptHelperPath        = "/usr/local/bin/ubuntu-fleet-manager"
	dpkgQueryPath        = "/usr/bin/dpkg-query"
	APTOutcomeSucceeded  = "succeeded"
	APTOutcomeFailed     = "failed"
	APTOutcomePartial    = "partial"
	APTOutcomeUnknown    = "unknown"
)

var aptPackageNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,254}(:[a-z0-9][a-z0-9-]{0,31})?$`)

type APTPolicy struct {
	Enabled           bool     `json:"enabled"`
	AllowedOperations []string `json:"allowed_operations,omitempty"`
	AllowedPackages   []string `json:"allowed_packages,omitempty"`
}

type PackageState struct {
	Name      string `json:"name"`
	Installed bool   `json:"installed"`
	Version   string `json:"version,omitempty"`
}

type APTActionResult struct {
	Operation         string         `json:"operation"`
	Before            []PackageState `json:"before,omitempty"`
	After             []PackageState `json:"after,omitempty"`
	Outcome           string         `json:"outcome"`
	RollbackAvailable bool           `json:"rollback_available"`
	Reason            string         `json:"reason,omitempty"`
}

type APTPackageRollbackResult struct {
	Name     string `json:"name"`
	Restored bool   `json:"restored"`
	Exact    bool   `json:"exact"`
	Reason   string `json:"reason,omitempty"`
}

type APTRollbackResult struct {
	Outcome  string                     `json:"outcome"`
	Packages []APTPackageRollbackResult `json:"packages"`
}

// NormalizeAPTPolicy validates and sorts the explicit operation and package
// allowlists stored by a host agent or local stdio configuration.
func NormalizeAPTPolicy(policy APTPolicy) (APTPolicy, error) {
	if !policy.Enabled {
		if len(policy.AllowedOperations) != 0 || len(policy.AllowedPackages) != 0 {
			return APTPolicy{}, fmt.Errorf("disabled APT policy cannot contain allowed operations or packages")
		}
		return APTPolicy{}, nil
	}
	if len(policy.AllowedOperations) == 0 {
		return APTPolicy{}, fmt.Errorf("enabled APT policy must allow at least one operation")
	}
	if len(policy.AllowedPackages) > MaxAPTPolicyPackages {
		return APTPolicy{}, fmt.Errorf("APT policy can allow at most %d packages", MaxAPTPolicyPackages)
	}
	allowedOperations := make(map[string]struct{}, len(policy.AllowedOperations))
	for _, operation := range policy.AllowedOperations {
		if !validAPTPolicyOperation(operation) {
			return APTPolicy{}, fmt.Errorf("APT policy contains unsupported operation %q", operation)
		}
		if _, duplicate := allowedOperations[operation]; duplicate {
			return APTPolicy{}, fmt.Errorf("APT policy contains duplicate operation %q", operation)
		}
		allowedOperations[operation] = struct{}{}
	}
	needsPackages := false
	for _, operation := range []string{APTPolicyInstall, APTPolicyRemove, APTPolicyUpgrade} {
		if _, ok := allowedOperations[operation]; ok {
			needsPackages = true
		}
	}
	if needsPackages && len(policy.AllowedPackages) == 0 {
		return APTPolicy{}, fmt.Errorf("install, remove, and upgrade policies must name allowed packages")
	}
	if _, canRollback := allowedOperations[APTPolicyRollback]; canRollback {
		if _, canInstall := allowedOperations[APTPolicyInstall]; !canInstall {
			if _, canRemove := allowedOperations[APTPolicyRemove]; !canRemove {
				if _, canUpgrade := allowedOperations[APTPolicyUpgrade]; !canUpgrade {
					return APTPolicy{}, fmt.Errorf("APT rollback requires an allowed install, remove, or upgrade operation")
				}
			}
		}
	}
	packages := make(map[string]struct{}, len(policy.AllowedPackages))
	for _, name := range policy.AllowedPackages {
		if !aptPackageNamePattern.MatchString(name) {
			return APTPolicy{}, fmt.Errorf("APT policy contains an invalid package name")
		}
		if _, duplicate := packages[name]; duplicate {
			return APTPolicy{}, fmt.Errorf("APT policy contains duplicate package %q", name)
		}
		packages[name] = struct{}{}
	}
	policy.AllowedOperations = sortedKeys(allowedOperations)
	policy.AllowedPackages = sortedKeys(packages)
	return policy, nil
}

// ValidateAPTAction checks the operation and package set against the explicit
// host policy and returns a normalized copy suitable for job serialization.
func ValidateAPTAction(policy APTPolicy, operation string, packages []string) ([]string, error) {
	policy, err := NormalizeAPTPolicy(policy)
	if err != nil {
		return nil, err
	}
	if !policy.Enabled {
		return nil, fmt.Errorf("APT package changes are disabled by host policy")
	}
	policyOperation, ok := aptPolicyOperationForJob(operation)
	if !ok {
		return nil, fmt.Errorf("unsupported APT operation")
	}
	if !containsString(policy.AllowedOperations, policyOperation) {
		return nil, fmt.Errorf("APT operation is not allowed by host policy")
	}
	if policyOperation == APTPolicyRollback {
		return nil, fmt.Errorf("APT rollback requires captured package state")
	}
	packages, err = ValidateAPTActionInput(operation, packages)
	if err != nil {
		return nil, err
	}
	allowedPackages := make(map[string]struct{}, len(policy.AllowedPackages))
	for _, name := range policy.AllowedPackages {
		allowedPackages[name] = struct{}{}
	}
	for _, name := range packages {
		if _, allowed := allowedPackages[name]; !allowed {
			return nil, fmt.Errorf("APT package is not allowed by host policy")
		}
	}
	return packages, nil
}

// ValidateAPTActionInput checks the public typed job shape before policy is
// applied by the host that executes it.
func ValidateAPTActionInput(operation string, packages []string) ([]string, error) {
	policyOperation, ok := aptPolicyOperationForJob(operation)
	if !ok || policyOperation == APTPolicyRollback {
		return nil, fmt.Errorf("unsupported APT action input")
	}
	if policyOperation == APTPolicyUpdate {
		if len(packages) != 0 {
			return nil, fmt.Errorf("APT index refresh does not accept package names")
		}
		return nil, nil
	}
	if len(packages) == 0 || len(packages) > MaxAPTActionPackages {
		return nil, fmt.Errorf("APT package action must contain between one and %d package names", MaxAPTActionPackages)
	}
	seen := make(map[string]struct{}, len(packages))
	validated := make([]string, 0, len(packages))
	for _, name := range packages {
		if !aptPackageNamePattern.MatchString(name) {
			return nil, fmt.Errorf("APT package action contains an invalid package name")
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, fmt.Errorf("APT package action contains a duplicate package name")
		}
		seen[name] = struct{}{}
		validated = append(validated, name)
	}
	sort.Strings(validated)
	return validated, nil
}

func aptPolicyOperationForJob(operation string) (string, bool) {
	switch operation {
	case OperationAPTUpdate:
		return APTPolicyUpdate, true
	case OperationAPTInstall:
		return APTPolicyInstall, true
	case OperationAPTRemove:
		return APTPolicyRemove, true
	case OperationAPTUpgrade:
		return APTPolicyUpgrade, true
	case OperationAPTRollback:
		return APTPolicyRollback, true
	default:
		return "", false
	}
}

func validAPTPolicyOperation(operation string) bool {
	switch operation {
	case APTPolicyUpdate, APTPolicyInstall, APTPolicyRemove, APTPolicyUpgrade, APTPolicyRollback:
		return true
	default:
		return false
	}
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func sortedKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func validPackageVersion(version string) bool {
	if version == "" || len(version) > 255 {
		return false
	}
	for _, character := range version {
		if !(character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || strings.ContainsRune(".+:~_-", character)) {
			return false
		}
	}
	return true
}

// RunAPTAction executes one explicitly permitted package operation. It records
// the requested and dependency package states that changed, without exposing
// APT's unrestricted command-line surface to the caller.
func RunAPTAction(ctx context.Context, operation string, packages []string, policy APTPolicy, runner APTCommandRunner) (APTActionResult, error) {
	packages, err := ValidateAPTAction(policy, operation, packages)
	if err != nil {
		return APTActionResult{}, err
	}
	policy, err = NormalizeAPTPolicy(policy)
	if err != nil {
		return APTActionResult{}, err
	}
	rollbackAllowed := containsString(policy.AllowedOperations, APTPolicyRollback)
	if runner == nil {
		runner = execAPTCommandRunner{}
	}
	actionCtx, cancel := context.WithTimeout(ctx, aptActionTimeout)
	defer cancel()
	result := APTActionResult{Operation: operation, Outcome: APTOutcomeUnknown}
	if operation == OperationAPTUpdate {
		_, err := runAPTMutation(actionCtx, runner, APTPolicyUpdate, []string{"-q", "update"})
		if err != nil {
			result.Outcome = APTOutcomeFailed
			result.Reason = "APT index refresh failed; configured package sources were not changed"
			return result, nil
		}
		result.Outcome = APTOutcomeSucceeded
		return result, nil
	}

	before, err := installedPackageSnapshot(actionCtx, runner)
	if err != nil {
		return APTActionResult{}, fmt.Errorf("capture installed package state before APT operation: %w", err)
	}
	if operation == OperationAPTUpgrade {
		for _, requested := range packages {
			if _, exists := resolvePackageState(before, requested); !exists {
				return APTActionResult{}, fmt.Errorf("package upgrade requires every requested package to be installed")
			}
		}
	}
	args, err := packageMutationArguments(operation, packages)
	if err != nil {
		return APTActionResult{}, err
	}
	policyOperation, _ := aptPolicyOperationForJob(operation)
	_, operationErr := runAPTMutation(actionCtx, runner, policyOperation, args)
	after, snapshotErr := installedPackageSnapshot(actionCtx, runner)
	if snapshotErr != nil {
		result.Before = packageStatesForRequested(before, packages)
		result.Outcome = APTOutcomeUnknown
		result.RollbackAvailable = false
		result.Reason = "APT operation finished but the resulting package state could not be verified"
		return result, nil
	}
	changedCount := countPackageStateChanges(before, after)
	if changedCount > MaxAPTActionStates {
		result.Before = packageStatesForRequested(before, packages)
		result.After = packageStatesForRequested(after, packages)
		result.Outcome = APTOutcomeUnknown
		result.RollbackAvailable = false
		result.Reason = "APT changed more package states than the bounded rollback record can hold"
		return result, nil
	}
	result.Before, result.After = packageStatesForAction(before, after, packages)
	if operationErr != nil {
		if changedCount == 0 {
			result.Outcome = APTOutcomeFailed
			result.RollbackAvailable = false
			result.Reason = "APT operation failed; no installed package-state changes were observed"
			return result, nil
		}
		result.Outcome = APTOutcomePartial
		result.RollbackAvailable = rollbackAllowed
		if rollbackAllowed {
			result.Reason = "APT operation failed after package-state changes; use rollback_apt_action to attempt compensation"
		} else {
			result.Reason = "APT operation failed after package-state changes; rollback is disabled by host policy"
		}
		return result, nil
	}
	result.Outcome = APTOutcomeSucceeded
	result.RollbackAvailable = rollbackAllowed
	return result, nil
}

func packageMutationArguments(operation string, packages []string) ([]string, error) {
	args := []string{"-q", "-y"}
	switch operation {
	case OperationAPTInstall:
		args = append(args, "--no-remove", "--no-install-recommends", "install", "--")
	case OperationAPTRemove:
		args = append(args, "remove", "--")
	case OperationAPTUpgrade:
		args = append(args, "--no-remove", "--only-upgrade", "install", "--")
	default:
		return nil, fmt.Errorf("unsupported APT package mutation")
	}
	return append(args, packages...), nil
}

func runAPTMutation(ctx context.Context, runner APTCommandRunner, operation string, aptArgs []string) ([]byte, error) {
	args := []string{"-n", aptHelperPath, "apt-helper", operation}
	args = append(args, aptArgs...)
	return runner.Run(ctx, sudoPath, args...)
}

func installedPackageSnapshot(ctx context.Context, runner APTCommandRunner) (map[string]PackageState, error) {
	output, err := runner.Run(ctx, dpkgQueryPath, "-W", "-f="+dpkgQueryFormat)
	if err != nil {
		return nil, fmt.Errorf("query dpkg package database: %w", err)
	}
	if len(output) > MaxPackageOutputBytes {
		return nil, fmt.Errorf("dpkg package snapshot exceeds the %d-byte limit", MaxPackageOutputBytes)
	}
	if len(output) > 0 && output[len(output)-1] != '\n' {
		return nil, fmt.Errorf("dpkg package snapshot contains an incomplete row")
	}
	packages := make(map[string]PackageState)
	for lineNumber, line := range strings.Split(string(output), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 3 {
			return nil, fmt.Errorf("dpkg package snapshot row %d is malformed", lineNumber+1)
		}
		name := fields[0]
		status := strings.TrimSpace(fields[2])
		if !aptPackageNamePattern.MatchString(name) || len(status) != 2 {
			return nil, fmt.Errorf("dpkg package snapshot row %d is invalid", lineNumber+1)
		}
		if status[1] == 'i' {
			if !validPackageVersion(fields[1]) {
				return nil, fmt.Errorf("dpkg package snapshot row %d has an invalid installed version", lineNumber+1)
			}
			if _, duplicate := packages[name]; duplicate {
				return nil, fmt.Errorf("dpkg package snapshot contains a duplicate package")
			}
			packages[name] = PackageState{Name: name, Installed: true, Version: fields[1]}
		} else if status[1] != 'n' && status[1] != 'c' {
			return nil, fmt.Errorf("dpkg package database has a package in an incomplete state")
		}
		if len(packages) > MaxAPTActionStates*10 {
			return nil, fmt.Errorf("dpkg package snapshot exceeds the %d-package safety limit", MaxAPTActionStates*10)
		}
	}
	return packages, nil
}

func packageStatesForAction(before, after map[string]PackageState, requested []string) ([]PackageState, []PackageState) {
	changed := make(map[string]struct{})
	for name, previous := range before {
		if current, exists := after[name]; !exists || current != previous {
			changed[name] = struct{}{}
		}
	}
	for name, current := range after {
		if previous, exists := before[name]; !exists || current != previous {
			changed[name] = struct{}{}
		}
	}
	for _, packageName := range requested {
		if actualName, exists := resolvePackageState(before, packageName); exists {
			changed[actualName] = struct{}{}
		} else if actualName, exists := resolvePackageState(after, packageName); exists {
			changed[actualName] = struct{}{}
		} else {
			changed[packageName] = struct{}{}
		}
	}
	names := sortedKeys(changed)
	previousStates := make([]PackageState, 0, len(names))
	currentStates := make([]PackageState, 0, len(names))
	for _, name := range names {
		previous, exists := before[name]
		if !exists {
			previous = PackageState{Name: name}
		}
		current, exists := after[name]
		if !exists {
			current = PackageState{Name: name}
		}
		previousStates = append(previousStates, previous)
		currentStates = append(currentStates, current)
	}
	return previousStates, currentStates
}

func packageStatesForRequested(snapshot map[string]PackageState, requested []string) []PackageState {
	states := make([]PackageState, 0, len(requested))
	seen := make(map[string]struct{}, len(requested))
	for _, name := range requested {
		actualName := name
		if resolved, exists := resolvePackageState(snapshot, name); exists {
			actualName = resolved
		}
		if _, duplicate := seen[actualName]; duplicate {
			continue
		}
		seen[actualName] = struct{}{}
		if state, exists := snapshot[actualName]; exists {
			states = append(states, state)
		} else {
			states = append(states, PackageState{Name: actualName})
		}
	}
	sort.Slice(states, func(i, j int) bool { return states[i].Name < states[j].Name })
	return states
}

func resolvePackageState(snapshot map[string]PackageState, requested string) (string, bool) {
	if _, exists := snapshot[requested]; exists {
		return requested, true
	}
	match := ""
	for name := range snapshot {
		if strings.HasPrefix(name, requested+":") {
			if match != "" {
				return "", false
			}
			match = name
		}
	}
	return match, match != ""
}

func countPackageStateChanges(before, after map[string]PackageState) int {
	count := 0
	for name, previous := range before {
		if current, exists := after[name]; !exists || current != previous {
			count++
		}
	}
	for name := range after {
		if _, exists := before[name]; !exists {
			count++
		}
	}
	return count
}

// RestoreAPTAction attempts compensating apt-get operations only for packages
// that still match the post-operation state. It reports per-package failures
// because a package version can disappear from configured repositories or
// dependency constraints can prevent an exact restore.
func RestoreAPTAction(ctx context.Context, previous, expectedCurrent []PackageState, policy APTPolicy, runner APTCommandRunner) (APTRollbackResult, error) {
	policy, err := NormalizeAPTPolicy(policy)
	if err != nil {
		return APTRollbackResult{}, err
	}
	if !policy.Enabled || !containsString(policy.AllowedOperations, APTPolicyRollback) {
		return APTRollbackResult{}, fmt.Errorf("APT rollback is disabled by host policy")
	}
	if len(previous) == 0 || len(previous) != len(expectedCurrent) || len(previous) > MaxAPTActionStates {
		return APTRollbackResult{}, fmt.Errorf("APT rollback package state is incomplete or exceeds the safety limit")
	}
	allowed := make(map[string]struct{}, len(policy.AllowedPackages))
	for _, name := range policy.AllowedPackages {
		allowed[name] = struct{}{}
	}
	previousByName := make(map[string]PackageState, len(previous))
	expectedByName := make(map[string]PackageState, len(expectedCurrent))
	for _, state := range previous {
		if err := validatePackageState(state); err != nil {
			return APTRollbackResult{}, err
		}
		if _, duplicate := previousByName[state.Name]; duplicate {
			return APTRollbackResult{}, fmt.Errorf("APT rollback contains duplicate package state")
		}
		previousByName[state.Name] = state
	}
	for _, state := range expectedCurrent {
		if err := validatePackageState(state); err != nil {
			return APTRollbackResult{}, err
		}
		if _, duplicate := expectedByName[state.Name]; duplicate {
			return APTRollbackResult{}, fmt.Errorf("APT rollback contains duplicate expected package state")
		}
		expectedByName[state.Name] = state
	}
	if len(previousByName) != len(expectedByName) {
		return APTRollbackResult{}, fmt.Errorf("APT rollback package state names do not match")
	}
	for name := range previousByName {
		if _, ok := expectedByName[name]; !ok {
			return APTRollbackResult{}, fmt.Errorf("APT rollback package state names do not match")
		}
	}
	if runner == nil {
		runner = execAPTCommandRunner{}
	}
	rollbackCtx, cancel := context.WithTimeout(ctx, aptActionTimeout)
	defer cancel()
	current, err := installedPackageSnapshot(rollbackCtx, runner)
	if err != nil {
		return APTRollbackResult{}, fmt.Errorf("inspect package state before APT rollback: %w", err)
	}
	result := APTRollbackResult{Outcome: APTOutcomeSucceeded, Packages: make([]APTPackageRollbackResult, 0, len(previousByName))}
	eligible := make([]string, 0, len(previousByName))
	for _, name := range sortedKeys(packageStateNames(previousByName)) {
		observed := packageStateOrAbsent(current, name)
		before := previousByName[name]
		expected := expectedByName[name]
		switch {
		case observed == before:
			result.Packages = append(result.Packages, APTPackageRollbackResult{Name: name, Restored: true, Exact: true})
		case !hasPackage(allowed, name):
			result.Packages = append(result.Packages, APTPackageRollbackResult{Name: name, Reason: "package is outside the host allowlist; this dependency change was preserved"})
		case observed != expected:
			result.Packages = append(result.Packages, APTPackageRollbackResult{Name: name, Reason: "package state changed after the managed APT operation; current state was preserved"})
		default:
			eligible = append(eligible, name)
		}
	}
	for _, name := range eligible {
		state := previousByName[name]
		args := []string{"-q", "-y", "--no-remove", "install", "--", name + "=" + state.Version}
		if !state.Installed {
			args = []string{"-q", "-y", "remove", "--", name}
		}
		if _, err := runAPTMutation(rollbackCtx, runner, APTPolicyRollback, args); err != nil {
			// A later state check below decides whether the operation nevertheless
			// restored the requested package (for example, after an interrupted reply).
		}
	}
	if len(eligible) == 0 {
		for _, packageResult := range result.Packages {
			if !packageResult.Exact {
				result.Outcome = APTOutcomePartial
				break
			}
		}
		sort.Slice(result.Packages, func(i, j int) bool { return result.Packages[i].Name < result.Packages[j].Name })
		return result, nil
	}
	finalState, err := installedPackageSnapshot(rollbackCtx, runner)
	if err != nil {
		result.Outcome = APTOutcomePartial
		for _, name := range eligible {
			result.Packages = append(result.Packages, APTPackageRollbackResult{Name: name, Reason: "APT rollback ran but final package state could not be verified"})
		}
		return result, nil
	}
	for _, name := range eligible {
		if packageStateOrAbsent(finalState, name) == previousByName[name] {
			result.Packages = append(result.Packages, APTPackageRollbackResult{Name: name, Restored: true, Exact: true})
		} else {
			result.Packages = append(result.Packages, APTPackageRollbackResult{Name: name, Reason: "APT could not restore the captured version or installation state; repository versions or dependencies may have changed"})
		}
	}
	for _, packageResult := range result.Packages {
		if !packageResult.Exact {
			result.Outcome = APTOutcomePartial
			break
		}
	}
	sort.Slice(result.Packages, func(i, j int) bool { return result.Packages[i].Name < result.Packages[j].Name })
	return result, nil
}

func validatePackageState(state PackageState) error {
	if !aptPackageNamePattern.MatchString(state.Name) {
		return fmt.Errorf("APT rollback contains an invalid package name")
	}
	if state.Installed {
		if !validPackageVersion(state.Version) {
			return fmt.Errorf("APT rollback contains an invalid installed package version")
		}
	} else if state.Version != "" {
		return fmt.Errorf("absent APT package state cannot contain a version")
	}
	return nil
}

func packageStateNames(states map[string]PackageState) map[string]struct{} {
	names := make(map[string]struct{}, len(states))
	for name := range states {
		names[name] = struct{}{}
	}
	return names
}

func packageStateOrAbsent(states map[string]PackageState, name string) PackageState {
	if state, ok := states[name]; ok {
		return state
	}
	return PackageState{Name: name}
}

func hasPackage(allowed map[string]struct{}, name string) bool {
	if _, exists := allowed[name]; exists {
		return true
	}
	for packageName := range allowed {
		if strings.HasPrefix(name, packageName+":") || strings.HasPrefix(packageName, name+":") {
			return true
		}
	}
	return false
}
