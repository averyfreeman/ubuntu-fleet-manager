package localapt

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/averyfreeman/ubuntu-fleet-manager/internal/hostops"
	"github.com/averyfreeman/ubuntu-fleet-manager/internal/mcpserver"
	"github.com/averyfreeman/ubuntu-fleet-manager/internal/systeminfo"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type localAPTCommandRunner struct {
	packages map[string]string
	commands []string
}

func (runner *localAPTCommandRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	command := name + " " + strings.Join(args, " ")
	runner.commands = append(runner.commands, command)
	if name == "/usr/bin/dpkg-query" {
		names := make([]string, 0, len(runner.packages))
		for packageName := range runner.packages {
			names = append(names, packageName)
		}
		sort.Strings(names)
		var output strings.Builder
		for _, packageName := range names {
			fmt.Fprintf(&output, "%s\t%s\tii \n", packageName, runner.packages[packageName])
		}
		return []byte(output.String()), nil
	}
	if name != "/usr/bin/sudo" || len(args) < 6 || args[0] != "-n" || args[1] != "/usr/local/bin/ubuntu-fleet-manager" || args[2] != "apt-helper" {
		return nil, fmt.Errorf("unexpected command: %s", command)
	}
	aptArgs := args[4:]
	operation := ""
	for _, argument := range aptArgs {
		if argument == "install" || argument == "remove" || argument == "update" {
			operation = argument
			break
		}
	}
	if operation == "update" {
		return []byte("updated"), nil
	}
	separator := -1
	for index, argument := range aptArgs {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator < 0 || separator == len(aptArgs)-1 {
		return nil, fmt.Errorf("missing package argument: %s", command)
	}
	for _, packageSpec := range aptArgs[separator+1:] {
		switch operation {
		case "install":
			packageName, version, exact := strings.Cut(packageSpec, "=")
			if !exact {
				version = "2.0"
			}
			runner.packages[packageName] = version
		case "remove":
			delete(runner.packages, packageSpec)
		default:
			return nil, fmt.Errorf("unsupported fake apt action: %s", operation)
		}
	}
	return []byte("completed"), nil
}

func TestLoadPolicyFileRequiresPrivateExplicitStrictPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "apt-policy.json")
	encoded := []byte(`{"enabled":true,"allowed_operations":["rollback","install"],"allowed_packages":["jq","curl"]}`)
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err := LoadPolicyFile(path)
	if err != nil {
		t.Fatalf("load explicit private policy: %v", err)
	}
	if !policy.Enabled || strings.Join(policy.AllowedOperations, ",") != "install,rollback" || strings.Join(policy.AllowedPackages, ",") != "curl,jq" {
		t.Fatalf("normalized local policy = %#v", policy)
	}

	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicyFile(path); err == nil || !strings.Contains(err.Error(), "private regular file") {
		t.Fatalf("policy with group access error = %v, want private-file rejection", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"enabled":false,"unexpected":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicyFile(path); err == nil {
		t.Fatal("policy with an unknown field or no explicit enable was accepted")
	}
	link := filepath.Join(t.TempDir(), "policy-link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicyFile(link); err == nil {
		t.Fatal("symlinked local policy was accepted")
	}
}

func TestLocalAPTToolHandlersPersistEncryptedAuditAndRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "actions.json")
	key := []byte("0123456789abcdef0123456789abcdef")
	policy := hostops.APTPolicy{
		Enabled: true, AllowedOperations: []string{hostops.APTPolicyInstall, hostops.APTPolicyRollback},
		AllowedPackages: []string{"curl"},
	}
	runner := &localAPTCommandRunner{packages: map[string]string{"curl": "1.0"}}
	store, err := NewActionStore(policy, key, path, runner)
	if err != nil {
		t.Fatalf("create encrypted local action store: %v", err)
	}
	handlers := store.ToolHandlers()
	if _, err := handlers.Install(context.Background(), mcpserver.HostAPTActionInput{HostID: "other-host", Packages: []string{"curl"}}); err == nil {
		t.Fatal("local APT handler accepted a remote host identifier")
	}
	if _, err := handlers.Install(context.Background(), mcpserver.HostAPTActionInput{Packages: []string{"wget"}}); err == nil {
		t.Fatal("local APT handler installed a package outside the explicit allowlist")
	}
	if len(runner.commands) != 0 {
		t.Fatalf("denied local APT actions ran commands: %v", runner.commands)
	}
	installed, err := handlers.Install(context.Background(), mcpserver.HostAPTActionInput{Packages: []string{"curl"}})
	if err != nil {
		t.Fatalf("install allowlisted package locally: %v", err)
	}
	if installed.ActionID == "" || installed.Outcome != hostops.APTOutcomeSucceeded || installed.ChangedPackages != 1 || !installed.RollbackAvailable || installed.ExpiresAt.Before(time.Now().Add(6*24*time.Hour)) {
		t.Fatalf("local install receipt = %#v", installed)
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read local action store: %v", err)
	}
	if strings.Contains(string(encoded), "curl") || strings.Contains(string(encoded), "1.0") || !strings.Contains(string(encoded), "ufm_encrypted_payload") {
		t.Fatalf("local action store leaked plaintext package state or omitted encrypted payload: %s", encoded)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("local action-store mode = %v, error=%v; want 0600", info.Mode().Perm(), err)
	}

	// Reopen the store to prove that the action ID and encrypted pre-state
	// survive a process restart.
	restartedRunner := &localAPTCommandRunner{packages: map[string]string{"curl": "2.0"}}
	restarted, err := NewActionStore(policy, key, path, restartedRunner)
	if err != nil {
		t.Fatalf("reopen local action store: %v", err)
	}
	rolledBack, err := restarted.ToolHandlers().Rollback(context.Background(), mcpserver.HostAPTRollbackInput{ActionID: installed.ActionID})
	if err != nil {
		t.Fatalf("rollback local APT action: %v", err)
	}
	if !rolledBack.Exact || rolledBack.AlreadyRestored || rolledBack.RestoredPackages != 1 || restartedRunner.packages["curl"] != "1.0" {
		t.Fatalf("local rollback result = %#v, resulting packages=%v", rolledBack, restartedRunner.packages)
	}
	repeated, err := restarted.ToolHandlers().Rollback(context.Background(), mcpserver.HostAPTRollbackInput{ActionID: installed.ActionID})
	if err != nil || !repeated.AlreadyRestored || !repeated.Exact {
		t.Fatalf("repeat local rollback = %#v, error=%v; want idempotent already-restored result", repeated, err)
	}
}

func TestLocalAPTToolsRunThroughMCPWithoutRemoteHostID(t *testing.T) {
	policy := hostops.APTPolicy{Enabled: true, AllowedOperations: []string{hostops.APTPolicyInstall, hostops.APTPolicyRollback}, AllowedPackages: []string{"curl"}}
	runner := &localAPTCommandRunner{packages: map[string]string{"curl": "1.0"}}
	store, err := NewActionStore(policy, []byte("0123456789abcdef0123456789abcdef"), filepath.Join(t.TempDir(), "private", "actions.json"), runner)
	if err != nil {
		t.Fatalf("create local action store: %v", err)
	}
	server := mcpserver.New(func() (systeminfo.Info, error) { return systeminfo.Info{}, nil }, nil, nil, nil, nil, nil, nil, nil, nil, nil, store.ToolHandlers())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("connect local APT MCP server: %v", err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "local-apt-test-client"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("connect local APT MCP client: %v", err)
	}
	t.Cleanup(func() {
		_ = clientSession.Close()
		_ = serverSession.Wait()
	})
	listed, err := clientSession.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list local MCP tools: %v", err)
	}
	for _, name := range []string{"apt_install", "rollback_apt_action"} {
		var found *mcp.Tool
		for _, tool := range listed.Tools {
			if tool.Name == name {
				found = tool
				break
			}
		}
		if found == nil || found.Annotations == nil || found.Annotations.DestructiveHint == nil || !*found.Annotations.DestructiveHint {
			t.Fatalf("local APT tool %q missing or lacks destructive hint", name)
		}
	}
	for _, name := range []string{"apt_update", "apt_remove", "apt_upgrade"} {
		for _, tool := range listed.Tools {
			if tool.Name == name {
				t.Fatalf("local APT tool %q was registered although local policy denies it", name)
			}
		}
	}
	result, err := clientSession.CallTool(ctx, &mcp.CallToolParams{Name: "apt_install", Arguments: map[string]any{"packages": []string{"curl"}}})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("local apt_install result=%#v error=%v", result, err)
	}
	encoded, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var receipt mcpserver.HostAPTActionResult
	if err := json.Unmarshal(encoded, &receipt); err != nil || receipt.ActionID == "" || receipt.HostID != "" || receipt.Outcome != hostops.APTOutcomeSucceeded {
		t.Fatalf("local apt_install receipt = %#v, decode error=%v", receipt, err)
	}
}

func TestLocalAPTPolicyDefaultDenyAndRetentionCleanup(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	if _, err := NewActionStore(hostops.APTPolicy{}, key, filepath.Join(t.TempDir(), "state.json"), nil); err == nil {
		t.Fatal("local action store accepted disabled-by-default APT policy")
	}
	policy := hostops.APTPolicy{Enabled: true, AllowedOperations: []string{hostops.APTPolicyInstall, hostops.APTPolicyRollback}, AllowedPackages: []string{"curl"}}
	store, err := NewActionStore(policy, key, filepath.Join(t.TempDir(), "private", "actions.json"), nil)
	if err != nil {
		t.Fatalf("create local action store: %v", err)
	}
	unlock, err := store.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.readState()
	if err != nil {
		unlock()
		t.Fatal(err)
	}
	createdAt := time.Now().UTC().Add(-8 * 24 * time.Hour)
	actionID := "9f41bdbe-5e4b-4d2f-9ac2-bf742ec02954"
	plain, err := json.Marshal(actionPayload{
		Operation: hostops.OperationAPTInstall, RequestedPackages: []string{"curl"},
		Result: hostops.APTActionResult{
			Operation: hostops.OperationAPTInstall, Before: []hostops.PackageState{{Name: "curl"}},
			After:   []hostops.PackageState{{Name: "curl", Installed: true, Version: "1.0"}},
			Outcome: hostops.APTOutcomeSucceeded, RollbackAvailable: true,
		},
	})
	if err != nil {
		unlock()
		t.Fatal(err)
	}
	sealed, err := store.cipher.Seal(plain, localActionAssociatedData(actionID))
	if err != nil {
		unlock()
		t.Fatal(err)
	}
	state.Actions = append(state.Actions, actionRecord{ID: actionID, CreatedAt: createdAt, ExpiresAt: createdAt.Add(localActionRetention), Status: "available", Payload: sealed})
	if err := store.writeState(state); err != nil {
		unlock()
		t.Fatal(err)
	}
	unlock()
	if err := store.Cleanup(context.Background()); err != nil {
		t.Fatalf("clean expired local APT data: %v", err)
	}
	unlock, err = store.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	state, err = store.readState()
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Actions) != 0 {
		t.Fatalf("expired local APT records remain: %d", len(state.Actions))
	}
}
