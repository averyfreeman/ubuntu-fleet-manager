package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/averyfreeman/ubuntu-fleet-manager/internal/hostops"
	"github.com/averyfreeman/ubuntu-fleet-manager/internal/mcpserver"
	"github.com/averyfreeman/ubuntu-fleet-manager/internal/systeminfo"
	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type jobTestHarness struct {
	ctx        context.Context
	service    *Service
	server     *httptest.Server
	issuer     *testIssuer
	sessionA   *mcp.ClientSession
	sessionB   *mcp.ClientSession
	hostID     string
	credential string
}

type jobTestLease struct {
	ID             string          `json:"id"`
	Operation      string          `json:"operation"`
	Input          json.RawMessage `json:"input"`
	LeaseToken     string          `json:"lease_token"`
	LeaseExpiresAt time.Time       `json:"lease_expires_at"`
	Attempt        int             `json:"attempt"`
}

type jobCallOutcome struct {
	result *mcp.CallToolResult
	err    error
}

func TestGetHostSystemInfoFlowsThroughPostgreSQLAndAuthenticatedAgent(t *testing.T) {
	harness := newJobTestHarness(t)

	toolList, err := harness.sessionA.ListTools(harness.ctx, nil)
	if err != nil {
		t.Fatalf("list authenticated tools: %v", err)
	}
	if !hasTool(toolList.Tools, "get_host_system_info") || !hasTool(toolList.Tools, "get_system_info") {
		t.Fatalf("remote tools = %v, want both local and host-targeted system-info tools", toolNames(toolList.Tools))
	}

	completed := make(chan jobCallOutcome, 1)
	go func() {
		result, err := harness.sessionA.CallTool(harness.ctx, &mcp.CallToolParams{
			Name:      "get_host_system_info",
			Arguments: map[string]any{"host_id": harness.hostID},
		})
		completed <- jobCallOutcome{result: result, err: err}
	}()

	lease := waitForAgentJob(t, harness, 5*time.Second)
	if lease.Operation != "get_system_info" {
		t.Fatalf("leased operation = %q, want get_system_info", lease.Operation)
	}
	if lease.LeaseToken == "" || lease.ID == "" || lease.Attempt != 1 || !lease.LeaseExpiresAt.After(time.Now()) {
		t.Fatalf("invalid job lease: %#v", lease)
	}

	snapshot := sampleSystemInfo("web-01")
	resultResponse, resultBody := postAgentJSON(t, harness.ctx, harness.server.URL, "/agent/result", map[string]any{
		"job_id":      lease.ID,
		"lease_token": lease.LeaseToken,
		"result":      snapshot,
	}, harness.credential)
	if resultResponse.StatusCode != http.StatusOK {
		t.Fatalf("submit agent result status = %d, want 200: %s", resultResponse.StatusCode, resultBody)
	}
	duplicateSnapshot := sampleSystemInfo("changed-after-completion")
	duplicateResponse, duplicateBody := postAgentJSON(t, harness.ctx, harness.server.URL, "/agent/result", map[string]any{
		"job_id":      lease.ID,
		"lease_token": lease.LeaseToken,
		"result":      duplicateSnapshot,
	}, harness.credential)
	if duplicateResponse.StatusCode != http.StatusOK {
		t.Fatalf("duplicate completed result status = %d, want idempotent 200: %s", duplicateResponse.StatusCode, duplicateBody)
	}

	outcome := waitForMCPOutcome(t, completed, 5*time.Second)
	if outcome.err != nil {
		t.Fatalf("call get_host_system_info: %v", outcome.err)
	}
	if outcome.result == nil || outcome.result.IsError {
		t.Fatalf("get_host_system_info result = %#v, want success", outcome.result)
	}
	payload, err := json.Marshal(outcome.result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal host system-info result: %v", err)
	}
	var received struct {
		HostID      string          `json:"host_id"`
		Hostname    string          `json:"hostname"`
		RequestedAt time.Time       `json:"requested_at"`
		SystemInfo  systeminfo.Info `json:"system_info"`
	}
	if err := json.Unmarshal(payload, &received); err != nil {
		t.Fatalf("decode host system-info result: %v", err)
	}
	if received.HostID != harness.hostID || received.Hostname != "job-target.example.test" {
		t.Fatalf("target identity = host %q (%q), want %q (job-target.example.test)", received.HostID, received.Hostname, harness.hostID)
	}
	if received.RequestedAt.IsZero() || !received.SystemInfo.CollectedAt.Equal(snapshot.CollectedAt) {
		t.Fatalf("result freshness is incomplete: %#v", received)
	}
	if received.SystemInfo.Hostname != snapshot.Hostname || received.SystemInfo.OS.PrettyName != snapshot.OS.PrettyName {
		t.Fatalf("agent snapshot = %#v, want %#v", received.SystemInfo, snapshot)
	}
	removed, err := harness.sessionA.CallTool(harness.ctx, &mcp.CallToolParams{
		Name:      "remove_host",
		Arguments: map[string]any{"host_id": harness.hostID},
	})
	if err != nil || removed == nil || removed.IsError {
		t.Fatalf("remove host after delivering snapshot: result=%#v error=%v", removed, err)
	}
	var status string
	if err := harness.service.store.pool.QueryRow(harness.ctx, "SELECT status FROM jobs WHERE id = $1::uuid", lease.ID).Scan(&status); err != nil {
		t.Fatalf("read delivered job status after host removal: %v", err)
	}
	if status != "completed" {
		t.Fatalf("delivered job status after host removal = %q, want completed", status)
	}
}

func TestReadOnlyHostToolsFlowThroughPostgreSQLAndAuthenticatedFakeAgent(t *testing.T) {
	harness := newJobTestHarness(t)

	toolList, err := harness.sessionA.ListTools(harness.ctx, nil)
	if err != nil {
		t.Fatalf("list authenticated tools: %v", err)
	}
	for _, name := range []string{"list_directory", "read_file", "search_packages"} {
		var found *mcp.Tool
		for _, tool := range toolList.Tools {
			if tool.Name == name {
				found = tool
				break
			}
		}
		if found == nil {
			t.Fatalf("authenticated tools do not include %q: %v", name, toolNames(toolList.Tools))
		}
		if found.Annotations == nil || !found.Annotations.ReadOnlyHint || !found.Annotations.IdempotentHint || found.Annotations.OpenWorldHint == nil || *found.Annotations.OpenWorldHint {
			t.Errorf("tool %q annotations = %#v, want bounded, idempotent, read-only host access", name, found.Annotations)
		}
	}
	if hasTool(toolList.Tools, "write_file") || hasTool(toolList.Tools, "rollback_file") {
		t.Fatal("file mutation tools were registered while the operator approval policy was disabled")
	}

	allowedRoot := t.TempDir()
	insideFile := filepath.Join(allowedRoot, "settings.conf")
	if err := os.WriteFile(insideFile, []byte("mode=safe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outsideRoot := t.TempDir()
	outsideFile := filepath.Join(outsideRoot, "private.conf")
	if err := os.WriteFile(outsideFile, []byte("secret=value\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	submitResult := func(job jobTestLease, result any, failure string) error {
		payload := map[string]any{"job_id": job.ID, "lease_token": job.LeaseToken}
		if failure != "" {
			payload["error"] = failure
		} else {
			payload["result"] = result
		}
		response, body := postAgentJSON(t, harness.ctx, harness.server.URL, "/agent/result", payload, harness.credential)
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("submit host operation result: HTTP %d: %s", response.StatusCode, body)
		}
		return nil
	}
	runTool := func(name string, arguments map[string]any, operation string, execute func(jobTestLease) error) *mcp.CallToolResult {
		t.Helper()
		completed := make(chan jobCallOutcome, 1)
		go func() {
			result, err := harness.sessionA.CallTool(harness.ctx, &mcp.CallToolParams{Name: name, Arguments: arguments})
			completed <- jobCallOutcome{result: result, err: err}
		}()
		lease := waitForAgentJob(t, harness, 5*time.Second)
		if lease.Operation != operation {
			t.Fatalf("leased operation = %q, want %q", lease.Operation, operation)
		}
		if err := execute(lease); err != nil {
			t.Fatalf("execute %s host job: %v", name, err)
		}
		outcome := waitForMCPOutcome(t, completed, 5*time.Second)
		if outcome.err != nil {
			t.Fatalf("call %s: %v", name, outcome.err)
		}
		if outcome.result == nil {
			t.Fatalf("call %s returned no MCP result", name)
		}
		return outcome.result
	}

	listingResult := runTool("list_directory", map[string]any{"host_id": harness.hostID, "path": allowedRoot}, hostops.OperationListDirectory, func(job jobTestLease) error {
		var input hostops.PathInput
		if err := json.Unmarshal(job.Input, &input); err != nil {
			return fmt.Errorf("decode list-directory job input: %w", err)
		}
		if input.Path != allowedRoot {
			return fmt.Errorf("list-directory job path = %q, want %q", input.Path, allowedRoot)
		}
		return submitResult(job, hostops.DirectoryListing{
			Path: allowedRoot,
			Entries: []hostops.DirectoryEntry{{
				Name: "settings.conf", Path: insideFile, Type: "file", SizeBytes: int64(len("mode=safe\n")), Mode: "-rw-------", ModifiedAt: time.Now().UTC(),
			}},
		}, "")
	})
	if listingResult.IsError {
		t.Fatalf("list_directory returned MCP error: %v", listingResult.Content)
	}
	listingPayload, err := json.Marshal(listingResult.StructuredContent)
	if err != nil {
		t.Fatalf("marshal list_directory result: %v", err)
	}
	var listing struct {
		HostID  string                   `json:"host_id"`
		Listing hostops.DirectoryListing `json:"listing"`
	}
	if err := json.Unmarshal(listingPayload, &listing); err != nil {
		t.Fatalf("decode list_directory result: %v", err)
	}
	if listing.HostID != harness.hostID || len(listing.Listing.Entries) != 1 || listing.Listing.Entries[0].Name != "settings.conf" {
		t.Fatalf("list_directory result = %#v, want settings.conf from the enrolled host", listing)
	}

	fileResult := runTool("read_file", map[string]any{"host_id": harness.hostID, "path": insideFile}, hostops.OperationReadFile, func(job jobTestLease) error {
		var input hostops.PathInput
		if err := json.Unmarshal(job.Input, &input); err != nil {
			return fmt.Errorf("decode read-file job input: %w", err)
		}
		if input.Path != insideFile {
			return fmt.Errorf("read-file job path = %q, want %q", input.Path, insideFile)
		}
		return submitResult(job, hostops.FileReadResult{Path: insideFile, Content: "mode=safe\n", SizeBytes: int64(len("mode=safe\n"))}, "")
	})
	if fileResult.IsError {
		t.Fatalf("read_file returned MCP error: %v", fileResult.Content)
	}
	filePayload, err := json.Marshal(fileResult.StructuredContent)
	if err != nil {
		t.Fatalf("marshal read_file result: %v", err)
	}
	var file struct {
		HostID string                 `json:"host_id"`
		File   hostops.FileReadResult `json:"file"`
	}
	if err := json.Unmarshal(filePayload, &file); err != nil {
		t.Fatalf("decode read_file result: %v", err)
	}
	if file.HostID != harness.hostID || file.File.Content != "mode=safe\n" {
		t.Fatalf("read_file result = %#v, want the permitted file contents", file)
	}

	deniedResult := runTool("read_file", map[string]any{"host_id": harness.hostID, "path": outsideFile}, hostops.OperationReadFile, func(job jobTestLease) error {
		return submitResult(job, nil, "path is outside the configured allowed paths")
	})
	if !deniedResult.IsError {
		t.Fatalf("read_file outside the configured host boundary = %#v, want MCP tool error", deniedResult.StructuredContent)
	}

	packagesResult := runTool("search_packages", map[string]any{"host_id": harness.hostID, "query": "apt", "limit": 2}, hostops.OperationSearchPackages, func(job jobTestLease) error {
		var input hostops.PackageSearchInput
		if err := json.Unmarshal(job.Input, &input); err != nil {
			return fmt.Errorf("decode package-search job input: %w", err)
		}
		if input.Query != "apt" || input.Limit != 2 {
			return fmt.Errorf("package-search job input = %#v, want query apt and limit 2", input)
		}
		return submitResult(job, hostops.PackageSearchResult{Query: "apt", Packages: []hostops.PackageSearchEntry{{Name: "apt", Description: "command-line package manager"}}}, "")
	})
	if packagesResult.IsError {
		t.Fatalf("search_packages returned MCP error: %v", packagesResult.Content)
	}
	packagePayload, err := json.Marshal(packagesResult.StructuredContent)
	if err != nil {
		t.Fatalf("marshal search_packages result: %v", err)
	}
	var packages struct {
		HostID string                      `json:"host_id"`
		Search hostops.PackageSearchResult `json:"search"`
	}
	if err := json.Unmarshal(packagePayload, &packages); err != nil {
		t.Fatalf("decode search_packages result: %v", err)
	}
	if packages.HostID != harness.hostID || len(packages.Search.Packages) != 1 || packages.Search.Packages[0].Name != "apt" {
		t.Fatalf("search_packages result = %#v, want apt package from the enrolled host", packages)
	}

	deniedTenantResult, err := harness.sessionB.CallTool(harness.ctx, &mcp.CallToolParams{
		Name: "read_file", Arguments: map[string]any{"host_id": harness.hostID, "path": insideFile},
	})
	if err != nil || deniedTenantResult == nil || !deniedTenantResult.IsError {
		t.Fatalf("cross-tenant read_file result = %#v, error=%v; want an MCP tool error", deniedTenantResult, err)
	}
}

func TestHostJobInputsAndResultsAreEncryptedInPostgreSQL(t *testing.T) {
	harness := newJobTestHarness(t)
	var tenantID string
	if err := harness.service.store.pool.QueryRow(harness.ctx, "SELECT tenant_id::text FROM hosts WHERE id = $1::uuid", harness.hostID).Scan(&tenantID); err != nil {
		t.Fatalf("read host tenant: %v", err)
	}
	root := t.TempDir()
	path := filepath.Join(root, "secrets.conf")
	previousContent := "credential=old-sensitive-value\n"
	nextContent := "credential=new-sensitive-value\n"
	if err := os.WriteFile(path, []byte(previousContent), 0o600); err != nil {
		t.Fatalf("write prior file: %v", err)
	}
	input, err := json.Marshal(hostops.WriteFileInput{Path: path, Content: nextContent})
	if err != nil {
		t.Fatal(err)
	}
	target, jobID, err := harness.service.store.enqueueHostJob(harness.ctx, tenantID, harness.hostID, hostops.OperationWriteFile, input)
	if err != nil {
		t.Fatalf("enqueue file write: %v", err)
	}
	var storedInput []byte
	if err := harness.service.store.pool.QueryRow(harness.ctx, "SELECT input::text FROM jobs WHERE id = $1::uuid", jobID).Scan(&storedInput); err != nil {
		t.Fatalf("read stored input: %v", err)
	}
	if strings.Contains(string(storedInput), path) || strings.Contains(string(storedInput), nextContent) || !strings.Contains(string(storedInput), "ufm_encrypted_payload") {
		t.Fatalf("stored job input = %s, want authenticated ciphertext without path or content", storedInput)
	}
	lease, err := harness.service.store.claimNextHostJob(harness.ctx, harness.credential)
	if err != nil || lease == nil || lease.ID != jobID || lease.Operation != hostops.OperationWriteFile {
		t.Fatalf("claimed file job = %#v, error = %v", lease, err)
	}
	var decodedInput hostops.WriteFileInput
	if err := json.Unmarshal(lease.Input, &decodedInput); err != nil || decodedInput.Path != path || decodedInput.Content != nextContent {
		t.Fatalf("decrypted agent input = %#v, error = %v", decodedInput, err)
	}
	writeResult, err := hostops.WriteFile(path, decodedInput.Content, []string{root})
	if err != nil {
		t.Fatalf("execute file write: %v", err)
	}
	encodedResult, err := json.Marshal(writeResult)
	if err != nil {
		t.Fatal(err)
	}
	if err := harness.service.store.completeHostJob(harness.ctx, harness.credential, lease.ID, lease.LeaseToken, encodedResult, ""); err != nil {
		t.Fatalf("complete encrypted file job: %v", err)
	}
	var storedResult []byte
	if err := harness.service.store.pool.QueryRow(harness.ctx, "SELECT result::text FROM jobs WHERE id = $1::uuid", jobID).Scan(&storedResult); err != nil {
		t.Fatalf("read stored result: %v", err)
	}
	if strings.Contains(string(storedResult), path) || strings.Contains(string(storedResult), previousContent) || !strings.Contains(string(storedResult), "ufm_encrypted_payload") {
		t.Fatalf("stored job result = %s, want authenticated ciphertext without path or prior content", storedResult)
	}
	state, err := harness.service.store.hostJobState(harness.ctx, tenantID, target.HostID, jobID)
	if err != nil || string(state.Input) != string(input) || string(state.Result) != string(encodedResult) {
		t.Fatalf("decrypted completed state input=%s result=%s error=%v", state.Input, state.Result, err)
	}
	if cleared, err := harness.service.store.clearHostJobResult(harness.ctx, tenantID, target.HostID, jobID); err != nil || !cleared {
		t.Fatalf("clear delivered encrypted job payload: cleared=%v error=%v", cleared, err)
	}
	if err := harness.service.store.pool.QueryRow(harness.ctx, "SELECT input::text || COALESCE(result::text, '') FROM jobs WHERE id = $1::uuid", jobID).Scan(&storedInput); err != nil {
		t.Fatalf("read cleared job payload: %v", err)
	}
	if string(storedInput) != "{}" {
		t.Fatalf("cleared job payload = %s, want empty JSON object", storedInput)
	}
}

func TestFileWriteRollbackToolsRequirePolicyAndPersistEncryptedReversal(t *testing.T) {
	harness := newJobTestHarnessWithWrites(t, true)
	tools, err := harness.sessionA.ListTools(harness.ctx, nil)
	if err != nil {
		t.Fatalf("list authenticated tools: %v", err)
	}
	for _, name := range []string{"write_file", "rollback_file"} {
		found := false
		for _, tool := range tools.Tools {
			if tool.Name != name {
				continue
			}
			found = true
			if tool.Annotations == nil || tool.Annotations.ReadOnlyHint || tool.Annotations.DestructiveHint == nil || !*tool.Annotations.DestructiveHint || tool.Annotations.OpenWorldHint == nil || *tool.Annotations.OpenWorldHint {
				t.Errorf("tool %q annotations = %#v, want bounded, mutating, destructive behavior", name, tool.Annotations)
			}
			if name == "write_file" && tool.Annotations.IdempotentHint {
				t.Error("write_file is marked idempotent")
			}
			if name == "rollback_file" && !tool.Annotations.IdempotentHint {
				t.Error("rollback_file is not marked idempotent")
			}
		}
		if !found {
			t.Fatalf("enabled file mutation policy did not register %q", name)
		}
	}

	root := t.TempDir()
	path := filepath.Join(root, "service.conf")
	priorContent := []byte("token=prior-sensitive-value\n")
	newContent := "token=new-sensitive-value\n"
	if err := os.WriteFile(path, priorContent, 0o640); err != nil {
		t.Fatalf("write prior file: %v", err)
	}

	callAsync := func(name string, args map[string]any) <-chan jobCallOutcome {
		completed := make(chan jobCallOutcome, 1)
		go func() {
			result, err := harness.sessionA.CallTool(harness.ctx, &mcp.CallToolParams{Name: name, Arguments: args})
			completed <- jobCallOutcome{result: result, err: err}
		}()
		return completed
	}
	submitResult := func(job jobTestLease, result any) {
		t.Helper()
		response, body := postAgentJSON(t, harness.ctx, harness.server.URL, "/agent/result", map[string]any{
			"job_id": job.ID, "lease_token": job.LeaseToken, "result": result,
		}, harness.credential)
		if response.StatusCode != http.StatusOK {
			t.Fatalf("submit %s result: HTTP %d: %s", job.Operation, response.StatusCode, body)
		}
	}
	writeCall := callAsync("write_file", map[string]any{"host_id": harness.hostID, "path": path, "content": newContent})
	writeLease := waitForAgentJob(t, harness, 5*time.Second)
	if writeLease.Operation != hostops.OperationWriteFile {
		t.Fatalf("write lease operation = %q, want %s", writeLease.Operation, hostops.OperationWriteFile)
	}
	var writeInput hostops.WriteFileInput
	if err := json.Unmarshal(writeLease.Input, &writeInput); err != nil || writeInput.Path != path || writeInput.Content != newContent {
		t.Fatalf("write lease input = %#v, error = %v", writeInput, err)
	}
	writeResult, err := hostops.WriteFile(path, writeInput.Content, []string{root})
	if err != nil {
		t.Fatalf("simulate host file write: %v", err)
	}
	submitResult(writeLease, writeResult)
	writeOutcome := waitForMCPOutcome(t, writeCall, 5*time.Second)
	if writeOutcome.err != nil || writeOutcome.result == nil || writeOutcome.result.IsError {
		t.Fatalf("write_file result = %#v error=%v", writeOutcome.result, writeOutcome.err)
	}
	writePayload, err := json.Marshal(writeOutcome.result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var written mcpserver.HostFileWriteResult
	if err := json.Unmarshal(writePayload, &written); err != nil {
		t.Fatalf("decode write_file result: %v", err)
	}
	if written.ActionID != writeLease.ID || written.Path != path || written.Created || written.BytesWritten != len(newContent) || written.Mode != 0o640 || written.ExpiresAt.Before(time.Now().Add(6*24*time.Hour)) {
		t.Fatalf("write_file receipt = %#v, want encrypted reversal id, existing mode, and seven-day expiry", written)
	}
	var actionPayload []byte
	var actionStatus string
	if err := harness.service.store.pool.QueryRow(harness.ctx, "SELECT payload::text, status FROM file_actions WHERE id = $1::uuid", written.ActionID).Scan(&actionPayload, &actionStatus); err != nil {
		t.Fatalf("read encrypted file action: %v", err)
	}
	if strings.Contains(string(actionPayload), path) || strings.Contains(string(actionPayload), string(priorContent)) || !strings.Contains(string(actionPayload), "ufm_encrypted_payload") || actionStatus != "available" {
		t.Fatalf("stored file action payload=%s status=%s, want encrypted path/pre-state and available state", actionPayload, actionStatus)
	}
	var jobPayload []byte
	if err := harness.service.store.pool.QueryRow(harness.ctx, "SELECT input::text || COALESCE(result::text, '') FROM jobs WHERE id = $1::uuid", written.ActionID).Scan(&jobPayload); err != nil || string(jobPayload) != "{}" {
		t.Fatalf("consumed file job payload=%s error=%v, want immediately cleared sensitive input/result", jobPayload, err)
	}

	operatorContent := []byte("operator edited this after the managed write\n")
	if err := os.WriteFile(path, operatorContent, 0o640); err != nil {
		t.Fatalf("simulate later operator edit: %v", err)
	}
	conflictCall := callAsync("rollback_file", map[string]any{"host_id": harness.hostID, "action_id": written.ActionID})
	conflictLease := waitForAgentJob(t, harness, 5*time.Second)
	var conflictInput hostops.RestoreFileInput
	if err := json.Unmarshal(conflictLease.Input, &conflictInput); err != nil {
		t.Fatalf("decode conflict rollback input: %v", err)
	}
	conflictResult, err := hostops.RestoreFile(conflictInput, []string{root})
	if err != nil || conflictResult.Exact || !strings.Contains(conflictResult.Reason, "changed") {
		t.Fatalf("conflicting restore result = %#v error=%v, want exact-restore explanation", conflictResult, err)
	}
	submitResult(conflictLease, conflictResult)
	conflictOutcome := waitForMCPOutcome(t, conflictCall, 5*time.Second)
	if conflictOutcome.err != nil || conflictOutcome.result == nil || conflictOutcome.result.IsError {
		t.Fatalf("conflicting rollback result = %#v error=%v", conflictOutcome.result, conflictOutcome.err)
	}
	preservedContent, err := os.ReadFile(path)
	if err != nil || string(preservedContent) != string(operatorContent) {
		t.Fatalf("file after refused rollback = %q error=%v, want later operator content preserved", preservedContent, err)
	}
	if err := harness.service.store.pool.QueryRow(harness.ctx, "SELECT status FROM file_actions WHERE id = $1::uuid", written.ActionID).Scan(&actionStatus); err != nil || actionStatus != "available" {
		t.Fatalf("file action after refused rollback = %q error=%v, want available for retry", actionStatus, err)
	}
	if err := os.WriteFile(path, []byte(newContent), 0o640); err != nil {
		t.Fatalf("restore expected managed contents for successful rollback case: %v", err)
	}

	rollbackCall := callAsync("rollback_file", map[string]any{"host_id": harness.hostID, "action_id": written.ActionID})
	restoreLease := waitForAgentJob(t, harness, 5*time.Second)
	if restoreLease.Operation != hostops.OperationRestoreFile {
		t.Fatalf("rollback lease operation = %q, want %s", restoreLease.Operation, hostops.OperationRestoreFile)
	}
	var restoreInput hostops.RestoreFileInput
	if err := json.Unmarshal(restoreLease.Input, &restoreInput); err != nil || restoreInput.Path != path || string(restoreInput.Previous.Content) != string(priorContent) || restoreInput.Previous.Mode != 0o640 {
		t.Fatalf("rollback job input = %#v, error = %v", restoreInput, err)
	}
	restoreResult, err := hostops.RestoreFile(restoreInput, []string{root})
	if err != nil {
		t.Fatalf("simulate host rollback: %v", err)
	}
	submitResult(restoreLease, restoreResult)
	rollbackOutcome := waitForMCPOutcome(t, rollbackCall, 5*time.Second)
	if rollbackOutcome.err != nil || rollbackOutcome.result == nil || rollbackOutcome.result.IsError {
		t.Fatalf("rollback_file result = %#v error=%v", rollbackOutcome.result, rollbackOutcome.err)
	}
	rollbackPayload, err := json.Marshal(rollbackOutcome.result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var rollback mcpserver.HostFileRollbackResult
	if err := json.Unmarshal(rollbackPayload, &rollback); err != nil || !rollback.Exact || !rollback.Restored || rollback.AlreadyRestored {
		t.Fatalf("rollback_file result = %#v, decode error=%v", rollback, err)
	}
	content, err := os.ReadFile(path)
	info, statErr := os.Stat(path)
	if err != nil || statErr != nil || string(content) != string(priorContent) || info.Mode().Perm() != 0o640 {
		t.Fatalf("restored file=%q mode=%v read=%v stat=%v", content, info, err, statErr)
	}
	if err := harness.service.store.pool.QueryRow(harness.ctx, "SELECT status FROM file_actions WHERE id = $1::uuid", written.ActionID).Scan(&actionStatus); err != nil || actionStatus != "rolled_back" {
		t.Fatalf("file action status = %q error=%v, want rolled_back", actionStatus, err)
	}

	repeated, err := harness.sessionA.CallTool(harness.ctx, &mcp.CallToolParams{
		Name: "rollback_file", Arguments: map[string]any{"host_id": harness.hostID, "action_id": written.ActionID},
	})
	if err != nil || repeated == nil || repeated.IsError {
		t.Fatalf("repeat rollback result=%#v error=%v", repeated, err)
	}
	repeatedPayload, err := json.Marshal(repeated.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var repeatedResult mcpserver.HostFileRollbackResult
	if err := json.Unmarshal(repeatedPayload, &repeatedResult); err != nil || !repeatedResult.AlreadyRestored {
		t.Fatalf("repeat rollback result=%#v error=%v, want already_restored", repeatedResult, err)
	}
	crossTenant, err := harness.sessionB.CallTool(harness.ctx, &mcp.CallToolParams{
		Name: "rollback_file", Arguments: map[string]any{"host_id": harness.hostID, "action_id": written.ActionID},
	})
	if err != nil || crossTenant == nil || !crossTenant.IsError {
		t.Fatalf("cross-tenant rollback result=%#v error=%v, want an MCP error", crossTenant, err)
	}
}

func TestAPTToolsRequireServerPolicyExposeConfirmationHintsAndPersistRollback(t *testing.T) {
	defaultHarness := newJobTestHarness(t)
	defaultTools, err := defaultHarness.sessionA.ListTools(defaultHarness.ctx, nil)
	if err != nil {
		t.Fatalf("list tools under default APT policy: %v", err)
	}
	for _, name := range []string{"apt_update", "apt_install", "apt_remove", "apt_upgrade", "rollback_apt_action"} {
		if hasTool(defaultTools.Tools, name) {
			t.Errorf("APT tool %q is registered while ALLOW_APT_WRITES is false", name)
		}
	}

	harness := newJobTestHarnessWithPolicies(t, false, true)
	tools, err := harness.sessionA.ListTools(harness.ctx, nil)
	if err != nil {
		t.Fatalf("list tools under enabled APT policy: %v", err)
	}
	for _, name := range []string{"apt_update", "apt_install", "apt_remove", "apt_upgrade", "rollback_apt_action"} {
		var matched *mcp.Tool
		for _, candidate := range tools.Tools {
			if candidate.Name == name {
				matched = candidate
				break
			}
		}
		if matched == nil {
			t.Fatalf("APT tool %q was not registered when ALLOW_APT_WRITES is true; tools=%v", name, toolNames(tools.Tools))
		}
		if matched.Annotations == nil || matched.Annotations.ReadOnlyHint || matched.Annotations.DestructiveHint == nil || !*matched.Annotations.DestructiveHint || matched.Annotations.OpenWorldHint == nil || !*matched.Annotations.OpenWorldHint {
			t.Errorf("APT tool %q annotations = %#v, want mutating, destructive, open-world behavior", name, matched.Annotations)
		}
		if !strings.Contains(matched.Description, "per-call human confirmation") {
			t.Errorf("APT tool %q description does not require per-call HTTP confirmation: %q", name, matched.Description)
		}
	}

	completed := make(chan jobCallOutcome, 1)
	go func() {
		result, err := harness.sessionA.CallTool(harness.ctx, &mcp.CallToolParams{
			Name: "apt_install", Arguments: map[string]any{"host_id": harness.hostID, "packages": []string{"curl"}},
		})
		completed <- jobCallOutcome{result: result, err: err}
	}()
	installLease := waitForAgentJob(t, harness, 5*time.Second)
	if installLease.Operation != hostops.OperationAPTInstall {
		t.Fatalf("install job operation = %q, want %q", installLease.Operation, hostops.OperationAPTInstall)
	}
	var installInput hostops.APTActionInput
	if err := json.Unmarshal(installLease.Input, &installInput); err != nil || len(installInput.Packages) != 1 || installInput.Packages[0] != "curl" {
		t.Fatalf("typed install job input = %#v, error=%v", installInput, err)
	}
	installResult := hostops.APTActionResult{
		Operation: hostops.OperationAPTInstall,
		Before:    []hostops.PackageState{{Name: "curl"}},
		After:     []hostops.PackageState{{Name: "curl", Installed: true, Version: "2.0"}},
		Outcome:   hostops.APTOutcomeSucceeded, RollbackAvailable: true,
	}
	response, responseBody := postAgentJSON(t, harness.ctx, harness.server.URL, "/agent/result", map[string]any{
		"job_id": installLease.ID, "lease_token": installLease.LeaseToken, "result": installResult,
	}, harness.credential)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("submit typed install result: HTTP %d: %s", response.StatusCode, responseBody)
	}
	installOutcome := waitForMCPOutcome(t, completed, 5*time.Second)
	if installOutcome.err != nil || installOutcome.result == nil || installOutcome.result.IsError {
		t.Fatalf("apt_install outcome = %#v, error=%v", installOutcome.result, installOutcome.err)
	}
	installPayload, err := json.Marshal(installOutcome.result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var installReceipt mcpserver.HostAPTActionResult
	if err := json.Unmarshal(installPayload, &installReceipt); err != nil {
		t.Fatalf("decode apt_install receipt: %v", err)
	}
	if installReceipt.ActionID != installLease.ID || installReceipt.ChangedPackages != 1 || !installReceipt.RollbackAvailable || installReceipt.ExpiresAt.Before(time.Now().Add(6*24*time.Hour)) {
		t.Fatalf("apt_install receipt = %#v", installReceipt)
	}
	var sealedPayload []byte
	var actionStatus string
	if err := harness.service.store.pool.QueryRow(harness.ctx, "SELECT payload::text, status FROM package_actions WHERE id = $1::uuid", installReceipt.ActionID).Scan(&sealedPayload, &actionStatus); err != nil {
		t.Fatalf("read encrypted APT action record: %v", err)
	}
	if strings.Contains(string(sealedPayload), "curl") || strings.Contains(string(sealedPayload), "2.0") || !strings.Contains(string(sealedPayload), "ufm_encrypted_payload") || actionStatus != "available" {
		t.Fatalf("stored APT audit payload=%s status=%s, want encrypted pre-state and available status", sealedPayload, actionStatus)
	}
	var consumedJobPayload []byte
	if err := harness.service.store.pool.QueryRow(harness.ctx, "SELECT input::text || COALESCE(result::text, '') FROM jobs WHERE id = $1::uuid", installReceipt.ActionID).Scan(&consumedJobPayload); err != nil || string(consumedJobPayload) != "{}" {
		t.Fatalf("consumed APT job data=%s error=%v, want cleared input and result", consumedJobPayload, err)
	}

	rollbackDone := make(chan jobCallOutcome, 1)
	go func() {
		result, err := harness.sessionA.CallTool(harness.ctx, &mcp.CallToolParams{
			Name: "rollback_apt_action", Arguments: map[string]any{"host_id": harness.hostID, "action_id": installReceipt.ActionID},
		})
		rollbackDone <- jobCallOutcome{result: result, err: err}
	}()
	rollbackLease := waitForAgentJob(t, harness, 5*time.Second)
	if rollbackLease.Operation != hostops.OperationAPTRollback {
		t.Fatalf("rollback job operation = %q, want %q", rollbackLease.Operation, hostops.OperationAPTRollback)
	}
	var rollbackInput hostops.APTRollbackInput
	if err := json.Unmarshal(rollbackLease.Input, &rollbackInput); err != nil || len(rollbackInput.Previous) != 1 || len(rollbackInput.ExpectedCurrent) != 1 || rollbackInput.Previous[0].Installed || rollbackInput.ExpectedCurrent[0].Version != "2.0" {
		t.Fatalf("typed APT rollback input = %#v, error=%v", rollbackInput, err)
	}
	rollbackJobResult := hostops.APTRollbackResult{
		Outcome:  hostops.APTOutcomeSucceeded,
		Packages: []hostops.APTPackageRollbackResult{{Name: "curl", Restored: true, Exact: true}},
	}
	response, responseBody = postAgentJSON(t, harness.ctx, harness.server.URL, "/agent/result", map[string]any{
		"job_id": rollbackLease.ID, "lease_token": rollbackLease.LeaseToken, "result": rollbackJobResult,
	}, harness.credential)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("submit typed rollback result: HTTP %d: %s", response.StatusCode, responseBody)
	}
	rollbackOutcome := waitForMCPOutcome(t, rollbackDone, 5*time.Second)
	if rollbackOutcome.err != nil || rollbackOutcome.result == nil || rollbackOutcome.result.IsError {
		t.Fatalf("rollback_apt_action outcome = %#v, error=%v", rollbackOutcome.result, rollbackOutcome.err)
	}
	rollbackPayload, err := json.Marshal(rollbackOutcome.result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var rollbackReceipt mcpserver.HostAPTRollbackResult
	if err := json.Unmarshal(rollbackPayload, &rollbackReceipt); err != nil || !rollbackReceipt.Exact || rollbackReceipt.RestoredPackages != 1 || rollbackReceipt.AlreadyRestored {
		t.Fatalf("rollback_apt_action receipt = %#v, decode error=%v", rollbackReceipt, err)
	}
	if err := harness.service.store.pool.QueryRow(harness.ctx, "SELECT status FROM package_actions WHERE id = $1::uuid", installReceipt.ActionID).Scan(&actionStatus); err != nil || actionStatus != "rolled_back" {
		t.Fatalf("APT action status after rollback = %q, error=%v; want rolled_back", actionStatus, err)
	}
	repeated, err := harness.sessionA.CallTool(harness.ctx, &mcp.CallToolParams{
		Name: "rollback_apt_action", Arguments: map[string]any{"host_id": harness.hostID, "action_id": installReceipt.ActionID},
	})
	if err != nil || repeated == nil || repeated.IsError {
		t.Fatalf("repeat APT rollback result=%#v error=%v", repeated, err)
	}
	repeatedPayload, err := json.Marshal(repeated.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var repeatedReceipt mcpserver.HostAPTRollbackResult
	if err := json.Unmarshal(repeatedPayload, &repeatedReceipt); err != nil || !repeatedReceipt.AlreadyRestored || !repeatedReceipt.Exact {
		t.Fatalf("repeat APT rollback receipt = %#v, decode error=%v", repeatedReceipt, err)
	}
}

func TestExecuteCommandToolRequiresServerPolicyAndReturnsTypedResult(t *testing.T) {
	defaultHarness := newJobTestHarness(t)
	defaultTools, err := defaultHarness.sessionA.ListTools(defaultHarness.ctx, nil)
	if err != nil {
		t.Fatalf("list tools under default command policy: %v", err)
	}
	if hasTool(defaultTools.Tools, "execute_command") {
		t.Fatal("execute_command is registered while ALLOW_COMMAND_EXECUTION is false")
	}

	harness := newJobTestHarnessWithPolicies(t, false, false, true)
	tools, err := harness.sessionA.ListTools(harness.ctx, nil)
	if err != nil {
		t.Fatalf("list tools under enabled command policy: %v", err)
	}
	var commandTool *mcp.Tool
	for _, candidate := range tools.Tools {
		if candidate.Name == "execute_command" {
			commandTool = candidate
			break
		}
	}
	if commandTool == nil {
		t.Fatalf("execute_command was not registered when command policy is enabled; tools=%v", toolNames(tools.Tools))
	}
	if commandTool.Annotations == nil || commandTool.Annotations.ReadOnlyHint || commandTool.Annotations.DestructiveHint == nil || !*commandTool.Annotations.DestructiveHint || commandTool.Annotations.IdempotentHint || commandTool.Annotations.OpenWorldHint == nil || !*commandTool.Annotations.OpenWorldHint {
		t.Fatalf("execute_command annotations=%#v; want destructive, non-idempotent, open-world behavior", commandTool.Annotations)
	}
	if !strings.Contains(commandTool.Description, "no rollback") || !strings.Contains(commandTool.Description, "per-call human confirmation") {
		t.Fatalf("execute_command description lacks reversal limit or confirmation requirement: %q", commandTool.Description)
	}

	completed := make(chan jobCallOutcome, 1)
	go func() {
		result, err := harness.sessionA.CallTool(harness.ctx, &mcp.CallToolParams{
			Name: "execute_command",
			Arguments: map[string]any{
				"host_id": harness.hostID, "executable": "/usr/bin/df", "args": []string{"-h", "/"},
				"working_directory": "/var/tmp",
			},
		})
		completed <- jobCallOutcome{result: result, err: err}
	}()
	lease := waitForAgentJobOrMCPError(t, harness, completed, 5*time.Second)
	if lease.Operation != hostops.OperationExecuteCommand {
		t.Fatalf("command job operation=%q, want %q", lease.Operation, hostops.OperationExecuteCommand)
	}
	var input hostops.CommandInput
	if err := json.Unmarshal(lease.Input, &input); err != nil || input.Executable != "/usr/bin/df" || !reflect.DeepEqual(input.Arguments, []string{"-h", "/"}) || input.WorkingDirectory != "/var/tmp" {
		t.Fatalf("typed command job input=%#v, error=%v", input, err)
	}
	commandResult := hostops.CommandResult{ExitCode: 0, Stdout: "filesystem report\npassword=[REDACTED]\n"}
	response, responseBody := postAgentJSON(t, harness.ctx, harness.server.URL, "/agent/result", map[string]any{
		"job_id": lease.ID, "lease_token": lease.LeaseToken, "result": commandResult,
	}, harness.credential)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("submit command result: HTTP %d: %s", response.StatusCode, responseBody)
	}
	outcome := waitForMCPOutcome(t, completed, 5*time.Second)
	if outcome.err != nil || outcome.result == nil || outcome.result.IsError {
		t.Fatalf("execute_command result=%#v error=%v", outcome.result, outcome.err)
	}
	encoded, err := json.Marshal(outcome.result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var receipt mcpserver.HostCommandResult
	if err := json.Unmarshal(encoded, &receipt); err != nil || receipt.ExitCode != 0 || receipt.Stdout != commandResult.Stdout || receipt.HostID != harness.hostID || receipt.OutputTruncated {
		t.Fatalf("execute_command receipt=%#v decode error=%v", receipt, err)
	}
}

func TestRetentionCleanupDeletesExpiredReversalAndJobRecords(t *testing.T) {
	harness := newJobTestHarness(t)
	var tenantID string
	if err := harness.service.store.pool.QueryRow(harness.ctx, "SELECT tenant_id::text FROM hosts WHERE id = $1::uuid", harness.hostID).Scan(&tenantID); err != nil {
		t.Fatalf("read host tenant: %v", err)
	}
	now := time.Now().UTC()
	expiredID := uuid.New()
	payload, err := json.Marshal(fileActionPayload{
		Path:            filepath.Join(t.TempDir(), "secret.conf"),
		Previous:        hostops.FileState{Existed: true, Content: []byte("old-sensitive-data"), Mode: 0o600},
		ExpectedCurrent: hostops.FileFingerprint{Existed: true, SHA256: strings.Repeat("a", 64), Mode: 0o600},
	})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := harness.service.store.cipher.Seal(payload, fileActionAssociatedData(tenantID, harness.hostID, expiredID.String()))
	if err != nil {
		t.Fatalf("encrypt expired action fixture: %v", err)
	}
	if _, err := harness.service.store.pool.Exec(harness.ctx, `
		INSERT INTO file_actions (id, tenant_id, host_id, payload, status, created_at, expires_at)
		VALUES ($1, $2::uuid, $3::uuid, $4::jsonb, 'available', $5::timestamptz - interval '8 days', $5::timestamptz - interval '1 day')
	`, expiredID, tenantID, harness.hostID, sealed, now); err != nil {
		t.Fatalf("insert expired file action: %v", err)
	}
	var expiredJobID string
	if err := harness.service.store.pool.QueryRow(harness.ctx, `
		INSERT INTO jobs (tenant_id, host_id, operation, status, requested_at, input)
		VALUES ($1::uuid, $2::uuid, $3, 'completed', $4::timestamptz - interval '8 days', '{}'::jsonb)
		RETURNING id::text
	`, tenantID, harness.hostID, hostops.OperationGetSystemInfo, now).Scan(&expiredJobID); err != nil {
		t.Fatalf("insert expired job fixture: %v", err)
	}
	staleID := uuid.New()
	stalePayload, err := harness.service.store.cipher.Seal(payload, fileActionAssociatedData(tenantID, harness.hostID, staleID.String()))
	if err != nil {
		t.Fatalf("encrypt stale action fixture: %v", err)
	}
	if _, err := harness.service.store.pool.Exec(harness.ctx, `
		INSERT INTO file_actions (id, tenant_id, host_id, payload, status, created_at, expires_at, rollback_started_at)
		VALUES ($1, $2::uuid, $3::uuid, $4::jsonb, 'rolling_back', $5::timestamptz - interval '1 day', $5::timestamptz + interval '6 days', $5::timestamptz - interval '10 minutes')
	`, staleID, tenantID, harness.hostID, stalePayload, now); err != nil {
		t.Fatalf("insert stale rollback fixture: %v", err)
	}
	expiredAPTID := uuid.New()
	aptPayload, err := json.Marshal(aptActionPayload{
		Operation: hostops.OperationAPTInstall, RequestedPackages: []string{"curl"},
		Previous: []hostops.PackageState{{Name: "curl"}}, ExpectedCurrent: []hostops.PackageState{{Name: "curl", Installed: true, Version: "1.0"}},
		Outcome: hostops.APTOutcomeSucceeded, RollbackAvailable: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	expiredAPTSealed, err := harness.service.store.cipher.Seal(aptPayload, aptActionAssociatedData(tenantID, harness.hostID, expiredAPTID.String()))
	if err != nil {
		t.Fatalf("encrypt expired APT action fixture: %v", err)
	}
	if _, err := harness.service.store.pool.Exec(harness.ctx, `
		INSERT INTO package_actions (id, tenant_id, host_id, payload, status, created_at, expires_at)
		VALUES ($1, $2::uuid, $3::uuid, $4::jsonb, 'available', $5::timestamptz - interval '8 days', $5::timestamptz - interval '1 day')
	`, expiredAPTID, tenantID, harness.hostID, expiredAPTSealed, now); err != nil {
		t.Fatalf("insert expired APT action fixture: %v", err)
	}
	staleAPTID := uuid.New()
	staleAPTSealed, err := harness.service.store.cipher.Seal(aptPayload, aptActionAssociatedData(tenantID, harness.hostID, staleAPTID.String()))
	if err != nil {
		t.Fatalf("encrypt stale APT action fixture: %v", err)
	}
	if _, err := harness.service.store.pool.Exec(harness.ctx, `
		INSERT INTO package_actions (id, tenant_id, host_id, payload, status, created_at, expires_at, rollback_started_at)
		VALUES ($1, $2::uuid, $3::uuid, $4::jsonb, 'rolling_back', $5::timestamptz - interval '1 day', $5::timestamptz + interval '6 days', $5::timestamptz - interval '10 minutes')
	`, staleAPTID, tenantID, harness.hostID, staleAPTSealed, now); err != nil {
		t.Fatalf("insert stale APT rollback fixture: %v", err)
	}
	deleted, err := harness.service.store.cleanupExpiredApplicationData(harness.ctx, now)
	if err != nil || deleted < 3 {
		t.Fatalf("retention cleanup deleted %d rows, error=%v, want expired file action, APT action, and job", deleted, err)
	}
	var actionCount, aptActionCount, jobCount int
	if err := harness.service.store.pool.QueryRow(harness.ctx, "SELECT count(*) FROM file_actions WHERE id = $1::uuid", expiredID).Scan(&actionCount); err != nil {
		t.Fatal(err)
	}
	if err := harness.service.store.pool.QueryRow(harness.ctx, "SELECT count(*) FROM jobs WHERE id = $1::uuid", expiredJobID).Scan(&jobCount); err != nil {
		t.Fatal(err)
	}
	if err := harness.service.store.pool.QueryRow(harness.ctx, "SELECT count(*) FROM package_actions WHERE id = $1::uuid", expiredAPTID).Scan(&aptActionCount); err != nil {
		t.Fatal(err)
	}
	if actionCount != 0 || aptActionCount != 0 || jobCount != 0 {
		t.Fatalf("expired active-store rows remain: file_actions=%d package_actions=%d jobs=%d", actionCount, aptActionCount, jobCount)
	}
	var staleStatus string
	if err := harness.service.store.pool.QueryRow(harness.ctx, "SELECT status FROM file_actions WHERE id = $1::uuid", staleID).Scan(&staleStatus); err != nil || staleStatus != "available" {
		t.Fatalf("stale rollback status = %q error=%v, want available", staleStatus, err)
	}
	if err := harness.service.store.pool.QueryRow(harness.ctx, "SELECT status FROM package_actions WHERE id = $1::uuid", staleAPTID).Scan(&staleStatus); err != nil || staleStatus != "available" {
		t.Fatalf("stale APT rollback status = %q error=%v, want available", staleStatus, err)
	}
}

func TestOnlyTargetHostCredentialCanLeaseAndCompleteSystemInfoJob(t *testing.T) {
	harness := newJobTestHarness(t)
	codeResult, err := harness.sessionA.CallTool(harness.ctx, &mcp.CallToolParams{
		Name:      "create_pairing_code",
		Arguments: map[string]any{},
	})
	if err != nil || codeResult.IsError {
		t.Fatalf("create second host pairing code: result=%#v error=%v", codeResult, err)
	}
	codePayload, err := json.Marshal(codeResult.StructuredContent)
	if err != nil {
		t.Fatalf("marshal second host pairing code: %v", err)
	}
	var code struct {
		Value string `json:"pairing_code"`
	}
	if err := json.Unmarshal(codePayload, &code); err != nil || code.Value == "" {
		t.Fatalf("decode second host pairing code: payload=%s error=%v", codePayload, err)
	}
	response, body := postAgentJSON(t, harness.ctx, harness.server.URL, "/agent/enroll", map[string]any{
		"pairing_code": code.Value, "hostname": "other-host.example.test", "os_pretty_name": "Ubuntu 26.04 LTS",
	}, "")
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("enroll second host status = %d: %s", response.StatusCode, body)
	}
	var otherHost struct {
		Credential string `json:"credential"`
	}
	if err := json.Unmarshal(body, &otherHost); err != nil || otherHost.Credential == "" {
		t.Fatalf("decode second host credential: body=%s error=%v", body, err)
	}

	completed := make(chan jobCallOutcome, 1)
	go func() {
		result, err := harness.sessionA.CallTool(harness.ctx, &mcp.CallToolParams{
			Name:      "get_host_system_info",
			Arguments: map[string]any{"host_id": harness.hostID},
		})
		completed <- jobCallOutcome{result: result, err: err}
	}()
	lease := waitForAgentJob(t, harness, 5*time.Second)

	otherPoll, otherPollBody := postAgentJSON(t, harness.ctx, harness.server.URL, "/agent/poll", map[string]any{}, otherHost.Credential)
	if otherPoll.StatusCode != http.StatusOK {
		t.Fatalf("other host poll status = %d: %s", otherPoll.StatusCode, otherPollBody)
	}
	var otherPollResult struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(otherPollBody, &otherPollResult); err != nil || otherPollResult.Status != "idle" {
		t.Fatalf("other host poll result = %s, error=%v; want idle", otherPollBody, err)
	}

	wrongHost, wrongHostBody := postAgentJSON(t, harness.ctx, harness.server.URL, "/agent/result", map[string]any{
		"job_id": lease.ID, "lease_token": lease.LeaseToken, "result": sampleSystemInfo("wrong-host-result"),
	}, otherHost.Credential)
	if wrongHost.StatusCode != http.StatusConflict {
		t.Fatalf("other host result status = %d, want 409: %s", wrongHost.StatusCode, wrongHostBody)
	}

	validResult, validResultBody := postAgentJSON(t, harness.ctx, harness.server.URL, "/agent/result", map[string]any{
		"job_id": lease.ID, "lease_token": lease.LeaseToken, "result": sampleSystemInfo("target-host-result"),
	}, harness.credential)
	if validResult.StatusCode != http.StatusOK {
		t.Fatalf("target host result status = %d, want 200: %s", validResult.StatusCode, validResultBody)
	}
	outcome := waitForMCPOutcome(t, completed, 5*time.Second)
	if outcome.err != nil || outcome.result == nil || outcome.result.IsError {
		t.Fatalf("target host system-info result = %#v, error=%v", outcome.result, outcome.err)
	}
}

func TestHostSystemInfoRejectsOtherTenantAndCancelsOfflineRequest(t *testing.T) {
	harness := newJobTestHarness(t)
	for _, test := range []struct {
		name    string
		session *mcp.ClientSession
		hostID  string
	}{
		{name: "cross tenant", session: harness.sessionB, hostID: harness.hostID},
		{name: "invalid host", session: harness.sessionA, hostID: "not-a-host-id"},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := test.session.CallTool(harness.ctx, &mcp.CallToolParams{
				Name:      "get_host_system_info",
				Arguments: map[string]any{"host_id": test.hostID},
			})
			if err != nil {
				t.Fatalf("call get_host_system_info: %v", err)
			}
			if !result.IsError {
				t.Fatalf("unauthorized target result = %#v, want MCP tool error", result.StructuredContent)
			}
		})
	}

	offlineCtx, cancel := context.WithTimeout(harness.ctx, 250*time.Millisecond)
	defer cancel()
	result, err := harness.sessionA.CallTool(offlineCtx, &mcp.CallToolParams{
		Name:      "get_host_system_info",
		Arguments: map[string]any{"host_id": harness.hostID},
	})
	if err == nil && (result == nil || !result.IsError) {
		t.Fatal("offline host request did not return a timeout or tool error")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var status string
		queryCtx, queryCancel := context.WithTimeout(context.Background(), time.Second)
		queryErr := harness.service.store.pool.QueryRow(queryCtx, `
			SELECT status FROM jobs WHERE host_id = $1::uuid ORDER BY requested_at DESC LIMIT 1
		`, harness.hostID).Scan(&status)
		queryCancel()
		if queryErr == nil && status == "cancelled" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("offline host request did not cancel its pending job")
}

func TestRemovingHostCancelsOutstandingSystemInfoJob(t *testing.T) {
	harness := newJobTestHarness(t)
	completed := make(chan jobCallOutcome, 1)
	go func() {
		result, err := harness.sessionA.CallTool(harness.ctx, &mcp.CallToolParams{
			Name:      "get_host_system_info",
			Arguments: map[string]any{"host_id": harness.hostID},
		})
		completed <- jobCallOutcome{result: result, err: err}
	}()

	lease := waitForAgentJob(t, harness, 5*time.Second)
	removed, err := harness.sessionA.CallTool(harness.ctx, &mcp.CallToolParams{
		Name:      "remove_host",
		Arguments: map[string]any{"host_id": harness.hostID},
	})
	if err != nil || removed == nil || removed.IsError {
		t.Fatalf("remove host with active job: result=%#v error=%v", removed, err)
	}
	outcome := waitForMCPOutcome(t, completed, 5*time.Second)
	if outcome.err == nil && (outcome.result == nil || !outcome.result.IsError) {
		t.Fatalf("outstanding system-info request after host removal = %#v, want an MCP error", outcome.result)
	}
	var status string
	if err := harness.service.store.pool.QueryRow(harness.ctx, "SELECT status FROM jobs WHERE id = $1::uuid", lease.ID).Scan(&status); err != nil {
		t.Fatalf("read removed host job status: %v", err)
	}
	if status != "cancelled" {
		t.Fatalf("removed host job status = %q, want cancelled", status)
	}
	pollResponse, pollBody := postAgentJSON(t, harness.ctx, harness.server.URL, "/agent/poll", map[string]any{}, harness.credential)
	if pollResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("removed host poll status = %d, want 401: %s", pollResponse.StatusCode, pollBody)
	}
}

func TestExpiredSystemInfoLeaseCanBeReclaimedWhileRequestIsActive(t *testing.T) {
	harness := newJobTestHarness(t)
	requestCtx, cancelRequest := context.WithCancel(harness.ctx)
	defer cancelRequest()
	completed := make(chan jobCallOutcome, 1)
	go func() {
		result, err := harness.sessionA.CallTool(requestCtx, &mcp.CallToolParams{
			Name:      "get_host_system_info",
			Arguments: map[string]any{"host_id": harness.hostID},
		})
		completed <- jobCallOutcome{result: result, err: err}
	}()

	lease := waitForAgentJob(t, harness, 5*time.Second)
	if lease.Attempt != 1 {
		t.Fatalf("first lease attempt = %d, want 1", lease.Attempt)
	}
	jobID := lease.ID
	for wantAttempt := 2; wantAttempt <= 4; wantAttempt++ {
		previous := lease
		expireSystemInfoLease(t, harness, previous.ID)
		lease = waitForAgentJob(t, harness, 5*time.Second)
		if lease.ID != jobID || lease.Attempt != wantAttempt || lease.LeaseToken == previous.LeaseToken {
			t.Fatalf("reclaimed lease = %#v, want job %s attempt %d with a fresh token", lease, jobID, wantAttempt)
		}
		staleResponse, staleBody := postAgentJSON(t, harness.ctx, harness.server.URL, "/agent/result", map[string]any{
			"job_id": previous.ID, "lease_token": previous.LeaseToken, "result": sampleSystemInfo("stale-result"),
		}, harness.credential)
		if staleResponse.StatusCode != http.StatusConflict {
			t.Fatalf("stale lease attempt %d status = %d, want 409: %s", previous.Attempt, staleResponse.StatusCode, staleBody)
		}
	}

	cancelRequest()
	outcome := waitForMCPOutcome(t, completed, 5*time.Second)
	if outcome.err == nil && (outcome.result == nil || !outcome.result.IsError) {
		t.Fatalf("cancelled system-info request = %#v, want an error", outcome.result)
	}
	deadline := time.Now().Add(time.Second)
	for {
		queryCtx, cancelQuery := context.WithTimeout(context.Background(), time.Second)
		var status string
		err := harness.service.store.pool.QueryRow(queryCtx, "SELECT status FROM jobs WHERE id = $1::uuid", jobID).Scan(&status)
		cancelQuery()
		if err != nil {
			t.Fatalf("read cancelled system-info job status: %v", err)
		}
		if status == "cancelled" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("system-info job status after caller cancellation = %q, want cancelled", status)
		}
		time.Sleep(20 * time.Millisecond)
	}

	lateResponse, lateBody := postAgentJSON(t, harness.ctx, harness.server.URL, "/agent/result", map[string]any{
		"job_id": lease.ID, "lease_token": lease.LeaseToken, "result": sampleSystemInfo("late-result"),
	}, harness.credential)
	if lateResponse.StatusCode != http.StatusConflict {
		t.Fatalf("late result after cancellation status = %d, want 409: %s", lateResponse.StatusCode, lateBody)
	}
	idleResponse, idleBody := postAgentJSON(t, harness.ctx, harness.server.URL, "/agent/poll", map[string]any{}, harness.credential)
	if idleResponse.StatusCode != http.StatusOK {
		t.Fatalf("poll after request cancellation status = %d: %s", idleResponse.StatusCode, idleBody)
	}
	var poll struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(idleBody, &poll); err != nil {
		t.Fatalf("decode poll after request cancellation: %v", err)
	}
	if poll.Status != "idle" {
		t.Fatalf("poll status after request cancellation = %q, want idle", poll.Status)
	}
}

func TestAgentReportedSystemInfoFailureEndsMCPRequestWithError(t *testing.T) {
	harness := newJobTestHarness(t)
	completed := make(chan jobCallOutcome, 1)
	go func() {
		result, err := harness.sessionA.CallTool(harness.ctx, &mcp.CallToolParams{
			Name:      "get_host_system_info",
			Arguments: map[string]any{"host_id": harness.hostID},
		})
		completed <- jobCallOutcome{result: result, err: err}
	}()

	lease := waitForAgentJob(t, harness, 5*time.Second)
	response, body := postAgentJSON(t, harness.ctx, harness.server.URL, "/agent/result", map[string]any{
		"job_id": lease.ID, "lease_token": lease.LeaseToken, "error": "system-info collection failed",
	}, harness.credential)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("submit agent failure status = %d, want 200: %s", response.StatusCode, body)
	}
	outcome := waitForMCPOutcome(t, completed, 5*time.Second)
	if outcome.err == nil && (outcome.result == nil || !outcome.result.IsError) {
		t.Fatalf("MCP result for agent-reported failure = %#v, want an error", outcome.result)
	}
}

func expireSystemInfoLease(t *testing.T, harness *jobTestHarness, jobID string) {
	t.Helper()
	if _, err := harness.service.store.pool.Exec(harness.ctx, `
		UPDATE jobs SET lease_expires_at = clock_timestamp() - interval '1 second'
		WHERE id = $1::uuid AND status = 'leased'
	`, jobID); err != nil {
		t.Fatalf("expire test lease: %v", err)
	}
}

func sampleSystemInfo(hostname string) systeminfo.Info {
	return systeminfo.Info{
		OS:             systeminfo.OperatingSystem{ID: "ubuntu", PrettyName: "Ubuntu 26.04 LTS", VersionID: "26.04"},
		Hostname:       hostname,
		Kernel:         systeminfo.KernelInfo{Name: "Linux", Release: "6.14.0-test"},
		Architecture:   "amd64",
		Memory:         systeminfo.MemoryInfo{TotalBytes: 8 << 30, AvailableBytes: 0},
		RootFilesystem: systeminfo.FilesystemInfo{TotalBytes: 100 << 30, UsedBytes: 25 << 30, FreeBytes: 75 << 30, AvailableBytes: 0},
		CollectedAt:    time.Now().UTC(),
	}
}

func newJobTestHarness(t *testing.T) *jobTestHarness {
	return newJobTestHarnessWithWrites(t, false)
}

func newJobTestHarnessWithWrites(t *testing.T, allowFileWrites bool) *jobTestHarness {
	return newJobTestHarnessWithPolicies(t, allowFileWrites, false)
}

func newJobTestHarnessWithPolicies(t *testing.T, allowFileWrites, allowAPTWrites bool, allowCommandExecution ...bool) *jobTestHarness {
	t.Helper()
	databaseURL := testDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	issuer := newTestIssuer(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test HTTP address: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	config := Config{
		DatabaseURL:           databaseURL,
		OIDCIssuerURL:         issuer.URL(),
		OIDCAudience:          "ubuntu-fleet-manager",
		PublicURL:             "http://" + listener.Addr().String(),
		ListenAddress:         "127.0.0.1:8080",
		FileActionKeyFile:     testEncryptionKeyFile(t),
		AllowFileWrites:       allowFileWrites,
		AllowAPTWrites:        allowAPTWrites,
		AllowCommandExecution: len(allowCommandExecution) > 0 && allowCommandExecution[0],
		allowInsecureOIDCTest: true,
	}
	service, err := New(ctx, config)
	if err != nil {
		t.Fatalf("start control plane: %v", err)
	}
	t.Cleanup(service.Close)
	httpServer := httptest.NewUnstartedServer(service.Handler())
	httpServer.Listener = listener
	httpServer.Start()
	t.Cleanup(httpServer.Close)

	unique := time.Now().UnixNano()
	subjectA := fmt.Sprintf("job-owner-%d", unique)
	subjectB := fmt.Sprintf("job-other-%d", unique)
	sessionA := connectAuthorized(t, ctx, httpServer.URL+"/mcp", issuer.Token(t, subjectA, config.OIDCAudience))
	t.Cleanup(func() { _ = sessionA.Close() })
	sessionB := connectAuthorized(t, ctx, httpServer.URL+"/mcp", issuer.Token(t, subjectB, config.OIDCAudience))
	t.Cleanup(func() { _ = sessionB.Close() })
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		if _, err := service.store.pool.Exec(cleanupCtx, "DELETE FROM tenants WHERE issuer = $1 AND (subject = $2 OR subject = $3)", issuer.URL(), subjectA, subjectB); err != nil {
			t.Errorf("clean up job test tenants: %v", err)
		}
	})

	codeResult, err := sessionA.CallTool(ctx, &mcp.CallToolParams{Name: "create_pairing_code", Arguments: map[string]any{}})
	if err != nil || codeResult.IsError {
		t.Fatalf("create pairing code: result=%#v error=%v", codeResult, err)
	}
	codePayload, err := json.Marshal(codeResult.StructuredContent)
	if err != nil {
		t.Fatalf("marshal pairing code: %v", err)
	}
	var code struct {
		Value string `json:"pairing_code"`
	}
	if err := json.Unmarshal(codePayload, &code); err != nil || code.Value == "" {
		t.Fatalf("decode pairing code: payload=%s error=%v", codePayload, err)
	}
	enrollmentResponse, enrollmentBody := postAgentJSON(t, ctx, httpServer.URL, "/agent/enroll", map[string]any{
		"pairing_code":   code.Value,
		"hostname":       "job-target.example.test",
		"os_pretty_name": "Ubuntu 26.04 LTS",
	}, "")
	if enrollmentResponse.StatusCode != http.StatusCreated {
		t.Fatalf("enroll job target status = %d: %s", enrollmentResponse.StatusCode, enrollmentBody)
	}
	var enrollment struct {
		HostID     string `json:"host_id"`
		Credential string `json:"credential"`
	}
	if err := json.Unmarshal(enrollmentBody, &enrollment); err != nil {
		t.Fatalf("decode enrolled host: %v", err)
	}
	return &jobTestHarness{
		ctx:        ctx,
		service:    service,
		server:     httpServer,
		issuer:     issuer,
		sessionA:   sessionA,
		sessionB:   sessionB,
		hostID:     enrollment.HostID,
		credential: enrollment.Credential,
	}
}

func waitForAgentJob(t *testing.T, harness *jobTestHarness, timeout time.Duration) jobTestLease {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		response, body := postAgentJSON(t, harness.ctx, harness.server.URL, "/agent/poll", map[string]any{}, harness.credential)
		if response.StatusCode != http.StatusOK {
			t.Fatalf("poll for agent job status = %d: %s", response.StatusCode, body)
		}
		var poll struct {
			Status string       `json:"status"`
			Job    jobTestLease `json:"job"`
		}
		if err := json.Unmarshal(body, &poll); err != nil {
			t.Fatalf("decode agent poll: %v", err)
		}
		if poll.Status == "job" {
			return poll.Job
		}
		time.Sleep(20 * time.Millisecond)
	}
	var jobSummary string
	if err := harness.service.store.pool.QueryRow(harness.ctx, `
		SELECT COALESCE(string_agg(operation || ':' || status, ',' ORDER BY requested_at), '<none>')
		FROM jobs WHERE host_id = $1::uuid
	`, harness.hostID).Scan(&jobSummary); err != nil {
		t.Fatalf("read queued command job diagnostics: %v", err)
	}
	t.Logf("command job state at timeout: %s", jobSummary)
	t.Fatal("control plane did not deliver a job before the test deadline")
	return jobTestLease{}
}

func waitForAgentJobOrMCPError(t *testing.T, harness *jobTestHarness, completed <-chan jobCallOutcome, timeout time.Duration) jobTestLease {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case outcome := <-completed:
			var content []byte
			if outcome.result != nil {
				content, _ = json.Marshal(outcome.result.Content)
			}
			t.Fatalf("MCP command call finished before queuing a host job: result content=%s error=%v", content, outcome.err)
		default:
		}
		response, body := postAgentJSON(t, harness.ctx, harness.server.URL, "/agent/poll", map[string]any{}, harness.credential)
		if response.StatusCode != http.StatusOK {
			t.Fatalf("poll for command job status = %d: %s", response.StatusCode, body)
		}
		var poll struct {
			Status string       `json:"status"`
			Job    jobTestLease `json:"job"`
		}
		if err := json.Unmarshal(body, &poll); err != nil {
			t.Fatalf("decode command agent poll: %v", err)
		}
		if poll.Status == "job" {
			return poll.Job
		}
		time.Sleep(20 * time.Millisecond)
	}
	var jobSummary string
	if err := harness.service.store.pool.QueryRow(harness.ctx, `
		SELECT COALESCE(string_agg(operation || ':' || status, ',' ORDER BY requested_at), '<none>')
		FROM jobs WHERE host_id = $1::uuid
	`, harness.hostID).Scan(&jobSummary); err != nil {
		t.Fatalf("read queued command job diagnostics: %v", err)
	}
	t.Logf("command job state at timeout: %s", jobSummary)
	t.Fatal("control plane did not deliver a job before the test deadline")
	return jobTestLease{}
}

func waitForMCPOutcome(t *testing.T, completed <-chan jobCallOutcome, timeout time.Duration) jobCallOutcome {
	t.Helper()
	select {
	case outcome := <-completed:
		return outcome
	case <-time.After(timeout):
		t.Fatal("MCP tool call did not complete before the test deadline")
		return jobCallOutcome{}
	}
}

func postAgentJSON(t *testing.T, ctx context.Context, baseURL, path string, payload any, credential string) (*http.Response, []byte) {
	t.Helper()
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("encode %s request: %v", path, err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+path, bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("create %s request: %v", path, err)
	}
	request.Header.Set("Content-Type", "application/json")
	if credential != "" {
		request.Header.Set("Authorization", "Bearer "+credential)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		t.Fatalf("read %s response: %v", path, err)
	}
	return response, body
}
