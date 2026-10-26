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
	"testing"
	"time"

	"github.com/averyfreeman/ubuntu-fleet-manager/internal/systeminfo"
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
	ID             string    `json:"id"`
	Operation      string    `json:"operation"`
	LeaseToken     string    `json:"lease_token"`
	LeaseExpiresAt time.Time `json:"lease_expires_at"`
	Attempt        int       `json:"attempt"`
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
	t.Fatal("control plane did not deliver a job before the test deadline")
	return jobTestLease{}
}

func waitForMCPOutcome(t *testing.T, completed <-chan jobCallOutcome, timeout time.Duration) jobCallOutcome {
	t.Helper()
	select {
	case outcome := <-completed:
		return outcome
	case <-time.After(timeout):
		t.Fatal("MCP system-info call did not complete before the test deadline")
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
