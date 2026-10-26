package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestPairingEnrollmentPollingAndRevocation(t *testing.T) {
	databaseURL := testDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

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

	subjectA := "enrollment-owner-" + time.Now().Format("150405.000000000")
	subjectB := "enrollment-other-" + time.Now().Format("150405.000000000")
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		if _, err := service.store.pool.Exec(cleanupCtx, `
			DELETE FROM tenants WHERE issuer = $1 AND (subject = $2 OR subject = $3)
		`, issuer.URL(), subjectA, subjectB); err != nil {
			t.Errorf("clean up enrollment test tenants: %v", err)
		}
	})
	sessionA := connectAuthorized(t, ctx, httpServer.URL+"/mcp", issuer.Token(t, subjectA, config.OIDCAudience))
	t.Cleanup(func() { _ = sessionA.Close() })
	sessionB := connectAuthorized(t, ctx, httpServer.URL+"/mcp", issuer.Token(t, subjectB, config.OIDCAudience))
	t.Cleanup(func() { _ = sessionB.Close() })

	for _, session := range []*mcp.ClientSession{sessionA, sessionB} {
		tools, err := session.ListTools(ctx, nil)
		if err != nil {
			t.Fatalf("list authenticated tools: %v", err)
		}
		if !hasTool(tools.Tools, "create_pairing_code") || !hasTool(tools.Tools, "remove_host") {
			t.Fatalf("tools = %v, want create_pairing_code and remove_host", toolNames(tools.Tools))
		}
		for _, tool := range tools.Tools {
			if tool.Name == "create_pairing_code" {
				if tool.Annotations == nil || tool.Annotations.ReadOnlyHint || tool.Annotations.DestructiveHint == nil || *tool.Annotations.DestructiveHint || tool.Annotations.IdempotentHint {
					t.Errorf("create_pairing_code annotations = %#v, want mutating, non-destructive, and non-idempotent", tool.Annotations)
				}
			}
			if tool.Name == "remove_host" {
				if tool.Annotations == nil || tool.Annotations.ReadOnlyHint || tool.Annotations.DestructiveHint == nil || !*tool.Annotations.DestructiveHint || !tool.Annotations.IdempotentHint {
					t.Errorf("remove_host annotations = %#v, want mutating, destructive, and idempotent", tool.Annotations)
				}
			}
		}
	}

	createPairingCode := func() (string, time.Time) {
		t.Helper()
		result, err := sessionA.CallTool(ctx, &mcp.CallToolParams{Name: "create_pairing_code", Arguments: map[string]any{}})
		if err != nil {
			t.Fatalf("create pairing code: %v", err)
		}
		if result.IsError {
			t.Fatalf("create_pairing_code returned error: %v", result.Content)
		}
		payload, err := json.Marshal(result.StructuredContent)
		if err != nil {
			t.Fatalf("marshal pairing code: %v", err)
		}
		var response struct {
			Code      string    `json:"pairing_code"`
			ExpiresAt time.Time `json:"expires_at"`
		}
		if err := json.Unmarshal(payload, &response); err != nil {
			t.Fatalf("decode pairing code: %v", err)
		}
		if response.Code == "" {
			t.Fatal("create_pairing_code returned an empty code")
		}
		if remaining := time.Until(response.ExpiresAt); remaining < 9*time.Minute || remaining > 10*time.Minute+5*time.Second {
			t.Fatalf("pairing code lifetime = %s, want ten minutes", remaining)
		}
		return response.Code, response.ExpiresAt
	}

	postJSON := func(path string, body any, credential string) (*http.Response, []byte) {
		t.Helper()
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("encode request: %v", err)
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, httpServer.URL+path, bytes.NewReader(encoded))
		if err != nil {
			t.Fatalf("create request: %v", err)
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
		payload, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
		if err != nil {
			t.Fatalf("read %s response: %v", path, err)
		}
		return response, payload
	}
	missingCredential, missingCredentialBody := postJSON("/agent/poll", map[string]any{}, "")
	if missingCredential.StatusCode != http.StatusUnauthorized {
		t.Fatalf("agent poll without credential status = %d, want 401: %s", missingCredential.StatusCode, missingCredentialBody)
	}
	invalidCredential, invalidCredentialBody := postJSON("/agent/poll", map[string]any{}, "not-a-host-credential")
	if invalidCredential.StatusCode != http.StatusUnauthorized {
		t.Fatalf("agent poll with invalid credential status = %d, want 401: %s", invalidCredential.StatusCode, invalidCredentialBody)
	}

	tenantA, err := service.store.ensureTenant(ctx, issuer.URL(), subjectA)
	if err != nil {
		t.Fatalf("find pairing-code owner tenant: %v", err)
	}
	tenantB, err := service.store.ensureTenant(ctx, issuer.URL(), subjectB)
	if err != nil {
		t.Fatalf("find other operator tenant: %v", err)
	}
	code, _ := createPairingCode()
	forgedTenant, forgedTenantBody := postJSON("/agent/enroll", map[string]any{
		"pairing_code": code, "tenant_id": tenantB, "hostname": "forged.example.test", "os_pretty_name": "Ubuntu 26.04 LTS",
	}, "")
	if forgedTenant.StatusCode != http.StatusBadRequest {
		t.Fatalf("caller-selected enrollment tenant status = %d, want 400: %s", forgedTenant.StatusCode, forgedTenantBody)
	}
	response, payload := postJSON("/agent/enroll", map[string]any{
		"pairing_code":   code,
		"hostname":       "enrolled-host.example.test",
		"os_pretty_name": "Ubuntu 26.04 LTS",
	}, "")
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("enroll status = %d, want 201: %s", response.StatusCode, payload)
	}
	var enrollment struct {
		HostID     string `json:"host_id"`
		Credential string `json:"credential"`
	}
	if err := json.Unmarshal(payload, &enrollment); err != nil {
		t.Fatalf("decode enrollment response: %v", err)
	}
	if enrollment.HostID == "" || enrollment.Credential == "" {
		t.Fatalf("enrollment response is missing host identity or one-time credential: %#v", enrollment)
	}
	pairingHash := sha256.Sum256([]byte(code))
	var storedPairingHash []byte
	if err := service.store.pool.QueryRow(ctx, "SELECT code_hash FROM pairing_codes WHERE code_hash = $1", pairingHash[:]).Scan(&storedPairingHash); err != nil {
		t.Fatalf("read stored pairing-code verifier: %v", err)
	}
	if !bytes.Equal(storedPairingHash, pairingHash[:]) || bytes.Equal(storedPairingHash, []byte(code)) {
		t.Fatal("control plane did not store the pairing code as its SHA-256 verifier")
	}
	credentialHash := sha256.Sum256([]byte(enrollment.Credential))
	var storedCredentialHash []byte
	if err := service.store.pool.QueryRow(ctx, `
		SELECT credential_hash FROM host_credentials WHERE host_id = $1::uuid
	`, enrollment.HostID).Scan(&storedCredentialHash); err != nil {
		t.Fatalf("read stored host-credential verifier: %v", err)
	}
	if !bytes.Equal(storedCredentialHash, credentialHash[:]) || bytes.Equal(storedCredentialHash, []byte(enrollment.Credential)) {
		t.Fatal("control plane did not store the host credential as its SHA-256 verifier")
	}

	replay, replayBody := postJSON("/agent/enroll", map[string]any{
		"pairing_code": code, "hostname": "replay.example.test", "os_pretty_name": "Ubuntu 26.04 LTS",
	}, "")
	if replay.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replayed pairing code status = %d, want 401: %s", replay.StatusCode, replayBody)
	}
	if bytes.Contains(replayBody, []byte(enrollment.Credential)) {
		t.Fatal("enrollment replay response exposed the host credential")
	}
	duplicateCode, _ := createPairingCode()
	duplicateHost, duplicateHostBody := postJSON("/agent/enroll", map[string]any{
		"pairing_code": duplicateCode, "hostname": "enrolled-host.example.test", "os_pretty_name": "Ubuntu 26.04 LTS",
	}, "")
	if duplicateHost.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate active hostname status = %d, want 409: %s", duplicateHost.StatusCode, duplicateHostBody)
	}

	type listedHost struct {
		ID       string
		Hostname string
		LastSeen time.Time
	}
	listHosts := func(session *mcp.ClientSession) []string {
		t.Helper()
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "list_hosts", Arguments: map[string]any{}})
		if err != nil {
			t.Fatalf("list hosts: %v", err)
		}
		if result.IsError {
			t.Fatalf("list_hosts returned error: %v", result.Content)
		}
		payload, err := json.Marshal(result.StructuredContent)
		if err != nil {
			t.Fatalf("marshal host list: %v", err)
		}
		var page struct {
			Hosts []struct {
				ID       string    `json:"id"`
				Hostname string    `json:"hostname"`
				LastSeen time.Time `json:"last_seen_at"`
			} `json:"hosts"`
		}
		if err := json.Unmarshal(payload, &page); err != nil {
			t.Fatalf("decode host list: %v", err)
		}
		var names []string
		for _, host := range page.Hosts {
			if host.ID == enrollment.HostID && host.LastSeen.IsZero() {
				t.Error("authenticated poll did not report host liveness")
			}
			if strings.Contains(string(payload), enrollment.Credential) {
				t.Fatal("host inventory exposed the host credential")
			}
			names = append(names, host.Hostname)
		}
		return names
	}
	listHostsWithState := func(session *mcp.ClientSession) []listedHost {
		t.Helper()
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "list_hosts", Arguments: map[string]any{}})
		if err != nil {
			t.Fatalf("list hosts: %v", err)
		}
		if result.IsError {
			t.Fatalf("list_hosts returned error: %v", result.Content)
		}
		payload, err := json.Marshal(result.StructuredContent)
		if err != nil {
			t.Fatalf("marshal host list: %v", err)
		}
		var page struct {
			Hosts []struct {
				ID       string    `json:"id"`
				Hostname string    `json:"hostname"`
				LastSeen time.Time `json:"last_seen_at"`
			} `json:"hosts"`
		}
		if err := json.Unmarshal(payload, &page); err != nil {
			t.Fatalf("decode host list: %v", err)
		}
		if strings.Contains(string(payload), enrollment.Credential) {
			t.Fatal("host inventory exposed the host credential")
		}
		hosts := make([]listedHost, 0, len(page.Hosts))
		for _, host := range page.Hosts {
			hosts = append(hosts, listedHost{ID: host.ID, Hostname: host.Hostname, LastSeen: host.LastSeen})
		}
		return hosts
	}
	initialHosts := listHostsWithState(sessionA)
	if len(initialHosts) != 1 || initialHosts[0].Hostname != "enrolled-host.example.test" {
		t.Fatalf("owner host inventory = %#v, want enrolled host", initialHosts)
	}
	if got := listHosts(sessionB); len(got) != 0 {
		t.Fatalf("other tenant host inventory = %v, want empty", got)
	}
	otherTenantRemoval, err := sessionB.CallTool(ctx, &mcp.CallToolParams{Name: "remove_host", Arguments: map[string]any{"host_id": enrollment.HostID}})
	if err != nil {
		t.Fatalf("other tenant remove_host call: %v", err)
	}
	if !otherTenantRemoval.IsError {
		t.Fatal("operator in another tenant removed this host")
	}
	if got := listHosts(sessionA); len(got) != 1 {
		t.Fatalf("owner inventory after cross-tenant removal attempt = %v, want one host", got)
	}

	time.Sleep(10 * time.Millisecond)
	poll, pollBody := postJSON("/agent/poll", map[string]any{}, enrollment.Credential)
	if poll.StatusCode != http.StatusOK {
		t.Fatalf("authenticated host poll status = %d, want 200: %s", poll.StatusCode, pollBody)
	}
	var pollResult struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(pollBody, &pollResult); err != nil {
		t.Fatalf("decode host poll response: %v", err)
	}
	if pollResult.Status != "idle" {
		t.Fatalf("host poll status = %q, want idle", pollResult.Status)
	}
	if bytes.Contains(pollBody, []byte(enrollment.Credential)) {
		t.Fatal("host poll response exposed the host credential")
	}
	updatedHosts := listHostsWithState(sessionA)
	if len(updatedHosts) != 1 || !updatedHosts[0].LastSeen.After(initialHosts[0].LastSeen) {
		t.Fatalf("host liveness timestamp did not advance: before=%#v after=%#v", initialHosts, updatedHosts)
	}

	secondCode, _ := createPairingCode()
	secondCodeHash := sha256.Sum256([]byte(secondCode))
	if _, err := service.store.pool.Exec(ctx, `
		UPDATE pairing_codes SET expires_at = now() - interval '1 second'
		WHERE tenant_id = $1 AND code_hash = $2 AND consumed_at IS NULL
	`, tenantA, secondCodeHash[:]); err != nil {
		t.Fatalf("expire test pairing code: %v", err)
	}
	expired, expiredBody := postJSON("/agent/enroll", map[string]any{
		"pairing_code": secondCode, "hostname": "expired.example.test", "os_pretty_name": "Ubuntu 26.04 LTS",
	}, "")
	if expired.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired pairing code status = %d, want 401: %s", expired.StatusCode, expiredBody)
	}
	invalid, invalidBody := postJSON("/agent/enroll", map[string]any{
		"pairing_code": "not-a-valid-pairing-code", "hostname": "invalid.example.test", "os_pretty_name": "Ubuntu 26.04 LTS",
	}, "")
	if invalid.StatusCode != http.StatusUnauthorized {
		t.Fatalf("invalid pairing code status = %d, want 401: %s", invalid.StatusCode, invalidBody)
	}

	removed, err := sessionA.CallTool(ctx, &mcp.CallToolParams{Name: "remove_host", Arguments: map[string]any{"host_id": enrollment.HostID}})
	if err != nil {
		t.Fatalf("remove host: %v", err)
	}
	if removed.IsError {
		t.Fatalf("remove_host returned error: %v", removed.Content)
	}
	postRemovalPoll, postRemovalBody := postJSON("/agent/poll", map[string]any{}, enrollment.Credential)
	if postRemovalPoll.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked host poll status = %d, want 401: %s", postRemovalPoll.StatusCode, postRemovalBody)
	}
	if got := listHosts(sessionA); len(got) != 0 {
		t.Fatalf("owner host inventory after removal = %v, want empty", got)
	}
	reenrolled, reenrollBody := postJSON("/agent/enroll", map[string]any{
		"pairing_code": duplicateCode, "hostname": "enrolled-host.example.test", "os_pretty_name": "Ubuntu 26.04 LTS",
	}, "")
	if reenrolled.StatusCode != http.StatusCreated {
		t.Fatalf("re-enrollment status = %d, want 201: %s", reenrolled.StatusCode, reenrollBody)
	}
	var renewedIdentity struct {
		HostID     string `json:"host_id"`
		Credential string `json:"credential"`
	}
	if err := json.Unmarshal(reenrollBody, &renewedIdentity); err != nil {
		t.Fatalf("decode re-enrollment response: %v", err)
	}
	if renewedIdentity.HostID == "" || renewedIdentity.HostID == enrollment.HostID || renewedIdentity.Credential == "" || renewedIdentity.Credential == enrollment.Credential {
		t.Fatalf("re-enrollment did not create new host identity and credential: %#v", renewedIdentity)
	}
	if got := listHosts(sessionA); len(got) != 1 || got[0] != "enrolled-host.example.test" {
		t.Fatalf("owner inventory after re-enrollment = %v, want one active host", got)
	}
	newCredentialPoll, newCredentialBody := postJSON("/agent/poll", map[string]any{}, renewedIdentity.Credential)
	if newCredentialPoll.StatusCode != http.StatusOK {
		t.Fatalf("newly enrolled host poll status = %d, want 200: %s", newCredentialPoll.StatusCode, newCredentialBody)
	}
}
