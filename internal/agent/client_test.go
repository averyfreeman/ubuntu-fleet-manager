package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/averyfreeman/ubuntu-fleet-manager/internal/systeminfo"
)

func TestEnrollStoresCredentialPrivatelyAndPollsOutbound(t *testing.T) {
	credential := "ufm_host_one-time-secret"
	var pairingCodeSeen, credentialSeen string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/agent/enroll":
			if r.Method != http.MethodPost {
				t.Errorf("enrollment method = %s, want POST", r.Method)
			}
			var request struct {
				PairingCode  string `json:"pairing_code"`
				Hostname     string `json:"hostname"`
				OSPrettyName string `json:"os_pretty_name"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("decode enrollment request: %v", err)
			}
			pairingCodeSeen = request.PairingCode
			if request.Hostname != "node-01" || request.OSPrettyName != "Ubuntu 26.04 LTS" {
				t.Errorf("enrollment identity = %#v, want node-01 and Ubuntu 26.04 LTS", request)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"host_id":"host-123","credential":"`+credential+`"}`)
		case "/agent/poll":
			if r.Method != http.MethodPost {
				t.Errorf("poll method = %s, want POST", r.Method)
			}
			credentialSeen = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"status":"idle"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	configPath := filepath.Join(t.TempDir(), "agent.json")
	client := NewClient(nil)
	hostID, err := client.Enroll(context.Background(), server.URL, "ufm_pair_one-time-code", "node-01", "Ubuntu 26.04 LTS", configPath)
	if err != nil {
		t.Fatalf("enroll agent: %v", err)
	}
	if hostID != "host-123" {
		t.Fatalf("enrolled host ID = %q, want host-123", hostID)
	}
	if pairingCodeSeen != "ufm_pair_one-time-code" {
		t.Fatalf("pairing code sent = %q, want original one-time code", pairingCodeSeen)
	}
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("stat agent config: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("agent config mode = %04o, want 0600", info.Mode().Perm())
	}

	config, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("load agent config: %v", err)
	}
	if config.Credential != credential || config.HostID != hostID {
		t.Fatalf("stored agent config = %#v, want host ID and returned credential", config)
	}
	if err := client.PollOnce(context.Background(), config); err != nil {
		t.Fatalf("poll control plane: %v", err)
	}
	if credentialSeen != credential {
		t.Fatalf("poll credential = %q, want enrolled host credential", credentialSeen)
	}
}

func TestAgentClientRejectsInsecureRemoteControlPlaneURL(t *testing.T) {
	client := NewClient(nil)
	err := client.PollOnce(context.Background(), Config{
		ServerURL:  "http://fleet.example.test",
		HostID:     "host-123",
		Credential: "ufm_host_secret",
	})
	if err == nil {
		t.Fatal("agent accepted a non-HTTPS control-plane URL")
	}
}

func TestPollFailureDoesNotExposeCredential(t *testing.T) {
	credential := "ufm_host_private-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, credential)
	}))
	defer server.Close()

	err := NewClient(nil).PollOnce(context.Background(), Config{ServerURL: server.URL, HostID: "host-123", Credential: credential})
	if err == nil {
		t.Fatal("poll with revoked credential unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), credential) {
		t.Fatalf("poll error exposed credential: %v", err)
	}
}

func TestLoadConfigRejectsWorldOrGroupReadableCredentialFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	contents := `{"server_url":"https://fleet.example.test","host_id":"host-123","credential":"ufm_host_secret"}`
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write test config: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("set broad test config mode: %v", err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("agent loaded a credential file readable by group or others")
	}
}

func TestRunStopsWhenContextIsCanceled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"idle"}`)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := NewClient(nil).Run(ctx, Config{ServerURL: server.URL, HostID: "host-123", Credential: "ufm_host_secret"}, time.Second); err == nil {
		t.Fatal("agent run returned without observing cancellation")
	}
}

func TestPollExecutesTypedSystemInfoJobAndSubmitsStructuredResult(t *testing.T) {
	const credential = "ufm_host_private-credential"
	collected := 0
	snapshot := systeminfo.Info{
		OS:           systeminfo.OperatingSystem{ID: "ubuntu", PrettyName: "Ubuntu 26.04 LTS", VersionID: "26.04"},
		Hostname:     "web-01",
		Kernel:       systeminfo.KernelInfo{Name: "Linux", Release: "6.14-test"},
		Architecture: "amd64",
		Memory:       systeminfo.MemoryInfo{TotalBytes: 8 << 30, AvailableBytes: 4 << 30},
		RootFilesystem: systeminfo.FilesystemInfo{
			TotalBytes: 100 << 30, UsedBytes: 25 << 30, FreeBytes: 75 << 30, AvailableBytes: 70 << 30,
		},
		CollectedAt: time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC),
	}
	var submitted struct {
		JobID      string          `json:"job_id"`
		LeaseToken string          `json:"lease_token"`
		Result     systeminfo.Info `json:"result"`
		Error      string          `json:"error"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+credential {
			t.Errorf("agent authorization header = %q, want enrolled credential", r.Header.Get("Authorization"))
		}
		switch r.URL.Path {
		case "/agent/poll":
			_, _ = io.WriteString(w, `{"status":"job","job":{"id":"job-123","operation":"get_system_info","lease_token":"lease-456","lease_expires_at":"2026-10-26T12:01:00Z","attempt":1}}`)
		case "/agent/result":
			if err := json.NewDecoder(r.Body).Decode(&submitted); err != nil {
				t.Errorf("decode submitted job result: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"accepted":true}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewClientWithSystemInfoCollector(nil, func() (systeminfo.Info, error) {
		collected++
		return snapshot, nil
	})
	if err := client.PollOnce(context.Background(), Config{ServerURL: server.URL, HostID: "host-123", Credential: credential}); err != nil {
		t.Fatalf("poll and execute typed job: %v", err)
	}
	if collected != 1 || submitted.JobID != "job-123" || submitted.LeaseToken != "lease-456" || submitted.Error != "" {
		t.Fatalf("job execution = collected %d times, result %#v", collected, submitted)
	}
	if submitted.Result.Hostname != snapshot.Hostname || !submitted.Result.CollectedAt.Equal(snapshot.CollectedAt) {
		t.Fatalf("submitted snapshot = %#v, want %#v", submitted.Result, snapshot)
	}
}

func TestAgentRejectsUnknownOperationWithoutExecutingIt(t *testing.T) {
	const credential = "ufm_host_private-credential"
	collected := 0
	var submitted struct {
		JobID      string `json:"job_id"`
		LeaseToken string `json:"lease_token"`
		Result     any    `json:"result"`
		Error      string `json:"error"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/agent/poll" {
			_, _ = io.WriteString(w, `{"status":"job","job":{"id":"job-123","operation":"execute_command","lease_token":"lease-456","lease_expires_at":"2026-10-26T12:01:00Z","attempt":1}}`)
			return
		}
		if r.URL.Path == "/agent/result" {
			if err := json.NewDecoder(r.Body).Decode(&submitted); err != nil {
				t.Errorf("decode unsupported-operation result: %v", err)
			}
			_, _ = io.WriteString(w, `{"accepted":true}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClientWithSystemInfoCollector(nil, func() (systeminfo.Info, error) {
		collected++
		return systeminfo.Info{}, nil
	})
	if err := client.PollOnce(context.Background(), Config{ServerURL: server.URL, HostID: "host-123", Credential: credential}); err != nil {
		t.Fatalf("return unsupported operation error: %v", err)
	}
	if collected != 0 || submitted.JobID != "job-123" || submitted.LeaseToken != "lease-456" || submitted.Result != nil || submitted.Error == "" {
		t.Fatalf("unsupported operation was executed or not rejected: collected=%d result=%#v", collected, submitted)
	}
}

func TestPollTreatsExpiredJobLeaseAsDiscardedAndKeepsAgentAvailable(t *testing.T) {
	const credential = "ufm_host_private-credential"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/agent/poll":
			_, _ = io.WriteString(w, `{"status":"job","job":{"id":"job-123","operation":"get_system_info","lease_token":"lease-456","lease_expires_at":"2026-10-26T12:01:00Z","attempt":1}}`)
		case "/agent/result":
			w.WriteHeader(http.StatusConflict)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewClientWithSystemInfoCollector(nil, func() (systeminfo.Info, error) {
		return systeminfo.Info{Hostname: "web-01"}, nil
	})
	if err := client.PollOnce(context.Background(), Config{ServerURL: server.URL, HostID: "host-123", Credential: credential}); err != nil {
		t.Fatalf("poll with expired lease: %v", err)
	}
}
