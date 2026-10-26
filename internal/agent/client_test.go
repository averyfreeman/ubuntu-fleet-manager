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
