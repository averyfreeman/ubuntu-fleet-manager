package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/averyfreeman/ubuntu-fleet-manager/internal/hostops"
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
	defaultPaths, err := hostops.NormalizeAllowedPaths(nil)
	if err != nil {
		t.Fatalf("normalize default host path boundary: %v", err)
	}
	if len(config.AllowedPaths) != 1 || len(defaultPaths) != 1 || config.AllowedPaths[0] != defaultPaths[0] {
		t.Fatalf("stored default allowed paths = %v, want agent home %v", config.AllowedPaths, defaultPaths)
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

func TestSaveAndLoadConfigPreservesExplicitBoundedAPTPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	config := Config{
		ServerURL:  "https://fleet.example.test",
		HostID:     "host-123",
		Credential: "ufm_host_secret",
		APTPolicy: hostops.APTPolicy{
			Enabled:           true,
			AllowedOperations: []string{hostops.APTPolicyRollback, hostops.APTPolicyUpgrade},
			AllowedPackages:   []string{"curl"},
		},
	}
	if err := SaveConfig(path, config); err != nil {
		t.Fatalf("save explicit APT policy: %v", err)
	}
	loaded, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("load explicit APT policy: %v", err)
	}
	if !loaded.APTPolicy.Enabled || !reflect.DeepEqual(loaded.APTPolicy.AllowedOperations, config.APTPolicy.AllowedOperations) || !reflect.DeepEqual(loaded.APTPolicy.AllowedPackages, []string{"curl"}) {
		t.Fatalf("loaded APT policy = %#v, want explicit upgrade/rollback for curl", loaded.APTPolicy)
	}

	invalid := config
	invalid.APTPolicy.AllowedPackages = []string{"--assume-yes"}
	if err := SaveConfig(filepath.Join(t.TempDir(), "invalid.json"), invalid); err == nil {
		t.Fatal("saved a package policy that permits option injection")
	}
}

func TestSaveAndLoadConfigPreservesExactCommandPolicy(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "agent.json")
	workingDirectory := t.TempDir()
	executable := filepath.Join(t.TempDir(), "report")
	if err := os.WriteFile(executable, []byte("test executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	config := Config{
		ServerURL:  "https://fleet.example.test",
		HostID:     "host-123",
		Credential: "ufm_host_secret",
		CommandPolicy: hostops.CommandPolicy{
			Enabled: true,
			Rules: []hostops.CommandRule{{
				Executable:         executable,
				AllowedArguments:   [][]string{{"--output", "/var/lib/report.json"}, {"--version"}},
				WorkingDirectories: []string{workingDirectory},
			}},
		},
	}
	if err := SaveConfig(configPath, config); err != nil {
		t.Fatalf("save exact command policy: %v", err)
	}
	loaded, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("load exact command policy: %v", err)
	}
	if !loaded.CommandPolicy.Enabled || !reflect.DeepEqual(loaded.CommandPolicy, config.CommandPolicy) {
		t.Fatalf("loaded command policy = %#v, want %#v", loaded.CommandPolicy, config.CommandPolicy)
	}

	invalid := config
	invalid.CommandPolicy.Rules = []hostops.CommandRule{{
		Executable: "/bin/sh", AllowedArguments: [][]string{{"-c", "id"}},
	}}
	if err := SaveConfig(filepath.Join(t.TempDir(), "invalid.json"), invalid); err == nil {
		t.Fatal("saved a command policy that permits a shell")
	}

	oversized := config
	oversized.CommandPolicy.Rules = []hostops.CommandRule{{
		Executable: executable,
		AllowedArguments: [][]string{
			{strings.Repeat("a", hostops.MaxCommandArgumentSize)},
			{strings.Repeat("b", hostops.MaxCommandArgumentSize)},
			{strings.Repeat("c", hostops.MaxCommandArgumentSize)},
			{strings.Repeat("d", hostops.MaxCommandArgumentSize)},
			{strings.Repeat("e", hostops.MaxCommandArgumentSize)},
		},
	}}
	if err := SaveConfig(filepath.Join(t.TempDir(), "oversized.json"), oversized); err == nil {
		t.Fatal("saved an agent configuration larger than the load limit")
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

func TestPollExecutesTypedWriteFileAndSubmitsCapturedPriorState(t *testing.T) {
	const credential = "ufm_host_private-credential"
	root := t.TempDir()
	path := filepath.Join(root, "settings.conf")
	if err := os.WriteFile(path, []byte("before\n"), 0o640); err != nil {
		t.Fatalf("write original file: %v", err)
	}
	newContent := strings.Repeat("x", 32<<10)
	encodedInput, err := json.Marshal(hostops.WriteFileInput{Path: path, Content: newContent})
	if err != nil {
		t.Fatal(err)
	}
	var submitted struct {
		Result hostops.WriteFileResult `json:"result"`
		Error  string                  `json:"error"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/agent/poll":
			_, _ = fmt.Fprintf(w, `{"status":"job","job":{"id":"job-write","operation":"write_file","input":%s,"lease_token":"lease-write","lease_expires_at":"2026-10-26T12:01:00Z","attempt":1}}`, encodedInput)
		case "/agent/result":
			if err := json.NewDecoder(r.Body).Decode(&submitted); err != nil {
				t.Errorf("decode submitted write result: %v", err)
			}
			_, _ = io.WriteString(w, `{"accepted":true}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	config := Config{ServerURL: server.URL, HostID: "host-123", Credential: credential, WritablePaths: []string{root}}
	if err := NewClient(nil).PollOnce(context.Background(), config); err != nil {
		t.Fatalf("poll and execute write job: %v", err)
	}
	content, err := os.ReadFile(path)
	info, statErr := os.Stat(path)
	if err != nil || statErr != nil || string(content) != newContent || info.Mode().Perm() != 0o640 {
		t.Fatalf("written file = %q mode=%v read=%v stat=%v", content, info, err, statErr)
	}
	if submitted.Error != "" || !submitted.Result.Previous.Existed || string(submitted.Result.Previous.Content) != "before\n" || submitted.Result.Previous.Mode != 0o640 {
		t.Fatalf("submitted write result = %#v, want captured prior bytes/mode", submitted)
	}
}

func TestPollRejectsFileWriteWithoutExplicitWritablePath(t *testing.T) {
	const credential = "ufm_host_private-credential"
	root := t.TempDir()
	path := filepath.Join(root, "settings.conf")
	if err := os.WriteFile(path, []byte("preserve"), 0o600); err != nil {
		t.Fatalf("write original file: %v", err)
	}
	var submitted struct {
		Error string `json:"error"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/agent/poll" {
			_, _ = io.WriteString(w, `{"status":"job","job":{"id":"job-write","operation":"write_file","input":{"path":"`+path+`","content":"changed"},"lease_token":"lease-write","lease_expires_at":"2026-10-26T12:01:00Z","attempt":1}}`)
			return
		}
		if r.URL.Path == "/agent/result" {
			if err := json.NewDecoder(r.Body).Decode(&submitted); err != nil {
				t.Errorf("decode denied write result: %v", err)
			}
			_, _ = io.WriteString(w, `{"accepted":true}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	if err := NewClient(nil).PollOnce(context.Background(), Config{ServerURL: server.URL, HostID: "host-123", Credential: credential}); err != nil {
		t.Fatalf("poll denied write job: %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "preserve" {
		t.Fatalf("file after denied write = %q, error = %v, want unchanged", content, err)
	}
	if !strings.Contains(submitted.Error, "writable-path policy") {
		t.Fatalf("write denial = %q, want explicit writable-path explanation", submitted.Error)
	}
}

func TestPollExecutesTypedRestoreFileJob(t *testing.T) {
	const credential = "ufm_host_private-credential"
	root := t.TempDir()
	path := filepath.Join(root, "settings.conf")
	if err := os.WriteFile(path, []byte("after\n"), 0o640); err != nil {
		t.Fatalf("write current file: %v", err)
	}
	previousContent := strings.Repeat("before", 4000)
	input := hostops.RestoreFileInput{
		Path:            path,
		Previous:        hostops.FileState{Existed: true, Content: []byte(previousContent), Mode: 0o640},
		ExpectedCurrent: hostops.FileFingerprint{Existed: true, SHA256: "7b9a72466d3960eb2aacccfc848939453490db0678bd4725def3f789b891c919", Mode: 0o640},
	}
	inputJSON, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var submitted struct {
		Result hostops.RestoreFileResult `json:"result"`
		Error  string                    `json:"error"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/agent/poll":
			_, _ = fmt.Fprintf(w, `{"status":"job","job":{"id":"job-restore","operation":"restore_file","input":%s,"lease_token":"lease-restore","lease_expires_at":"2026-10-26T12:01:00Z","attempt":1}}`, inputJSON)
		case "/agent/result":
			if err := json.NewDecoder(r.Body).Decode(&submitted); err != nil {
				t.Errorf("decode submitted restore result: %v", err)
			}
			_, _ = io.WriteString(w, `{"accepted":true}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	if err := NewClient(nil).PollOnce(context.Background(), Config{ServerURL: server.URL, HostID: "host-123", Credential: credential, WritablePaths: []string{root}}); err != nil {
		t.Fatalf("poll and execute restore job: %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != previousContent {
		t.Fatalf("restored file = %q, error = %v", content, err)
	}
	if submitted.Error != "" || !submitted.Result.Exact || !submitted.Result.Restored {
		t.Fatalf("submitted restore result = %#v, want exact restored state", submitted)
	}
}

func TestPollExecutesTypedReadFileJobWithinConfiguredBoundary(t *testing.T) {
	const credential = "ufm_host_private-credential"
	allowedPath := t.TempDir()
	filePath := filepath.Join(allowedPath, "settings.conf")
	if err := os.WriteFile(filePath, []byte("mode=safe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var submitted struct {
		JobID      string                 `json:"job_id"`
		LeaseToken string                 `json:"lease_token"`
		Result     hostops.FileReadResult `json:"result"`
		Error      string                 `json:"error"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+credential {
			t.Errorf("agent authorization header = %q, want enrolled credential", r.Header.Get("Authorization"))
		}
		switch r.URL.Path {
		case "/agent/poll":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "job",
				"job": map[string]any{
					"id": "job-456", "operation": hostops.OperationReadFile, "lease_token": "lease-789",
					"lease_expires_at": time.Now().Add(time.Minute), "attempt": 1,
					"input": hostops.PathInput{Path: filePath},
				},
			})
		case "/agent/result":
			if err := json.NewDecoder(r.Body).Decode(&submitted); err != nil {
				t.Errorf("decode submitted file result: %v", err)
			}
			_, _ = io.WriteString(w, `{"accepted":true}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewClient(nil)
	config := Config{ServerURL: server.URL, HostID: "host-123", Credential: credential, AllowedPaths: []string{allowedPath}}
	if err := client.PollOnce(context.Background(), config); err != nil {
		t.Fatalf("poll and execute file job: %v", err)
	}
	if submitted.JobID != "job-456" || submitted.LeaseToken != "lease-789" || submitted.Error != "" {
		t.Fatalf("file job result envelope = %#v", submitted)
	}
	if submitted.Result.Content != "mode=safe\n" || submitted.Result.SizeBytes != int64(len("mode=safe\n")) {
		t.Fatalf("submitted file result = %#v", submitted.Result)
	}
}

func TestPollExecutesTypedListDirectoryJobWithinConfiguredBoundary(t *testing.T) {
	const credential = "ufm_host_private-credential"
	allowedPath := t.TempDir()
	if err := os.WriteFile(filepath.Join(allowedPath, "settings.conf"), []byte("mode=safe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var submitted struct {
		Result hostops.DirectoryListing `json:"result"`
		Error  string                   `json:"error"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/agent/poll":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "job",
				"job": map[string]any{
					"id": "job-directory", "operation": hostops.OperationListDirectory, "lease_token": "lease-directory",
					"lease_expires_at": time.Now().Add(time.Minute), "attempt": 1,
					"input": hostops.PathInput{Path: allowedPath},
				},
			})
		case "/agent/result":
			if err := json.NewDecoder(r.Body).Decode(&submitted); err != nil {
				t.Errorf("decode submitted directory listing: %v", err)
			}
			_, _ = io.WriteString(w, `{"accepted":true}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	config := Config{ServerURL: server.URL, HostID: "host-123", Credential: credential, AllowedPaths: []string{allowedPath}}
	if err := NewClient(nil).PollOnce(context.Background(), config); err != nil {
		t.Fatalf("poll and execute directory-listing job: %v", err)
	}
	if submitted.Error != "" || len(submitted.Result.Entries) != 1 || submitted.Result.Entries[0].Name != "settings.conf" {
		t.Fatalf("submitted directory result = %#v, want settings.conf and no error", submitted)
	}
}

type testAPTCommandRunner struct {
	output []byte
}

func (runner testAPTCommandRunner) Run(context.Context, string, ...string) ([]byte, error) {
	return runner.output, nil
}

func TestPollExecutesTypedPackageSearchJob(t *testing.T) {
	const credential = "ufm_host_private-credential"
	var submitted struct {
		Result hostops.PackageSearchResult `json:"result"`
		Error  string                      `json:"error"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/agent/poll":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "job",
				"job": map[string]any{
					"id": "job-search", "operation": hostops.OperationSearchPackages, "lease_token": "lease-search",
					"lease_expires_at": time.Now().Add(time.Minute), "attempt": 1,
					"input": hostops.PackageSearchInput{Query: "apt", Limit: 1},
				},
			})
		case "/agent/result":
			if err := json.NewDecoder(r.Body).Decode(&submitted); err != nil {
				t.Errorf("decode submitted package search: %v", err)
			}
			_, _ = io.WriteString(w, `{"accepted":true}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewClient(nil)
	client.aptRunner = testAPTCommandRunner{output: []byte("apt - command-line package manager\napt-doc - documentation\n")}
	config := Config{ServerURL: server.URL, HostID: "host-123", Credential: credential}
	if err := client.PollOnce(context.Background(), config); err != nil {
		t.Fatalf("poll and execute package-search job: %v", err)
	}
	if submitted.Error != "" || submitted.Result.Query != "apt" || len(submitted.Result.Packages) != 1 || submitted.Result.Packages[0].Name != "apt" || !submitted.Result.Truncated {
		t.Fatalf("submitted package-search result = %#v, want one apt match and truncated=true", submitted)
	}
}

func TestPollDeniesAPTJobWhenHostPackagePolicyIsMissing(t *testing.T) {
	const credential = "ufm_host_private-credential"
	var submitted struct {
		Result json.RawMessage `json:"result"`
		Error  string          `json:"error"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/agent/poll":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "job",
				"job": map[string]any{
					"id": "job-apt-install", "operation": hostops.OperationAPTInstall, "lease_token": "lease-apt-install",
					"lease_expires_at": time.Now().Add(time.Minute), "attempt": 1,
					"input": hostops.APTActionInput{Packages: []string{"curl"}},
				},
			})
		case "/agent/result":
			if err := json.NewDecoder(r.Body).Decode(&submitted); err != nil {
				t.Errorf("decode submitted APT denial: %v", err)
			}
			_, _ = io.WriteString(w, `{"accepted":true}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	if err := NewClient(nil).PollOnce(context.Background(), Config{ServerURL: server.URL, HostID: "host-123", Credential: credential}); err != nil {
		t.Fatalf("poll and deny unconfigured APT job: %v", err)
	}
	if submitted.Error == "" || len(submitted.Result) != 0 {
		t.Fatalf("APT denial submission = %#v, want generic error and no result", submitted)
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
