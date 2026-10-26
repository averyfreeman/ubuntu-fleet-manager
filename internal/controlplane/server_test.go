package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

func TestConfigRequiresSecureProviderAndCompleteDeploymentSettings(t *testing.T) {
	base := Config{
		DatabaseURL:       "postgres://ufm:secret@localhost:5432/ufm?sslmode=disable",
		OIDCIssuerURL:     "https://identity.example.test/issuer",
		OIDCAudience:      "ubuntu-fleet-manager",
		PublicURL:         "https://fleet.example.test",
		ListenAddress:     ":8080",
		FileActionKeyFile: testEncryptionKeyFile(t),
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid configuration rejected: %v", err)
	}

	insecure := base
	insecure.OIDCIssuerURL = "http://identity.example.test/issuer"
	if err := insecure.Validate(); err == nil {
		t.Fatal("insecure OIDC issuer was accepted")
	}

	missingAudience := base
	missingAudience.OIDCAudience = ""
	if err := missingAudience.Validate(); err == nil {
		t.Fatal("configuration without an OIDC audience was accepted")
	}

	invalidPort := base
	invalidPort.ListenAddress = ":not-a-port"
	if err := invalidPort.Validate(); err == nil {
		t.Fatal("configuration with a nonnumeric listen port was accepted")
	}
}

func TestConfigRequiresAbsoluteApplicationEncryptionKeyFile(t *testing.T) {
	config := Config{
		DatabaseURL:   "postgres://ufm:secret@localhost:5432/ufm?sslmode=disable",
		OIDCIssuerURL: "https://identity.example.test/issuer",
		OIDCAudience:  "ubuntu-fleet-manager",
		PublicURL:     "https://fleet.example.test",
		ListenAddress: ":8080",
	}
	if err := config.Validate(); err == nil {
		t.Fatal("configuration without an application encryption key file was accepted")
	}
	config.FileActionKeyFile = "relative-key"
	if err := config.Validate(); err == nil {
		t.Fatal("configuration with a relative encryption key path was accepted")
	}
}

func TestLoadConfigParsesExplicitFileWritePolicy(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://ufm:secret@localhost:5432/ufm?sslmode=disable")
	t.Setenv("OIDC_ISSUER_URL", "https://identity.example.test/issuer")
	t.Setenv("OIDC_AUDIENCE", "ubuntu-fleet-manager")
	t.Setenv("PUBLIC_URL", "https://fleet.example.test")
	t.Setenv("LISTEN_ADDR", ":8080")
	t.Setenv("FILE_ACTION_KEY_FILE", testEncryptionKeyFile(t))
	t.Setenv("ALLOW_FILE_WRITES", "false")
	config, err := LoadConfigFromEnv()
	if err != nil || config.AllowFileWrites {
		t.Fatalf("default denied write policy = %v, error=%v", config.AllowFileWrites, err)
	}
	t.Setenv("ALLOW_FILE_WRITES", "true")
	config, err = LoadConfigFromEnv()
	if err != nil || !config.AllowFileWrites {
		t.Fatalf("enabled write policy = %v, error=%v", config.AllowFileWrites, err)
	}
	t.Setenv("ALLOW_FILE_WRITES", "sometimes")
	if _, err := LoadConfigFromEnv(); err == nil {
		t.Fatal("invalid file-write approval policy was accepted")
	}
}

func TestLoadConfigParsesExplicitAPTWritePolicy(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://ufm:secret@localhost:5432/ufm?sslmode=disable")
	t.Setenv("OIDC_ISSUER_URL", "https://identity.example.test/issuer")
	t.Setenv("OIDC_AUDIENCE", "ubuntu-fleet-manager")
	t.Setenv("PUBLIC_URL", "https://fleet.example.test")
	t.Setenv("LISTEN_ADDR", ":8080")
	t.Setenv("FILE_ACTION_KEY_FILE", testEncryptionKeyFile(t))
	t.Setenv("ALLOW_APT_WRITES", "false")
	config, err := LoadConfigFromEnv()
	if err != nil || config.AllowAPTWrites {
		t.Fatalf("default denied APT policy = %v, error=%v", config.AllowAPTWrites, err)
	}
	t.Setenv("ALLOW_APT_WRITES", "true")
	config, err = LoadConfigFromEnv()
	if err != nil || !config.AllowAPTWrites {
		t.Fatalf("enabled APT policy = %v, error=%v", config.AllowAPTWrites, err)
	}
	t.Setenv("ALLOW_APT_WRITES", "yes")
	if _, err := LoadConfigFromEnv(); err == nil {
		t.Fatal("invalid APT write policy was accepted")
	}
}

func TestLoadConfigParsesExplicitCommandExecutionPolicy(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://ufm:secret@localhost:5432/ufm?sslmode=disable")
	t.Setenv("OIDC_ISSUER_URL", "https://identity.example.test/issuer")
	t.Setenv("OIDC_AUDIENCE", "ubuntu-fleet-manager")
	t.Setenv("PUBLIC_URL", "https://fleet.example.test")
	t.Setenv("LISTEN_ADDR", ":8080")
	t.Setenv("FILE_ACTION_KEY_FILE", testEncryptionKeyFile(t))
	t.Setenv("ALLOW_COMMAND_EXECUTION", "false")
	config, err := LoadConfigFromEnv()
	if err != nil || config.AllowCommandExecution {
		t.Fatalf("default denied command policy = %v, error=%v", config.AllowCommandExecution, err)
	}
	t.Setenv("ALLOW_COMMAND_EXECUTION", "true")
	config, err = LoadConfigFromEnv()
	if err != nil || !config.AllowCommandExecution {
		t.Fatalf("enabled command policy = %v, error=%v", config.AllowCommandExecution, err)
	}
	t.Setenv("ALLOW_COMMAND_EXECUTION", "yes")
	if _, err := LoadConfigFromEnv(); err == nil {
		t.Fatal("invalid command execution policy was accepted")
	}
}

func TestNewFailsClosedWhenApplicationEncryptionKeyIsMissing(t *testing.T) {
	config := Config{
		DatabaseURL:       "postgres://ufm:secret@localhost:5432/ufm?sslmode=disable",
		OIDCIssuerURL:     "https://identity.example.test/issuer",
		OIDCAudience:      "ubuntu-fleet-manager",
		PublicURL:         "https://fleet.example.test",
		ListenAddress:     ":8080",
		FileActionKeyFile: filepath.Join(t.TempDir(), "missing-key"),
	}
	if _, err := New(context.Background(), config); err == nil || !strings.Contains(err.Error(), "encryption key file") {
		t.Fatalf("New without key error = %v, want fail-closed key error", err)
	}
}

func TestControlPlaneAuthenticatesAndIsolatesHostInventory(t *testing.T) {
	databaseURL := testDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	issuer := newTestIssuer(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test HTTP address: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	publicURL := "http://" + listener.Addr().String()
	config := Config{
		DatabaseURL:           databaseURL,
		OIDCIssuerURL:         issuer.URL(),
		OIDCAudience:          "ubuntu-fleet-manager",
		PublicURL:             publicURL,
		ListenAddress:         "127.0.0.1:8080",
		FileActionKeyFile:     testEncryptionKeyFile(t),
		allowInsecureOIDCTest: true,
	}
	service, err := New(ctx, config)
	if err != nil {
		t.Fatalf("start control plane: %v", err)
	}
	defer service.Close()

	if err := service.store.ping(ctx); err != nil {
		t.Fatalf("database did not become ready: %v", err)
	}
	var migrationCount int
	if err := service.store.pool.QueryRow(ctx, "SELECT count(*) FROM schema_migrations").Scan(&migrationCount); err != nil {
		t.Fatalf("read migration records: %v", err)
	}
	if migrationCount == 0 {
		t.Fatal("startup did not apply a schema migration")
	}
	restarted, err := New(ctx, config)
	if err != nil {
		t.Fatalf("repeated startup failed after migrations were applied: %v", err)
	}
	restarted.Close()

	httpServer := httptest.NewUnstartedServer(service.Handler())
	httpServer.Listener = listener
	httpServer.Start()
	defer httpServer.Close()

	readyResponse, err := http.Get(httpServer.URL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	readyResponse.Body.Close()
	if readyResponse.StatusCode != http.StatusOK {
		t.Fatalf("/readyz status = %d, want 200", readyResponse.StatusCode)
	}

	metadataURL := httpServer.URL + "/.well-known/oauth-protected-resource/mcp"
	metadataResponse, err := http.Get(metadataURL)
	if err != nil {
		t.Fatalf("GET protected resource metadata: %v", err)
	}
	defer metadataResponse.Body.Close()
	if metadataResponse.StatusCode != http.StatusOK {
		t.Fatalf("protected resource metadata status = %d, want 200", metadataResponse.StatusCode)
	}
	var metadata oauthex.ProtectedResourceMetadata
	if err := json.NewDecoder(metadataResponse.Body).Decode(&metadata); err != nil {
		t.Fatalf("decode protected resource metadata: %v", err)
	}
	if metadata.Resource != httpServer.URL+"/mcp" {
		t.Errorf("protected resource = %q, want %q", metadata.Resource, httpServer.URL+"/mcp")
	}
	if len(metadata.AuthorizationServers) != 1 || metadata.AuthorizationServers[0] != issuer.URL() {
		t.Errorf("authorization servers = %v, want [%q]", metadata.AuthorizationServers, issuer.URL())
	}

	unauthorizedResponse, err := http.Get(httpServer.URL + "/mcp")
	if err != nil {
		t.Fatalf("unauthenticated MCP request: %v", err)
	}
	unauthorizedResponse.Body.Close()
	if unauthorizedResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated MCP status = %d, want 401", unauthorizedResponse.StatusCode)
	}
	if !strings.Contains(unauthorizedResponse.Header.Get("WWW-Authenticate"), metadataURL) {
		t.Errorf("WWW-Authenticate = %q, want resource metadata URL %q", unauthorizedResponse.Header.Get("WWW-Authenticate"), metadataURL)
	}

	badTokenResponse, err := getWithBearer(httpServer.URL+"/mcp", "not-a-valid-token")
	if err != nil {
		t.Fatalf("invalid bearer request: %v", err)
	}
	badTokenResponse.Body.Close()
	if badTokenResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("invalid bearer status = %d, want 401", badTokenResponse.StatusCode)
	}

	subjectA := fmt.Sprintf("operator-a-%d", time.Now().UnixNano())
	subjectB := fmt.Sprintf("operator-b-%d", time.Now().UnixNano())
	subjectC := fmt.Sprintf("operator-c-%d", time.Now().UnixNano())
	wrongAudienceResponse, err := getWithBearer(httpServer.URL+"/mcp", issuer.Token(t, subjectA, "another-resource"))
	if err != nil {
		t.Fatalf("wrong-audience bearer request: %v", err)
	}
	wrongAudienceResponse.Body.Close()
	if wrongAudienceResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong-audience bearer status = %d, want 401", wrongAudienceResponse.StatusCode)
	}

	tenantA, err := service.store.ensureTenant(ctx, issuer.URL(), subjectA)
	if err != nil {
		t.Fatalf("create first personal tenant: %v", err)
	}
	tenantB, err := service.store.ensureTenant(ctx, issuer.URL(), subjectB)
	if err != nil {
		t.Fatalf("create second personal tenant: %v", err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = service.store.pool.Exec(cleanupCtx, "DELETE FROM tenants WHERE issuer = $1 AND (subject = $2 OR subject = $3 OR subject = $4)", issuer.URL(), subjectA, subjectB, subjectC)
	}()
	if err := insertTestHost(ctx, service.store, tenantA, "alpha.example.test", "Ubuntu 26.04 LTS"); err != nil {
		t.Fatalf("insert first tenant host: %v", err)
	}
	if err := insertTestHost(ctx, service.store, tenantA, "alpha-second.example.test", "Ubuntu 26.04 LTS"); err != nil {
		t.Fatalf("insert second host for first tenant: %v", err)
	}
	if err := insertTestHost(ctx, service.store, tenantB, "bravo.example.test", "Ubuntu 26.04 LTS"); err != nil {
		t.Fatalf("insert second tenant host: %v", err)
	}

	tokenA := issuer.Token(t, subjectA, "ubuntu-fleet-manager")
	tokenB := issuer.Token(t, subjectB, "ubuntu-fleet-manager")
	tokenC := issuer.Token(t, subjectC, "ubuntu-fleet-manager")
	sessionA := connectAuthorized(t, ctx, httpServer.URL+"/mcp", tokenA)
	defer sessionA.Close()
	sessionB := connectAuthorized(t, ctx, httpServer.URL+"/mcp", tokenB)
	defer sessionB.Close()
	sessionC := connectAuthorized(t, ctx, httpServer.URL+"/mcp", tokenC)
	defer sessionC.Close()

	for _, session := range []*mcp.ClientSession{sessionA, sessionB} {
		tools, err := session.ListTools(ctx, nil)
		if err != nil {
			t.Fatalf("list remote tools: %v", err)
		}
		if !hasTool(tools.Tools, "get_system_info") || !hasTool(tools.Tools, "list_hosts") {
			t.Errorf("remote tools = %v, want get_system_info and list_hosts", toolNames(tools.Tools))
		}
	}

	callHostPage := func(session *mcp.ClientSession, arguments map[string]any) ([]string, string) {
		t.Helper()
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "list_hosts", Arguments: arguments})
		if err != nil {
			t.Fatalf("call list_hosts: %v", err)
		}
		if result.IsError {
			t.Fatalf("list_hosts returned tool error: %v", result.Content)
		}
		payload, err := json.Marshal(result.StructuredContent)
		if err != nil {
			t.Fatalf("marshal list_hosts result: %v", err)
		}
		var page struct {
			Hosts []struct {
				Hostname string `json:"hostname"`
			} `json:"hosts"`
			NextCursor string `json:"next_cursor"`
		}
		if err := json.Unmarshal(payload, &page); err != nil {
			t.Fatalf("decode list_hosts result: %v", err)
		}
		hostnames := make([]string, 0, len(page.Hosts))
		for _, host := range page.Hosts {
			hostnames = append(hostnames, host.Hostname)
		}
		return hostnames, page.NextCursor
	}

	pageA1, cursorA := callHostPage(sessionA, map[string]any{"limit": 1})
	if len(pageA1) != 1 || cursorA == "" {
		t.Fatalf("first tenant page = %v, cursor %q; want one host and a next cursor", pageA1, cursorA)
	}
	pageA2, cursorA2 := callHostPage(sessionA, map[string]any{"limit": 1, "cursor": cursorA})
	if len(pageA2) != 1 || cursorA2 != "" {
		t.Fatalf("second tenant page = %v, cursor %q; want one host and no next cursor", pageA2, cursorA2)
	}
	gotA := map[string]bool{pageA1[0]: true, pageA2[0]: true}
	if len(gotA) != 2 || !gotA["alpha.example.test"] || !gotA["alpha-second.example.test"] {
		t.Fatalf("first tenant pages contain %v, want both alpha hosts", gotA)
	}
	pageB, cursorB := callHostPage(sessionB, map[string]any{})
	if len(pageB) != 1 || pageB[0] != "bravo.example.test" || cursorB != "" {
		t.Fatalf("second tenant inventory = %v, cursor %q; want only bravo host", pageB, cursorB)
	}
	pageC, cursorC := callHostPage(sessionC, map[string]any{})
	if len(pageC) != 0 || cursorC != "" {
		t.Fatalf("new operator inventory = %v, cursor %q; want empty", pageC, cursorC)
	}
	var tenantCCreated int
	if err := service.store.pool.QueryRow(ctx, "SELECT count(*) FROM tenants WHERE issuer = $1 AND subject = $2", issuer.URL(), subjectC).Scan(&tenantCCreated); err != nil {
		t.Fatalf("check automatic personal tenant creation: %v", err)
	}
	if tenantCCreated != 1 {
		t.Fatalf("new authenticated operator has %d tenants, want 1", tenantCCreated)
	}
	invalidPage, err := sessionA.CallTool(ctx, &mcp.CallToolParams{Name: "list_hosts", Arguments: map[string]any{"limit": 201}})
	if err != nil {
		t.Fatalf("call list_hosts with invalid limit: %v", err)
	}
	if !invalidPage.IsError {
		t.Fatal("list_hosts accepted a limit above the configured maximum")
	}
	infoResult, err := sessionA.CallTool(ctx, &mcp.CallToolParams{Name: "get_system_info", Arguments: map[string]any{}})
	if err != nil {
		t.Fatalf("call remote get_system_info: %v", err)
	}
	if infoResult.IsError || infoResult.StructuredContent == nil {
		t.Fatalf("remote get_system_info result = %#v, want structured data", infoResult)
	}
}

func testDatabaseURL(t *testing.T) string {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("UFM_TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("UFM_TEST_DATABASE_URL is not set; PostgreSQL integration test skipped")
	}
	return databaseURL
}

func connectAuthorized(t *testing.T, ctx context.Context, endpoint, token string) *mcp.ClientSession {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "control-plane-test", Version: "test"}, nil)
	transport := &mcp.StreamableClientTransport{
		Endpoint: endpoint,
		HTTPClient: &http.Client{Transport: bearerRoundTripper{
			base:  http.DefaultTransport,
			token: token,
		}},
		DisableStandaloneSSE: true,
		MaxRetries:           -1,
	}
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("connect authenticated MCP client: %v", err)
	}
	return session
}

func getWithBearer(endpoint, token string) (*http.Response, error) {
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	return http.DefaultClient.Do(request)
}

type bearerRoundTripper struct {
	base  http.RoundTripper
	token string
}

func (t bearerRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	copy := request.Clone(request.Context())
	copy.Header = request.Header.Clone()
	copy.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(copy)
}

type testIssuer struct {
	server  *httptest.Server
	private *rsa.PrivateKey
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate OIDC test issuer key: %v", err)
	}
	issuer := &testIssuer{private: private}
	mux := http.NewServeMux()
	issuer.server = httptest.NewUnstartedServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                issuer.URL(),
			"jwks_uri":                              issuer.URL() + "/jwks",
			"authorization_endpoint":                issuer.URL() + "/authorize",
			"token_endpoint":                        issuer.URL() + "/token",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		public := private.PublicKey
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": "ufm-integration-test-key",
			"n":   base64.RawURLEncoding.EncodeToString(public.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes()),
		}}})
	})
	issuer.server.Start()
	t.Cleanup(issuer.server.Close)
	return issuer
}

func insertTestHost(ctx context.Context, store *postgresStore, tenantID, hostname, osPrettyName string) error {
	_, err := store.pool.Exec(ctx, "INSERT INTO hosts (tenant_id, hostname, os_pretty_name) VALUES ($1, $2, $3)", tenantID, hostname, osPrettyName)
	return err
}

func (i *testIssuer) URL() string {
	return i.server.URL
}

func (i *testIssuer) Token(t *testing.T, subject, audience string) string {
	t.Helper()
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   i.URL(),
		"sub":   subject,
		"aud":   audience,
		"iat":   now.Unix(),
		"exp":   now.Add(5 * time.Minute).Unix(),
		"scope": "openid",
	})
	token.Header["kid"] = "ufm-integration-test-key"
	encoded, err := token.SignedString(i.private)
	if err != nil {
		t.Fatalf("sign OIDC integration test token: %v", err)
	}
	return encoded
}

func hasTool(tools []*mcp.Tool, name string) bool {
	for _, tool := range tools {
		if tool.Name == name {
			return true
		}
	}
	return false
}

func toolNames(tools []*mcp.Tool) []string {
	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		names = append(names, tool.Name)
	}
	return names
}
