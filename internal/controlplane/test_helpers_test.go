package controlplane

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type mcpDiscoveryTestHarness struct {
	ctx     context.Context
	session *mcp.ClientSession
}

func newMCPDiscoveryTestHarness(t *testing.T, allowAPTWrites bool) *mcpDiscoveryTestHarness {
	t.Helper()
	databaseURL := testDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	issuer := newTestIssuer(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve MCP discovery test address: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	config := Config{
		DatabaseURL:           databaseURL,
		OIDCIssuerURL:         issuer.URL(),
		OIDCAudience:          "ubuntu-fleet-manager",
		PublicURL:             "http://" + listener.Addr().String(),
		ListenAddress:         "127.0.0.1:8080",
		FileActionKeyFile:     testEncryptionKeyFile(t),
		AllowAPTWrites:        allowAPTWrites,
		allowInsecureOIDCTest: true,
	}
	service, err := New(ctx, config)
	if err != nil {
		t.Fatalf("start MCP discovery control plane: %v", err)
	}
	t.Cleanup(service.Close)
	httpServer := httptest.NewUnstartedServer(service.Handler())
	httpServer.Listener = listener
	httpServer.Start()
	t.Cleanup(httpServer.Close)

	subject := fmt.Sprintf("mcp-discovery-owner-%d", time.Now().UnixNano())
	session := connectAuthorized(t, ctx, httpServer.URL+"/mcp", issuer.Token(t, subject, config.OIDCAudience))
	t.Cleanup(func() { _ = session.Close() })
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		if _, err := service.store.pool.Exec(cleanupCtx, "DELETE FROM tenants WHERE issuer = $1 AND subject = $2", issuer.URL(), subject); err != nil {
			t.Errorf("clean up MCP discovery test tenant: %v", err)
		}
	})
	return &mcpDiscoveryTestHarness{ctx: ctx, session: session}
}

func testEncryptionKeyFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "file-action-key")
	if err := os.WriteFile(path, bytes.Repeat([]byte{0x4a}, 32), 0o600); err != nil {
		t.Fatalf("write application encryption key fixture: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("set application encryption key fixture mode: %v", err)
	}
	return path
}
