package controlplane

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/averyfreeman/ubuntu-fleet-manager/internal/mcpserver"
	"github.com/averyfreeman/ubuntu-fleet-manager/internal/systeminfo"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

type Service struct {
	config   Config
	store    *postgresStore
	verifier auth.TokenVerifier
}

func New(ctx context.Context, config Config) (*Service, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	verifier, err := newOIDCTokenVerifier(ctx, config)
	if err != nil {
		return nil, err
	}
	storeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	store, err := openPostgresStore(storeCtx, config.DatabaseURL)
	if err != nil {
		return nil, err
	}
	return &Service{config: config, store: store, verifier: verifier}, nil
}

func (s *Service) Close() {
	s.store.close()
}

func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("live\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := s.store.ping(ctx); err != nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready\n"))
	})
	mux.Handle(s.config.resourceMetadataPath(), auth.ProtectedResourceMetadataHandler(&oauthex.ProtectedResourceMetadata{
		Resource:               s.config.resourceURL(),
		AuthorizationServers:   []string{s.config.OIDCIssuerURL},
		BearerMethodsSupported: []string{"header"},
		ResourceName:           "Ubuntu Fleet Manager MCP",
		ResourceDocumentation:  "https://github.com/averyfreeman/ubuntu-fleet-manager",
	}))

	mcpHandler := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server {
			return mcpserver.New(systeminfo.Collect, s.listHosts)
		},
		&mcp.StreamableHTTPOptions{
			MaxRequestBodyBytes: 1 << 20,
			SessionTimeout:      15 * time.Minute,
		},
	)
	authorized := auth.RequireBearerToken(s.verifier, &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: s.config.resourceMetadataURL(),
	})(s.ensurePersonalTenant(mcpHandler))
	mux.Handle("/mcp", authorized)
	return mux
}

func (s *Service) ensurePersonalTenant(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenInfo := auth.TokenInfoFromContext(r.Context())
		if tokenInfo == nil || tokenInfo.Extra == nil {
			http.Error(w, "authentication context is unavailable", http.StatusUnauthorized)
			return
		}
		issuer, issuerOK := tokenInfo.Extra["issuer"].(string)
		subject, subjectOK := tokenInfo.Extra["subject"].(string)
		if !issuerOK || !subjectOK || issuer == "" || subject == "" {
			http.Error(w, "authentication context is incomplete", http.StatusUnauthorized)
			return
		}
		tenantID, err := s.store.ensureTenant(r.Context(), issuer, subject)
		if err != nil {
			http.Error(w, "personal tenant is unavailable", http.StatusServiceUnavailable)
			return
		}
		ctx := context.WithValue(r.Context(), personalTenantContextKey{}, tenantID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type personalTenantContextKey struct{}

func (s *Service) listHosts(ctx context.Context, input mcpserver.ListHostsInput) (mcpserver.HostPage, error) {
	tenantID, ok := ctx.Value(personalTenantContextKey{}).(string)
	if !ok || tenantID == "" {
		return mcpserver.HostPage{}, fmt.Errorf("authenticated personal tenant is unavailable")
	}
	return s.store.listHosts(ctx, tenantID, input)
}
