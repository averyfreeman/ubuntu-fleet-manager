package controlplane

import (
	"context"
	"encoding/json"
	"errors"
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
	mux.HandleFunc("POST /agent/enroll", s.enrollAgent)
	mux.HandleFunc("POST /agent/poll", s.pollAgent)
	mux.HandleFunc("POST /agent/result", s.submitAgentResult)
	mux.Handle(s.config.resourceMetadataPath(), auth.ProtectedResourceMetadataHandler(&oauthex.ProtectedResourceMetadata{
		Resource:               s.config.resourceURL(),
		AuthorizationServers:   []string{s.config.OIDCIssuerURL},
		BearerMethodsSupported: []string{"header"},
		ResourceName:           "Ubuntu Fleet Manager MCP",
		ResourceDocumentation:  "https://github.com/averyfreeman/ubuntu-fleet-manager",
	}))

	mcpHandler := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server {
			return mcpserver.New(systeminfo.Collect, s.listHosts, s.createPairingCode, s.removeHost, s.getHostSystemInfo)
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

const (
	systemInfoRequestTimeout      = 90 * time.Second
	jobCancellationCleanupTimeout = 2 * time.Second
)

func (s *Service) listHosts(ctx context.Context, input mcpserver.ListHostsInput) (mcpserver.HostPage, error) {
	tenantID, ok := ctx.Value(personalTenantContextKey{}).(string)
	if !ok || tenantID == "" {
		return mcpserver.HostPage{}, fmt.Errorf("authenticated personal tenant is unavailable")
	}
	return s.store.listHosts(ctx, tenantID, input)
}

func (s *Service) createPairingCode(ctx context.Context) (mcpserver.PairingCode, error) {
	tenantID, ok := ctx.Value(personalTenantContextKey{}).(string)
	if !ok || tenantID == "" {
		return mcpserver.PairingCode{}, fmt.Errorf("authenticated personal tenant is unavailable")
	}
	return s.store.createPairingCode(ctx, tenantID)
}

func (s *Service) removeHost(ctx context.Context, hostID string) (mcpserver.HostRemoval, error) {
	tenantID, ok := ctx.Value(personalTenantContextKey{}).(string)
	if !ok || tenantID == "" {
		return mcpserver.HostRemoval{}, fmt.Errorf("authenticated personal tenant is unavailable")
	}
	return s.store.removeHost(ctx, tenantID, hostID)
}

func (s *Service) getHostSystemInfo(ctx context.Context, input mcpserver.HostSystemInfoInput) (mcpserver.HostSystemInfoResult, error) {
	tenantID, ok := ctx.Value(personalTenantContextKey{}).(string)
	if !ok || tenantID == "" {
		return mcpserver.HostSystemInfoResult{}, fmt.Errorf("authenticated personal tenant is unavailable")
	}
	waitCtx, cancel := context.WithTimeout(ctx, systemInfoRequestTimeout-jobCancellationCleanupTimeout)
	defer cancel()
	target, jobID, err := s.store.enqueueSystemInfo(waitCtx, tenantID, input.HostID)
	if err != nil {
		if errors.Is(waitCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
			return mcpserver.HostSystemInfoResult{}, fmt.Errorf("host did not return system information within 90 seconds")
		}
		return mcpserver.HostSystemInfoResult{}, err
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		state, err := s.store.systemInfoJobState(waitCtx, tenantID, target.HostID, jobID)
		if err != nil {
			s.cancelSystemInfoJob(jobID, tenantID, target.HostID)
			return mcpserver.HostSystemInfoResult{}, fmt.Errorf("read host system-info job: %w", err)
		}
		switch state.Status {
		case "completed":
			var info systeminfo.Info
			if err := json.Unmarshal(state.Result, &info); err != nil {
				s.cancelSystemInfoJob(jobID, tenantID, target.HostID)
				return mcpserver.HostSystemInfoResult{}, fmt.Errorf("host agent returned invalid system information")
			}
			if info.Hostname == "" || info.OS.PrettyName == "" || info.CollectedAt.IsZero() {
				s.cancelSystemInfoJob(jobID, tenantID, target.HostID)
				return mcpserver.HostSystemInfoResult{}, fmt.Errorf("host agent returned incomplete system information")
			}
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Second)
			cleared, err := s.store.clearSystemInfoJobResult(cleanupCtx, tenantID, target.HostID, jobID)
			cleanupCancel()
			if err != nil {
				return mcpserver.HostSystemInfoResult{}, fmt.Errorf("clear completed job snapshot: %w", err)
			}
			if !cleared {
				return mcpserver.HostSystemInfoResult{}, fmt.Errorf("host system-info result was cancelled before delivery")
			}
			if err := ctx.Err(); err != nil {
				return mcpserver.HostSystemInfoResult{}, err
			}
			target.SystemInfo = info
			return target, nil
		case "failed":
			if state.ErrorText == "" {
				return mcpserver.HostSystemInfoResult{}, fmt.Errorf("host system-info job failed")
			}
			return mcpserver.HostSystemInfoResult{}, fmt.Errorf("host system-info job failed: %s", state.ErrorText)
		case "cancelled":
			return mcpserver.HostSystemInfoResult{}, fmt.Errorf("host system-info job was cancelled")
		}

		select {
		case <-waitCtx.Done():
			s.cancelSystemInfoJob(jobID, tenantID, target.HostID)
			if errors.Is(waitCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
				return mcpserver.HostSystemInfoResult{}, fmt.Errorf("host did not return system information within 90 seconds")
			}
			return mcpserver.HostSystemInfoResult{}, waitCtx.Err()
		case <-ticker.C:
		}
	}
}

func (s *Service) cancelSystemInfoJob(jobID, tenantID, hostID string) {
	ctx, cancel := context.WithTimeout(context.Background(), jobCancellationCleanupTimeout)
	defer cancel()
	_ = s.store.cancelSystemInfoJob(ctx, tenantID, hostID, jobID)
}
