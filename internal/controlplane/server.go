package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/averyfreeman/ubuntu-fleet-manager/internal/hostops"
	"github.com/averyfreeman/ubuntu-fleet-manager/internal/mcpserver"
	"github.com/averyfreeman/ubuntu-fleet-manager/internal/securepayload"
	"github.com/averyfreeman/ubuntu-fleet-manager/internal/systeminfo"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

type Service struct {
	config        Config
	store         *postgresStore
	verifier      auth.TokenVerifier
	cleanupCancel context.CancelFunc
	cleanupDone   chan struct{}
}

func New(ctx context.Context, config Config) (*Service, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	key, err := securepayload.LoadKeyFile(config.FileActionKeyFile)
	if err != nil {
		return nil, err
	}
	payloadCipher, err := securepayload.New(key)
	for index := range key {
		key[index] = 0
	}
	if err != nil {
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
	store.cipher = payloadCipher
	cleanupCtx, cleanupCancel := context.WithCancel(context.Background())
	service := &Service{config: config, store: store, verifier: verifier, cleanupCancel: cleanupCancel, cleanupDone: make(chan struct{})}
	go service.runRetentionCleanup(cleanupCtx)
	return service, nil
}

func (s *Service) Close() {
	if s.cleanupCancel != nil {
		s.cleanupCancel()
		<-s.cleanupDone
	}
	s.store.close()
}

func (s *Service) runRetentionCleanup(ctx context.Context) {
	defer close(s.cleanupDone)
	cleanup := func() {
		cleanupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if _, err := s.store.cleanupExpiredApplicationData(cleanupCtx, time.Now().UTC()); err != nil {
			log.Printf("application retention cleanup failed")
		}
	}
	cleanup()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cleanup()
		}
	}
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
			var writeFile mcpserver.HostFileWriter
			var rollbackFile mcpserver.HostFileRollbacker
			var aptTools mcpserver.APTToolHandlers
			if s.config.AllowFileWrites {
				writeFile = s.writeHostFile
				rollbackFile = s.rollbackHostFile
			}
			if s.config.AllowAPTWrites {
				aptTools = mcpserver.APTToolHandlers{
					Update: s.updateHostAPTIndexes, Install: s.installHostPackages, Remove: s.removeHostPackages,
					Upgrade: s.upgradeHostPackages, Rollback: s.rollbackHostAPTAction,
				}
			}
			if s.config.AllowCommandExecution {
				aptTools.ExecuteCommand = s.executeHostCommand
			}
			return mcpserver.New(systeminfo.Collect, s.listHosts, s.createPairingCode, s.removeHost, s.getHostSystemInfo, s.listHostDirectory, s.readHostFile, s.searchHostPackages, writeFile, rollbackFile, aptTools)
		},
		&mcp.StreamableHTTPOptions{
			MaxRequestBodyBytes: 2 << 20,
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
	hostOperationRequestTimeout   = 90 * time.Second
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
	target, encoded, err := s.runHostOperation(ctx, input.HostID, hostops.OperationGetSystemInfo, struct{}{})
	if err != nil {
		return mcpserver.HostSystemInfoResult{}, err
	}
	var info systeminfo.Info
	if err := json.Unmarshal(encoded, &info); err != nil {
		return mcpserver.HostSystemInfoResult{}, fmt.Errorf("host agent returned invalid system information")
	}
	return mcpserver.HostSystemInfoResult{
		HostID: target.HostID, Hostname: target.Hostname, RequestedAt: target.RequestedAt, SystemInfo: info,
	}, nil
}

func (s *Service) listHostDirectory(ctx context.Context, input mcpserver.HostDirectoryInput) (mcpserver.HostDirectoryResult, error) {
	target, encoded, err := s.runHostOperation(ctx, input.HostID, hostops.OperationListDirectory, hostops.PathInput{Path: input.Path})
	if err != nil {
		return mcpserver.HostDirectoryResult{}, err
	}
	var listing hostops.DirectoryListing
	if err := json.Unmarshal(encoded, &listing); err != nil {
		return mcpserver.HostDirectoryResult{}, fmt.Errorf("host agent returned an invalid directory listing")
	}
	return mcpserver.HostDirectoryResult{
		HostID: target.HostID, Hostname: target.Hostname, RequestedAt: target.RequestedAt, Listing: listing,
	}, nil
}

func (s *Service) readHostFile(ctx context.Context, input mcpserver.HostFileInput) (mcpserver.HostFileResult, error) {
	target, encoded, err := s.runHostOperation(ctx, input.HostID, hostops.OperationReadFile, hostops.PathInput{Path: input.Path})
	if err != nil {
		return mcpserver.HostFileResult{}, err
	}
	var result hostops.FileReadResult
	if err := json.Unmarshal(encoded, &result); err != nil {
		return mcpserver.HostFileResult{}, fmt.Errorf("host agent returned an invalid file result")
	}
	return mcpserver.HostFileResult{
		HostID: target.HostID, Hostname: target.Hostname, RequestedAt: target.RequestedAt, File: result,
	}, nil
}

func (s *Service) searchHostPackages(ctx context.Context, input mcpserver.HostPackageSearchInput) (mcpserver.HostPackageSearchResult, error) {
	target, encoded, err := s.runHostOperation(ctx, input.HostID, hostops.OperationSearchPackages, hostops.PackageSearchInput{Query: input.Query, Limit: input.Limit})
	if err != nil {
		return mcpserver.HostPackageSearchResult{}, err
	}
	var result hostops.PackageSearchResult
	if err := json.Unmarshal(encoded, &result); err != nil {
		return mcpserver.HostPackageSearchResult{}, fmt.Errorf("host agent returned an invalid package search result")
	}
	return mcpserver.HostPackageSearchResult{
		HostID: target.HostID, Hostname: target.Hostname, RequestedAt: target.RequestedAt, Search: result,
	}, nil
}

func (s *Service) runHostOperation(ctx context.Context, rawHostID, operation string, input any) (hostJobTarget, json.RawMessage, error) {
	tenantID, ok := ctx.Value(personalTenantContextKey{}).(string)
	if !ok || tenantID == "" {
		return hostJobTarget{}, nil, fmt.Errorf("authenticated personal tenant is unavailable")
	}
	encodedInput, err := json.Marshal(input)
	if err != nil {
		return hostJobTarget{}, nil, fmt.Errorf("encode host operation input: %w", err)
	}
	encodedInput, err = hostops.ValidateJobInput(operation, encodedInput)
	if err != nil {
		return hostJobTarget{}, nil, err
	}
	waitCtx, cancel := context.WithTimeout(ctx, hostOperationRequestTimeout-jobCancellationCleanupTimeout)
	defer cancel()
	target, jobID, err := s.store.enqueueHostJob(waitCtx, tenantID, rawHostID, operation, encodedInput)
	if err != nil {
		if errors.Is(waitCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
			return hostJobTarget{}, nil, fmt.Errorf("host did not return the requested result within 90 seconds")
		}
		return hostJobTarget{}, nil, err
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		state, err := s.store.hostJobState(waitCtx, tenantID, target.HostID, jobID)
		if err != nil {
			s.cancelHostJob(jobID, tenantID, target.HostID)
			return hostJobTarget{}, nil, fmt.Errorf("read host operation job: %w", err)
		}
		switch state.Status {
		case "completed":
			if state.Operation != operation || !validHostOperationResult(state.Operation, json.RawMessage(state.Input), json.RawMessage(state.Result)) {
				s.cancelHostJob(jobID, tenantID, target.HostID)
				return hostJobTarget{}, nil, fmt.Errorf("host agent returned an invalid %s result", operation)
			}
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), jobCancellationCleanupTimeout)
			if operation == hostops.OperationWriteFile {
				var writeInput hostops.WriteFileInput
				var writeResult hostops.WriteFileResult
				if err := json.Unmarshal(state.Input, &writeInput); err != nil {
					cleanupCancel()
					return hostJobTarget{}, nil, fmt.Errorf("read completed file write input")
				}
				if err := json.Unmarshal(state.Result, &writeResult); err != nil {
					cleanupCancel()
					return hostJobTarget{}, nil, fmt.Errorf("read completed file write result")
				}
				expiresAt, persistErr := s.store.persistFileActionAndClearJob(cleanupCtx, tenantID, target.HostID, jobID, fileActionPayload{
					Path: writeResult.Path, Previous: writeResult.Previous, ExpectedCurrent: writeResult.Current,
				})
				cleanupCancel()
				if persistErr != nil {
					return hostJobTarget{}, nil, fmt.Errorf("persist encrypted file reversal data: %w", persistErr)
				}
				target.ActionID = jobID
				target.ExpiresAt = expiresAt
			} else if operation == hostops.OperationAPTUpdate || operation == hostops.OperationAPTInstall || operation == hostops.OperationAPTRemove || operation == hostops.OperationAPTUpgrade {
				var requestedPackages []string
				if operation != hostops.OperationAPTUpdate {
					var actionInput hostops.APTActionInput
					if err := json.Unmarshal(state.Input, &actionInput); err != nil {
						cleanupCancel()
						return hostJobTarget{}, nil, fmt.Errorf("read completed APT action input")
					}
					requestedPackages = actionInput.Packages
				}
				var actionResult hostops.APTActionResult
				if err := json.Unmarshal(state.Result, &actionResult); err != nil {
					cleanupCancel()
					return hostJobTarget{}, nil, fmt.Errorf("read completed APT action result")
				}
				expiresAt, persistErr := s.store.persistAPTActionAndClearJob(cleanupCtx, tenantID, target.HostID, jobID, aptActionPayload{
					Operation: operation, RequestedPackages: requestedPackages,
					Previous: actionResult.Before, ExpectedCurrent: actionResult.After,
					Outcome: actionResult.Outcome, Reason: actionResult.Reason, RollbackAvailable: actionResult.RollbackAvailable,
				})
				cleanupCancel()
				if persistErr != nil {
					return hostJobTarget{}, nil, fmt.Errorf("persist encrypted APT audit data: %w", persistErr)
				}
				target.ActionID = jobID
				target.ExpiresAt = expiresAt
			} else {
				cleared, clearErr := s.store.clearHostJobResult(cleanupCtx, tenantID, target.HostID, jobID)
				cleanupCancel()
				if clearErr != nil {
					return hostJobTarget{}, nil, fmt.Errorf("clear completed host operation result: %w", clearErr)
				}
				if !cleared {
					return hostJobTarget{}, nil, fmt.Errorf("host operation result was cancelled before delivery")
				}
			}
			if err := ctx.Err(); err != nil {
				return hostJobTarget{}, nil, err
			}
			return target, json.RawMessage(state.Result), nil
		case "failed":
			if state.ErrorText == "" {
				return hostJobTarget{}, nil, fmt.Errorf("host %s job failed", operation)
			}
			return hostJobTarget{}, nil, fmt.Errorf("host %s job failed: %s", operation, state.ErrorText)
		case "cancelled":
			return hostJobTarget{}, nil, fmt.Errorf("host %s job was cancelled", operation)
		}

		select {
		case <-waitCtx.Done():
			s.cancelHostJob(jobID, tenantID, target.HostID)
			if errors.Is(waitCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
				return hostJobTarget{}, nil, fmt.Errorf("host did not return the requested result within 90 seconds")
			}
			return hostJobTarget{}, nil, waitCtx.Err()
		case <-ticker.C:
		}
	}
}

func (s *Service) cancelHostJob(jobID, tenantID, hostID string) {
	ctx, cancel := context.WithTimeout(context.Background(), jobCancellationCleanupTimeout)
	defer cancel()
	_ = s.store.cancelHostJob(ctx, tenantID, hostID, jobID)
}
