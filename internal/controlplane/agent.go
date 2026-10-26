package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/averyfreeman/ubuntu-fleet-manager/internal/hostops"
	"github.com/averyfreeman/ubuntu-fleet-manager/internal/systeminfo"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var errInvalidPairingCode = errors.New("pairing code is invalid, expired, or already used")
var errInvalidHostCredential = errors.New("host credential is invalid or revoked")
var errHostAlreadyEnrolled = errors.New("a host with this name is already active in the pairing-code tenant")
var errInvalidHostJobResult = errors.New("host operation result is invalid")

const maxAgentRequestBytes = 16 << 10
const maxAgentResultRequestBytes = 4 << 20

type agentEnrollmentRequest struct {
	PairingCode  string `json:"pairing_code"`
	Hostname     string `json:"hostname"`
	OSPrettyName string `json:"os_pretty_name"`
}

type agentEnrollmentResponse struct {
	HostID     string `json:"host_id"`
	Credential string `json:"credential"`
}

type agentPollResponse struct {
	Status string        `json:"status"`
	Job    *hostJobLease `json:"job,omitempty"`
}

type agentResultRequest struct {
	JobID      string          `json:"job_id"`
	LeaseToken string          `json:"lease_token"`
	Result     json.RawMessage `json:"result,omitempty"`
	Error      string          `json:"error,omitempty"`
}

type agentResultResponse struct {
	Accepted bool `json:"accepted"`
}

func newOpaqueSecret(prefix string) (string, []byte, error) {
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", nil, fmt.Errorf("generate secret: %w", err)
	}
	secret := prefix + base64.RawURLEncoding.EncodeToString(randomBytes)
	hash := sha256.Sum256([]byte(secret))
	return secret, hash[:], nil
}

func (s *Service) enrollAgent(w http.ResponseWriter, r *http.Request) {
	var input agentEnrollmentRequest
	if err := decodeAgentJSON(w, r, &input); err != nil {
		http.Error(w, "invalid enrollment request", http.StatusBadRequest)
		return
	}
	if !validAgentText(input.Hostname, 253) || !validAgentText(input.OSPrettyName, 200) {
		http.Error(w, "invalid enrollment request", http.StatusBadRequest)
		return
	}
	if !validOpaqueSecretFormat(input.PairingCode, "ufm_pair_") {
		http.Error(w, "pairing code is invalid, expired, or already used", http.StatusUnauthorized)
		return
	}
	enrollment, err := s.store.enrollHost(r.Context(), input)
	if errors.Is(err, errInvalidPairingCode) {
		http.Error(w, "pairing code is invalid, expired, or already used", http.StatusUnauthorized)
		return
	}
	if errors.Is(err, errHostAlreadyEnrolled) {
		http.Error(w, "a host with this name is already active in the pairing-code tenant", http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, "host enrollment failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(enrollment)
}

func (s *Service) pollAgent(w http.ResponseWriter, r *http.Request) {
	var input map[string]json.RawMessage
	if err := decodeAgentJSON(w, r, &input); err != nil {
		http.Error(w, "invalid agent poll request", http.StatusBadRequest)
		return
	}
	if input == nil || len(input) != 0 {
		http.Error(w, "invalid agent poll request", http.StatusBadRequest)
		return
	}
	credential, ok := bearerCredential(r)
	if !ok {
		http.Error(w, "host credential is invalid or revoked", http.StatusUnauthorized)
		return
	}
	job, err := s.store.claimNextHostJob(r.Context(), credential)
	if errors.Is(err, errInvalidHostCredential) {
		http.Error(w, "host credential is invalid or revoked", http.StatusUnauthorized)
		return
	} else if err != nil {
		http.Error(w, "host poll failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if job == nil {
		_ = json.NewEncoder(w).Encode(agentPollResponse{Status: "idle"})
		return
	}
	_ = json.NewEncoder(w).Encode(agentPollResponse{Status: "job", Job: job})
}

func (s *Service) submitAgentResult(w http.ResponseWriter, r *http.Request) {
	var input agentResultRequest
	if err := decodeAgentJSONLimit(w, r, &input, maxAgentResultRequestBytes); err != nil {
		http.Error(w, "invalid agent result request", http.StatusBadRequest)
		return
	}
	if input.JobID == "" || input.LeaseToken == "" || (input.Error == "") == (len(input.Result) == 0) {
		http.Error(w, "result request must contain either a typed host operation result or an error", http.StatusBadRequest)
		return
	}
	if input.Error != "" {
		if !validAgentText(input.Error, 4096) {
			http.Error(w, "agent error is invalid", http.StatusBadRequest)
			return
		}
	}
	credential, ok := bearerCredential(r)
	if !ok {
		http.Error(w, "host credential is invalid or revoked", http.StatusUnauthorized)
		return
	}
	err := s.store.completeHostJob(r.Context(), credential, input.JobID, input.LeaseToken, input.Result, input.Error)
	if errors.Is(err, errInvalidHostCredential) {
		http.Error(w, "host credential is invalid or revoked", http.StatusUnauthorized)
		return
	}
	if errors.Is(err, errInvalidJobLease) {
		http.Error(w, "job lease is invalid, expired, or no longer current", http.StatusConflict)
		return
	}
	if errors.Is(err, errInvalidHostJobResult) {
		http.Error(w, "host operation result is invalid", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, "host job result could not be stored", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(agentResultResponse{Accepted: true})
}

func decodeAgentJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	return decodeAgentJSONLimit(w, r, destination, maxAgentRequestBytes)
}

func decodeAgentJSONLimit(w http.ResponseWriter, r *http.Request, destination any, maxBytes int64) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		return fmt.Errorf("content type must be application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("request must contain one JSON value")
	}
	return nil
}

func validAgentText(value string, maxBytes int) bool {
	if value == "" || len(value) > maxBytes || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func bearerCredential(r *http.Request) (string, bool) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", false
	}
	scheme, credential, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || credential == "" || strings.ContainsAny(credential, " \t\r\n") {
		return "", false
	}
	if !validOpaqueSecretFormat(credential, "ufm_host_") {
		return "", false
	}
	return credential, true
}

func validOpaqueSecretFormat(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	randomMaterial, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, prefix))
	return err == nil && len(randomMaterial) == 32
}

func validSystemInfoResult(encoded json.RawMessage) bool {
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	var info systeminfo.Info
	if err := decoder.Decode(&info); err != nil {
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return false
	}
	return info.OS.ID != "" && info.OS.PrettyName != "" && info.OS.VersionID != "" &&
		info.Hostname != "" && info.Kernel.Name != "" && info.Kernel.Release != "" &&
		info.Architecture != "" && info.Memory.TotalBytes > 0 && info.Memory.AvailableBytes <= info.Memory.TotalBytes &&
		info.RootFilesystem.TotalBytes > 0 && info.RootFilesystem.UsedBytes <= info.RootFilesystem.TotalBytes &&
		info.RootFilesystem.FreeBytes <= info.RootFilesystem.TotalBytes &&
		info.RootFilesystem.AvailableBytes <= info.RootFilesystem.FreeBytes &&
		!info.CollectedAt.IsZero()
}

func validHostOperationResult(operation string, input, result json.RawMessage) bool {
	if len(result) > maxAgentResultRequestBytes {
		return false
	}
	if operation == hostops.OperationGetSystemInfo {
		return validSystemInfoResult(result)
	}
	return hostops.ValidateJobResult(operation, input, result) == nil
}

func (s *postgresStore) enrollHost(ctx context.Context, input agentEnrollmentRequest) (agentEnrollmentResponse, error) {
	credential, credentialHash, err := newOpaqueSecret("ufm_host_")
	if err != nil {
		return agentEnrollmentResponse{}, err
	}
	pairingCodeHash := sha256.Sum256([]byte(input.PairingCode))
	transaction, err := s.pool.Begin(ctx)
	if err != nil {
		return agentEnrollmentResponse{}, fmt.Errorf("begin host enrollment: %w", err)
	}
	defer func() {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = transaction.Rollback(rollbackCtx)
	}()

	var tenantID string
	err = transaction.QueryRow(ctx, `
		UPDATE pairing_codes
		SET consumed_at = now()
		WHERE code_hash = $1 AND consumed_at IS NULL AND expires_at > now()
		RETURNING tenant_id::text
	`, pairingCodeHash[:]).Scan(&tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return agentEnrollmentResponse{}, errInvalidPairingCode
	}
	if err != nil {
		return agentEnrollmentResponse{}, fmt.Errorf("consume pairing code: %w", err)
	}

	var hostID string
	err = transaction.QueryRow(ctx, `
		INSERT INTO hosts (tenant_id, hostname, os_pretty_name)
		VALUES ($1::uuid, $2, $3)
		RETURNING id::text
	`, tenantID, input.Hostname, input.OSPrettyName).Scan(&hostID)
	if err != nil {
		var databaseError *pgconn.PgError
		if errors.As(err, &databaseError) && databaseError.Code == "23505" && databaseError.ConstraintName == "hosts_tenant_hostname_active_unique" {
			return agentEnrollmentResponse{}, errHostAlreadyEnrolled
		}
		return agentEnrollmentResponse{}, fmt.Errorf("create enrolled host: %w", err)
	}
	if _, err := transaction.Exec(ctx, `
		INSERT INTO host_credentials (host_id, credential_hash)
		VALUES ($1::uuid, $2)
	`, hostID, credentialHash); err != nil {
		return agentEnrollmentResponse{}, fmt.Errorf("store host credential verifier: %w", err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return agentEnrollmentResponse{}, fmt.Errorf("commit host enrollment: %w", err)
	}
	return agentEnrollmentResponse{HostID: hostID, Credential: credential}, nil
}
