package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var errHostNotFound = errors.New("host not found in the authenticated personal tenant")
var errInvalidJobLease = errors.New("job lease is invalid, expired, or no longer current")

type hostJobTarget struct {
	HostID      string
	Hostname    string
	RequestedAt time.Time
	ActionID    string
	ExpiresAt   time.Time
}

type hostJobLease struct {
	ID             string          `json:"id"`
	Operation      string          `json:"operation"`
	Input          json.RawMessage `json:"input"`
	LeaseToken     string          `json:"lease_token"`
	LeaseExpiresAt time.Time       `json:"lease_expires_at"`
	Attempt        int             `json:"attempt"`
}

type hostJobState struct {
	Status    string
	Operation string
	Input     []byte
	Result    []byte
	ErrorText string
}

func (s *postgresStore) enqueueHostJob(ctx context.Context, tenantID, rawHostID, operation string, input json.RawMessage) (hostJobTarget, string, error) {
	hostID, err := uuid.Parse(rawHostID)
	if err != nil {
		return hostJobTarget{}, "", errHostNotFound
	}
	transaction, err := s.pool.Begin(ctx)
	if err != nil {
		return hostJobTarget{}, "", fmt.Errorf("begin host operation request: %w", err)
	}
	defer rollbackJobTransaction(transaction)

	var target hostJobTarget
	err = transaction.QueryRow(ctx, `
		SELECT id::text, hostname
		FROM hosts
		WHERE id = $1 AND tenant_id = $2::uuid AND removed_at IS NULL
		FOR SHARE
	`, hostID, tenantID).Scan(&target.HostID, &target.Hostname)
	if errors.Is(err, pgx.ErrNoRows) {
		return hostJobTarget{}, "", errHostNotFound
	}
	if err != nil {
		return hostJobTarget{}, "", fmt.Errorf("find target host: %w", err)
	}
	jobUUID := uuid.New()
	jobID := jobUUID.String()
	sealedInput, err := s.sealJobPayload(tenantID, target.HostID, jobID, "input", input)
	if err != nil {
		return hostJobTarget{}, "", fmt.Errorf("encrypt host operation input")
	}
	err = transaction.QueryRow(ctx, `
		INSERT INTO jobs (id, tenant_id, host_id, operation, input)
		VALUES ($1, $2::uuid, $3, $4, $5::jsonb)
		RETURNING requested_at
	`, jobUUID, tenantID, hostID, operation, sealedInput).Scan(&target.RequestedAt)
	if err != nil {
		return hostJobTarget{}, "", fmt.Errorf("queue host operation: %w", err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return hostJobTarget{}, "", fmt.Errorf("commit host operation request: %w", err)
	}
	return target, jobID, nil
}

func (s *postgresStore) hostJobState(ctx context.Context, tenantID, hostID, jobID string) (hostJobState, error) {
	var state hostJobState
	err := s.pool.QueryRow(ctx, `
		SELECT status, operation, input, result, COALESCE(error_text, '')
		FROM jobs
		WHERE id = $1::uuid AND tenant_id = $2::uuid AND host_id = $3::uuid
	`, jobID, tenantID, hostID).Scan(&state.Status, &state.Operation, &state.Input, &state.Result, &state.ErrorText)
	if err != nil {
		return hostJobState{}, fmt.Errorf("read host job state: %w", err)
	}
	state.Input, _, err = s.openJobPayload(tenantID, hostID, jobID, "input", state.Input)
	if err != nil {
		return hostJobState{}, fmt.Errorf("decrypt host operation input")
	}
	if len(state.Result) > 0 {
		state.Result, _, err = s.openJobPayload(tenantID, hostID, jobID, "result", state.Result)
		if err != nil {
			return hostJobState{}, fmt.Errorf("decrypt host operation result")
		}
	}
	return state, nil
}

func (s *postgresStore) clearHostJobResult(ctx context.Context, tenantID, hostID, jobID string) (bool, error) {
	commandTag, err := s.pool.Exec(ctx, `
		UPDATE jobs SET result = NULL, input = '{}'::jsonb
		WHERE id = $1::uuid AND tenant_id = $2::uuid AND host_id = $3::uuid AND status = 'completed'
		  AND (result IS NOT NULL OR input <> '{}'::jsonb)
	`, jobID, tenantID, hostID)
	if err != nil {
		return false, fmt.Errorf("clear delivered host job result: %w", err)
	}
	return commandTag.RowsAffected() == 1, nil
}

func (s *postgresStore) cancelHostJob(ctx context.Context, tenantID, hostID, jobID string) error {
	transaction, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin host job cancellation: %w", err)
	}
	defer rollbackJobTransaction(transaction)
	if _, err := transaction.Exec(ctx, `
		UPDATE jobs
		SET status = 'cancelled',
		    result = NULL,
		    input = '{}'::jsonb,
		    error_text = 'request ended before result delivery',
		    completed_at = clock_timestamp(),
		    lease_expires_at = NULL
		WHERE id = $1::uuid AND tenant_id = $2::uuid AND host_id = $3::uuid
		  AND status IN ('pending', 'leased')
	`, jobID, tenantID, hostID); err != nil {
		return fmt.Errorf("cancel pending host job: %w", err)
	}
	if _, err := transaction.Exec(ctx, `
		UPDATE jobs SET result = NULL, input = '{}'::jsonb
		WHERE id = $1::uuid AND tenant_id = $2::uuid AND host_id = $3::uuid AND status = 'completed'
	`, jobID, tenantID, hostID); err != nil {
		return fmt.Errorf("clear undelivered host result: %w", err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return fmt.Errorf("commit host job cancellation: %w", err)
	}
	return nil
}

func (s *postgresStore) claimNextHostJob(ctx context.Context, credential string) (*hostJobLease, error) {
	credentialHash := sha256.Sum256([]byte(credential))
	transaction, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin host job poll: %w", err)
	}
	defer rollbackJobTransaction(transaction)

	var hostID, tenantID string
	err = transaction.QueryRow(ctx, `
		UPDATE hosts AS h
		SET last_seen_at = clock_timestamp()
		FROM host_credentials AS c
		WHERE c.credential_hash = $1
		  AND c.host_id = h.id
		  AND c.revoked_at IS NULL
		  AND h.removed_at IS NULL
		RETURNING h.id::text, h.tenant_id::text
	`, credentialHash[:]).Scan(&hostID, &tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errInvalidHostCredential
	}
	if err != nil {
		return nil, fmt.Errorf("authenticate host poll: %w", err)
	}
	var jobID, operation string
	var input []byte
	err = transaction.QueryRow(ctx, `
		SELECT id::text, operation, input
		FROM jobs
		WHERE host_id = $1::uuid AND tenant_id = $2::uuid
		  AND (status = 'pending' OR (status = 'leased' AND lease_expires_at <= clock_timestamp()))
		ORDER BY requested_at ASC, id ASC
		FOR UPDATE SKIP LOCKED
		LIMIT 1
	`, hostID, tenantID).Scan(&jobID, &operation, &input)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := transaction.Commit(ctx); err != nil {
			return nil, fmt.Errorf("commit idle host poll: %w", err)
		}
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find queued host job: %w", err)
	}
	var lease hostJobLease
	err = transaction.QueryRow(ctx, `
		UPDATE jobs
		SET status = 'leased',
		    attempt = attempt + 1,
		    lease_token = gen_random_uuid(),
		    lease_expires_at = clock_timestamp() + interval '60 seconds'
		WHERE id = $1::uuid
		RETURNING id::text, operation, lease_token::text, lease_expires_at, attempt
	`, jobID).Scan(&lease.ID, &lease.Operation, &lease.LeaseToken, &lease.LeaseExpiresAt, &lease.Attempt)
	if err != nil {
		return nil, fmt.Errorf("lease host job: %w", err)
	}
	decryptedInput, _, err := s.openJobPayload(tenantID, hostID, jobID, "input", input)
	if err != nil {
		return nil, fmt.Errorf("decrypt leased host operation input")
	}
	if err := transaction.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit host job lease: %w", err)
	}
	lease.Input = json.RawMessage(decryptedInput)
	return &lease, nil
}

func (s *postgresStore) completeHostJob(ctx context.Context, credential, rawJobID, rawLeaseToken string, result []byte, failure string) error {
	jobID, err := uuid.Parse(rawJobID)
	if err != nil {
		return errInvalidJobLease
	}
	leaseToken, err := uuid.Parse(rawLeaseToken)
	if err != nil {
		return errInvalidJobLease
	}
	credentialHash := sha256.Sum256([]byte(credential))
	transaction, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin host job completion: %w", err)
	}
	defer rollbackJobTransaction(transaction)

	var hostID, tenantID string
	err = transaction.QueryRow(ctx, `
		UPDATE hosts AS h
		SET last_seen_at = clock_timestamp()
		FROM host_credentials AS c
		WHERE c.credential_hash = $1 AND c.host_id = h.id
		  AND c.revoked_at IS NULL AND h.removed_at IS NULL
		RETURNING h.id::text, h.tenant_id::text
	`, credentialHash[:]).Scan(&hostID, &tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return errInvalidHostCredential
	}
	if err != nil {
		return fmt.Errorf("authenticate host result: %w", err)
	}

	var status, operation, storedLeaseToken, storedError string
	var input []byte
	err = transaction.QueryRow(ctx, `
		SELECT status, operation, input, COALESCE(lease_token::text, ''), COALESCE(error_text, '')
		FROM jobs
		WHERE id = $1 AND host_id = $2::uuid AND tenant_id = $3::uuid
		FOR UPDATE
	`, jobID, hostID, tenantID).Scan(&status, &operation, &input, &storedLeaseToken, &storedError)
	if errors.Is(err, pgx.ErrNoRows) {
		return errInvalidJobLease
	}
	if err != nil {
		return fmt.Errorf("read host job lease: %w", err)
	}
	if storedLeaseToken == leaseToken.String() && status == "completed" {
		return transaction.Commit(ctx)
	}
	if storedLeaseToken == leaseToken.String() && status == "failed" && failure != "" && storedError == failure {
		return transaction.Commit(ctx)
	}
	if status != "leased" || storedLeaseToken != leaseToken.String() {
		return errInvalidJobLease
	}
	decryptedInput, _, err := s.openJobPayload(tenantID, hostID, jobID.String(), "input", input)
	if err != nil {
		return fmt.Errorf("decrypt submitted host operation input")
	}
	if failure == "" && !validHostOperationResult(operation, json.RawMessage(decryptedInput), json.RawMessage(result)) {
		return errInvalidHostJobResult
	}
	if failure != "" {
		commandTag, updateErr := transaction.Exec(ctx, `
			UPDATE jobs
			SET status = 'failed', input = '{}'::jsonb, result = NULL, error_text = $2, completed_at = clock_timestamp(), lease_expires_at = NULL
			WHERE id = $1 AND status = 'leased' AND lease_token = $3::uuid AND lease_expires_at > clock_timestamp()
		`, jobID, failure, leaseToken)
		err = updateErr
		if err == nil && commandTag.RowsAffected() != 1 {
			return errInvalidJobLease
		}
	} else {
		sealedResult, sealErr := s.sealJobPayload(tenantID, hostID, jobID.String(), "result", result)
		if sealErr != nil {
			return fmt.Errorf("encrypt host operation result")
		}
		commandTag, updateErr := transaction.Exec(ctx, `
			UPDATE jobs
			SET status = 'completed', result = $2::jsonb, completed_at = clock_timestamp(), lease_expires_at = NULL
			WHERE id = $1 AND status = 'leased' AND lease_token = $3::uuid AND lease_expires_at > clock_timestamp()
		`, jobID, sealedResult, leaseToken)
		err = updateErr
		if err == nil && commandTag.RowsAffected() != 1 {
			return errInvalidJobLease
		}
	}
	if err != nil {
		return fmt.Errorf("store host job result: %w", err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return fmt.Errorf("commit host job result: %w", err)
	}
	return nil
}

func (s *postgresStore) sealJobPayload(tenantID, hostID, jobID, purpose string, plaintext []byte) ([]byte, error) {
	if s.cipher == nil {
		return nil, fmt.Errorf("application encryption is unavailable")
	}
	return s.cipher.Seal(plaintext, jobPayloadAssociatedData(tenantID, hostID, jobID, purpose))
}

func (s *postgresStore) openJobPayload(tenantID, hostID, jobID, purpose string, sealed []byte) ([]byte, bool, error) {
	if s.cipher == nil {
		return nil, false, fmt.Errorf("application encryption is unavailable")
	}
	return s.cipher.OpenIfSealed(sealed, jobPayloadAssociatedData(tenantID, hostID, jobID, purpose))
}

func jobPayloadAssociatedData(tenantID, hostID, jobID, purpose string) []byte {
	return []byte("ubuntu-fleet-manager:job:v1:" + tenantID + ":" + hostID + ":" + jobID + ":" + purpose)
}

func rollbackJobTransaction(transaction pgx.Tx) {
	rollbackCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = transaction.Rollback(rollbackCtx)
}
