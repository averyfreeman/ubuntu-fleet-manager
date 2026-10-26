package controlplane

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/averyfreeman/ubuntu-fleet-manager/internal/mcpserver"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var errHostNotFound = errors.New("host not found in the authenticated personal tenant")
var errInvalidJobLease = errors.New("job lease is invalid, expired, or no longer current")

type systemInfoJobLease struct {
	ID             string    `json:"id"`
	Operation      string    `json:"operation"`
	LeaseToken     string    `json:"lease_token"`
	LeaseExpiresAt time.Time `json:"lease_expires_at"`
	Attempt        int       `json:"attempt"`
}

type systemInfoJobState struct {
	Status    string
	Result    []byte
	ErrorText string
}

func (s *postgresStore) enqueueSystemInfo(ctx context.Context, tenantID, rawHostID string) (mcpserver.HostSystemInfoResult, string, error) {
	hostID, err := uuid.Parse(rawHostID)
	if err != nil {
		return mcpserver.HostSystemInfoResult{}, "", errHostNotFound
	}
	transaction, err := s.pool.Begin(ctx)
	if err != nil {
		return mcpserver.HostSystemInfoResult{}, "", fmt.Errorf("begin host system-info request: %w", err)
	}
	defer rollbackJobTransaction(transaction)

	var target mcpserver.HostSystemInfoResult
	err = transaction.QueryRow(ctx, `
		SELECT id::text, hostname
		FROM hosts
		WHERE id = $1 AND tenant_id = $2::uuid AND removed_at IS NULL
		FOR SHARE
	`, hostID, tenantID).Scan(&target.HostID, &target.Hostname)
	if errors.Is(err, pgx.ErrNoRows) {
		return mcpserver.HostSystemInfoResult{}, "", errHostNotFound
	}
	if err != nil {
		return mcpserver.HostSystemInfoResult{}, "", fmt.Errorf("find target host: %w", err)
	}
	var jobID string
	err = transaction.QueryRow(ctx, `
		INSERT INTO jobs (tenant_id, host_id, operation)
		VALUES ($1::uuid, $2, 'get_system_info')
		RETURNING id::text, requested_at
	`, tenantID, hostID).Scan(&jobID, &target.RequestedAt)
	if err != nil {
		return mcpserver.HostSystemInfoResult{}, "", fmt.Errorf("queue host system-info request: %w", err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return mcpserver.HostSystemInfoResult{}, "", fmt.Errorf("commit host system-info request: %w", err)
	}
	return target, jobID, nil
}

func (s *postgresStore) systemInfoJobState(ctx context.Context, tenantID, hostID, jobID string) (systemInfoJobState, error) {
	var state systemInfoJobState
	err := s.pool.QueryRow(ctx, `
		SELECT status, result, COALESCE(error_text, '')
		FROM jobs
		WHERE id = $1::uuid AND tenant_id = $2::uuid AND host_id = $3::uuid
	`, jobID, tenantID, hostID).Scan(&state.Status, &state.Result, &state.ErrorText)
	if err != nil {
		return systemInfoJobState{}, fmt.Errorf("read host system-info job state: %w", err)
	}
	return state, nil
}

func (s *postgresStore) clearSystemInfoJobResult(ctx context.Context, tenantID, hostID, jobID string) (bool, error) {
	commandTag, err := s.pool.Exec(ctx, `
		UPDATE jobs SET result = NULL
		WHERE id = $1::uuid AND tenant_id = $2::uuid AND host_id = $3::uuid AND status = 'completed'
		  AND result IS NOT NULL
	`, jobID, tenantID, hostID)
	if err != nil {
		return false, fmt.Errorf("clear delivered host system-info result: %w", err)
	}
	return commandTag.RowsAffected() == 1, nil
}

func (s *postgresStore) cancelSystemInfoJob(ctx context.Context, tenantID, hostID, jobID string) error {
	transaction, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin host job cancellation: %w", err)
	}
	defer rollbackJobTransaction(transaction)
	if _, err := transaction.Exec(ctx, `
		UPDATE jobs
		SET status = 'cancelled',
		    result = NULL,
		    error_text = 'request ended before result delivery',
		    completed_at = clock_timestamp(),
		    lease_expires_at = NULL
		WHERE id = $1::uuid AND tenant_id = $2::uuid AND host_id = $3::uuid
		  AND status IN ('pending', 'leased')
	`, jobID, tenantID, hostID); err != nil {
		return fmt.Errorf("cancel pending host job: %w", err)
	}
	if _, err := transaction.Exec(ctx, `
		UPDATE jobs SET result = NULL
		WHERE id = $1::uuid AND tenant_id = $2::uuid AND host_id = $3::uuid AND status = 'completed'
	`, jobID, tenantID, hostID); err != nil {
		return fmt.Errorf("clear undelivered host result: %w", err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return fmt.Errorf("commit host job cancellation: %w", err)
	}
	return nil
}

func (s *postgresStore) claimNextSystemInfoJob(ctx context.Context, credential string) (*systemInfoJobLease, error) {
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
	err = transaction.QueryRow(ctx, `
		SELECT id::text, operation
		FROM jobs
		WHERE host_id = $1::uuid AND tenant_id = $2::uuid
		  AND (status = 'pending' OR (status = 'leased' AND lease_expires_at <= clock_timestamp()))
		ORDER BY requested_at ASC, id ASC
		FOR UPDATE SKIP LOCKED
		LIMIT 1
	`, hostID, tenantID).Scan(&jobID, &operation)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := transaction.Commit(ctx); err != nil {
			return nil, fmt.Errorf("commit idle host poll: %w", err)
		}
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find queued host job: %w", err)
	}
	var lease systemInfoJobLease
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
	if err := transaction.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit host job lease: %w", err)
	}
	return &lease, nil
}

func (s *postgresStore) completeSystemInfoJob(ctx context.Context, credential, rawJobID, rawLeaseToken string, result []byte, failure string) error {
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

	var status, storedLeaseToken, storedError string
	err = transaction.QueryRow(ctx, `
		SELECT status, COALESCE(lease_token::text, ''), COALESCE(error_text, '')
		FROM jobs
		WHERE id = $1 AND host_id = $2::uuid AND tenant_id = $3::uuid
		FOR UPDATE
	`, jobID, hostID, tenantID).Scan(&status, &storedLeaseToken, &storedError)
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
	if failure != "" {
		commandTag, updateErr := transaction.Exec(ctx, `
			UPDATE jobs
			SET status = 'failed', error_text = $2, completed_at = clock_timestamp(), lease_expires_at = NULL
			WHERE id = $1 AND status = 'leased' AND lease_token = $3::uuid AND lease_expires_at > clock_timestamp()
		`, jobID, failure, leaseToken)
		err = updateErr
		if err == nil && commandTag.RowsAffected() != 1 {
			return errInvalidJobLease
		}
	} else {
		commandTag, updateErr := transaction.Exec(ctx, `
			UPDATE jobs
			SET status = 'completed', result = $2::jsonb, completed_at = clock_timestamp(), lease_expires_at = NULL
			WHERE id = $1 AND status = 'leased' AND lease_token = $3::uuid AND lease_expires_at > clock_timestamp()
		`, jobID, result, leaseToken)
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

func rollbackJobTransaction(transaction pgx.Tx) {
	rollbackCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = transaction.Rollback(rollbackCtx)
}
