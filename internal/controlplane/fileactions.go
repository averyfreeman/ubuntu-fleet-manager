package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/averyfreeman/ubuntu-fleet-manager/internal/hostops"
	"github.com/averyfreeman/ubuntu-fleet-manager/internal/mcpserver"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var errFileActionNotFound = errors.New("file action was not found in the authenticated personal tenant")
var errFileActionExpired = errors.New("file action reversal data has expired")
var errFileActionInProgress = errors.New("file action rollback is already in progress")

type fileActionPayload struct {
	Path            string                  `json:"path"`
	Previous        hostops.FileState       `json:"previous"`
	ExpectedCurrent hostops.FileFingerprint `json:"expected_current"`
}

func (s *Service) writeHostFile(ctx context.Context, input mcpserver.HostFileWriteInput) (mcpserver.HostFileWriteResult, error) {
	if !s.config.AllowFileWrites {
		return mcpserver.HostFileWriteResult{}, fmt.Errorf("file writes are disabled by the control-plane approval policy")
	}
	target, encoded, err := s.runHostOperation(ctx, input.HostID, hostops.OperationWriteFile, hostops.WriteFileInput{Path: input.Path, Content: input.Content})
	if err != nil {
		return mcpserver.HostFileWriteResult{}, err
	}
	var result hostops.WriteFileResult
	if err := json.Unmarshal(encoded, &result); err != nil {
		return mcpserver.HostFileWriteResult{}, fmt.Errorf("host agent returned an invalid file write result")
	}
	return mcpserver.HostFileWriteResult{
		HostID: target.HostID, Hostname: target.Hostname, RequestedAt: target.RequestedAt,
		Path: result.Path, ActionID: target.ActionID, Created: !result.Previous.Existed,
		BytesWritten: len(input.Content), Mode: result.Current.Mode, ExpiresAt: target.ExpiresAt,
	}, nil
}

func (s *Service) rollbackHostFile(ctx context.Context, input mcpserver.HostFileRollbackInput) (mcpserver.HostFileRollbackResult, error) {
	if !s.config.AllowFileWrites {
		return mcpserver.HostFileRollbackResult{}, fmt.Errorf("file rollback is disabled by the control-plane approval policy")
	}
	tenantID, ok := ctx.Value(personalTenantContextKey{}).(string)
	if !ok || tenantID == "" {
		return mcpserver.HostFileRollbackResult{}, fmt.Errorf("authenticated personal tenant is unavailable")
	}
	hostID, err := uuid.Parse(input.HostID)
	if err != nil {
		return mcpserver.HostFileRollbackResult{}, errHostNotFound
	}
	input.HostID = hostID.String()
	payload, alreadyRolledBack, err := s.store.beginFileActionRollback(ctx, tenantID, input.HostID, input.ActionID)
	if err != nil {
		return mcpserver.HostFileRollbackResult{}, err
	}
	if alreadyRolledBack {
		hostname, err := s.store.hostHostname(ctx, tenantID, input.HostID)
		if err != nil {
			return mcpserver.HostFileRollbackResult{}, err
		}
		return mcpserver.HostFileRollbackResult{
			HostID: input.HostID, Hostname: hostname, ActionID: input.ActionID, Restored: true, Exact: true,
			AlreadyRestored: true, RequestedAt: time.Now().UTC(),
		}, nil
	}
	rollbackFinished := false
	defer func() {
		if rollbackFinished {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), jobCancellationCleanupTimeout)
		defer cancel()
		_ = s.store.finishFileActionRollback(cleanupCtx, tenantID, input.HostID, input.ActionID, false)
	}()
	jobInput := hostops.RestoreFileInput{
		Path: payload.Path, Previous: payload.Previous, ExpectedCurrent: payload.ExpectedCurrent,
	}
	target, encoded, err := s.runHostOperation(ctx, input.HostID, hostops.OperationRestoreFile, jobInput)
	if err != nil {
		return mcpserver.HostFileRollbackResult{}, err
	}
	var restored hostops.RestoreFileResult
	if err := json.Unmarshal(encoded, &restored); err != nil {
		return mcpserver.HostFileRollbackResult{}, fmt.Errorf("host agent returned an invalid file restoration result")
	}
	if err := s.store.finishFileActionRollback(ctx, tenantID, target.HostID, input.ActionID, restored.Exact && restored.Restored); err != nil {
		return mcpserver.HostFileRollbackResult{}, err
	}
	rollbackFinished = true
	return mcpserver.HostFileRollbackResult{
		HostID: target.HostID, Hostname: target.Hostname, ActionID: input.ActionID,
		Restored: restored.Restored, Exact: restored.Exact, Reason: restored.Reason, RequestedAt: target.RequestedAt,
	}, nil
}

func (s *postgresStore) persistFileActionAndClearJob(ctx context.Context, tenantID, hostID, jobID string, payload fileActionPayload) (time.Time, error) {
	parsedJobID, err := uuid.Parse(jobID)
	if err != nil {
		return time.Time{}, fmt.Errorf("file action identifier is invalid")
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return time.Time{}, fmt.Errorf("encode encrypted file action payload")
	}
	sealed, err := s.cipher.Seal(encoded, fileActionAssociatedData(tenantID, hostID, jobID))
	if err != nil {
		return time.Time{}, fmt.Errorf("encrypt file action payload")
	}
	transaction, err := s.pool.Begin(ctx)
	if err != nil {
		return time.Time{}, fmt.Errorf("begin file action persistence: %w", err)
	}
	defer rollbackJobTransaction(transaction)
	var status, operation string
	if err := transaction.QueryRow(ctx, `
		SELECT status, operation FROM jobs
		WHERE id = $1 AND tenant_id = $2::uuid AND host_id = $3::uuid
		FOR UPDATE
	`, parsedJobID, tenantID, hostID).Scan(&status, &operation); err != nil {
		return time.Time{}, fmt.Errorf("lock completed file write job: %w", err)
	}
	if status != "completed" || operation != hostops.OperationWriteFile {
		return time.Time{}, fmt.Errorf("file write job is not completed")
	}
	var expiresAt time.Time
	err = transaction.QueryRow(ctx, `
		INSERT INTO file_actions (id, tenant_id, host_id, payload)
		VALUES ($1, $2::uuid, $3::uuid, $4::jsonb)
		ON CONFLICT (id) DO NOTHING
		RETURNING expires_at
	`, parsedJobID, tenantID, hostID, sealed).Scan(&expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = transaction.QueryRow(ctx, `
			SELECT expires_at FROM file_actions
			WHERE id = $1 AND tenant_id = $2::uuid AND host_id = $3::uuid
		`, parsedJobID, tenantID, hostID).Scan(&expiresAt)
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("store encrypted file action: %w", err)
	}
	if _, err := transaction.Exec(ctx, `
		UPDATE jobs SET input = '{}'::jsonb, result = NULL
		WHERE id = $1 AND tenant_id = $2::uuid AND host_id = $3::uuid AND status = 'completed'
	`, parsedJobID, tenantID, hostID); err != nil {
		return time.Time{}, fmt.Errorf("clear consumed file write payload: %w", err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return time.Time{}, fmt.Errorf("commit encrypted file action: %w", err)
	}
	return expiresAt.UTC(), nil
}

func (s *postgresStore) beginFileActionRollback(ctx context.Context, tenantID, hostID, rawActionID string) (fileActionPayload, bool, error) {
	parsedHostID, err := uuid.Parse(hostID)
	if err != nil {
		return fileActionPayload{}, false, errHostNotFound
	}
	actionID, err := uuid.Parse(rawActionID)
	if err != nil {
		return fileActionPayload{}, false, errFileActionNotFound
	}
	transaction, err := s.pool.Begin(ctx)
	if err != nil {
		return fileActionPayload{}, false, fmt.Errorf("begin file action rollback: %w", err)
	}
	defer rollbackJobTransaction(transaction)
	var status string
	var expiresAt time.Time
	var active bool
	var sealed []byte
	err = transaction.QueryRow(ctx, `
		SELECT status, expires_at, expires_at > clock_timestamp(), payload
		FROM file_actions
		WHERE id = $1 AND tenant_id = $2::uuid AND host_id = $3::uuid
		FOR UPDATE
	`, actionID, tenantID, parsedHostID).Scan(&status, &expiresAt, &active, &sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		return fileActionPayload{}, false, errFileActionNotFound
	}
	if err != nil {
		return fileActionPayload{}, false, fmt.Errorf("read encrypted file action: %w", err)
	}
	if !active {
		return fileActionPayload{}, false, errFileActionExpired
	}
	if status == "rolled_back" {
		if err := transaction.Commit(ctx); err != nil {
			return fileActionPayload{}, false, fmt.Errorf("commit completed file rollback lookup: %w", err)
		}
		return fileActionPayload{}, true, nil
	}
	if status != "available" {
		return fileActionPayload{}, false, errFileActionInProgress
	}
	encoded, err := s.cipher.Open(sealed, fileActionAssociatedData(tenantID, parsedHostID.String(), actionID.String()))
	if err != nil {
		return fileActionPayload{}, false, fmt.Errorf("decrypt file action reversal data")
	}
	var payload fileActionPayload
	if err := decodeFileActionPayload(encoded, &payload); err != nil {
		return fileActionPayload{}, false, fmt.Errorf("decode file action reversal data")
	}
	validationInput, err := json.Marshal(hostops.RestoreFileInput{Path: payload.Path, Previous: payload.Previous, ExpectedCurrent: payload.ExpectedCurrent})
	if err != nil {
		return fileActionPayload{}, false, fmt.Errorf("file action reversal data is invalid")
	}
	if _, err := hostops.ValidateJobInput(hostops.OperationRestoreFile, validationInput); err != nil {
		return fileActionPayload{}, false, fmt.Errorf("file action reversal data is invalid")
	}
	if _, err := transaction.Exec(ctx, `
		UPDATE file_actions
		SET status = 'rolling_back', rollback_started_at = clock_timestamp()
		WHERE id = $1 AND tenant_id = $2::uuid AND host_id = $3::uuid AND status = 'available'
	`, actionID, tenantID, parsedHostID); err != nil {
		return fileActionPayload{}, false, fmt.Errorf("mark file action rollback as active: %w", err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return fileActionPayload{}, false, fmt.Errorf("commit file action rollback reservation: %w", err)
	}
	return payload, false, nil
}

func decodeFileActionPayload(encoded []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("file action payload must contain one JSON object")
	}
	return nil
}

func (s *postgresStore) finishFileActionRollback(ctx context.Context, tenantID, hostID, rawActionID string, restored bool) error {
	parsedHostID, err := uuid.Parse(hostID)
	if err != nil {
		return errHostNotFound
	}
	actionID, err := uuid.Parse(rawActionID)
	if err != nil {
		return errFileActionNotFound
	}
	status := "available"
	if restored {
		status = "rolled_back"
	}
	commandTag, err := s.pool.Exec(ctx, `
		UPDATE file_actions
		SET status = $4, rollback_started_at = NULL
		WHERE id = $1 AND tenant_id = $2::uuid AND host_id = $3::uuid AND status = 'rolling_back'
	`, actionID, tenantID, parsedHostID, status)
	if err != nil {
		return fmt.Errorf("finish file action rollback: %w", err)
	}
	if commandTag.RowsAffected() != 1 {
		return fmt.Errorf("file action rollback state changed unexpectedly")
	}
	return nil
}

func (s *postgresStore) hostHostname(ctx context.Context, tenantID, rawHostID string) (string, error) {
	hostID, err := uuid.Parse(rawHostID)
	if err != nil {
		return "", errHostNotFound
	}
	var hostname string
	if err := s.pool.QueryRow(ctx, `
		SELECT hostname FROM hosts WHERE id = $1 AND tenant_id = $2::uuid
	`, hostID, tenantID).Scan(&hostname); errors.Is(err, pgx.ErrNoRows) {
		return "", errHostNotFound
	} else if err != nil {
		return "", fmt.Errorf("read target host name: %w", err)
	}
	return hostname, nil
}

func (s *postgresStore) cleanupExpiredApplicationData(ctx context.Context, now time.Time) (int64, error) {
	transaction, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin application retention cleanup: %w", err)
	}
	defer rollbackJobTransaction(transaction)
	if _, err := transaction.Exec(ctx, `
		UPDATE file_actions
		SET status = 'available', rollback_started_at = NULL
		WHERE status = 'rolling_back' AND rollback_started_at < $1::timestamptz - interval '2 minutes' AND expires_at > $1::timestamptz
	`, now); err != nil {
		return 0, fmt.Errorf("release stale file action rollbacks: %w", err)
	}
	if _, err := transaction.Exec(ctx, `
		UPDATE package_actions
		SET status = 'available', rollback_started_at = NULL
		WHERE status = 'rolling_back' AND rollback_started_at < $1::timestamptz - interval '2 minutes' AND expires_at > $1::timestamptz
	`, now); err != nil {
		return 0, fmt.Errorf("release stale APT action rollbacks: %w", err)
	}
	deletedActions, err := transaction.Exec(ctx, `DELETE FROM file_actions WHERE expires_at <= $1::timestamptz`, now)
	if err != nil {
		return 0, fmt.Errorf("delete expired file action data: %w", err)
	}
	deletedPackageActions, err := transaction.Exec(ctx, `DELETE FROM package_actions WHERE expires_at <= $1::timestamptz`, now)
	if err != nil {
		return 0, fmt.Errorf("delete expired APT action data: %w", err)
	}
	deletedJobs, err := transaction.Exec(ctx, `DELETE FROM jobs WHERE requested_at <= $1::timestamptz - interval '7 days'`, now)
	if err != nil {
		return 0, fmt.Errorf("delete expired host job records: %w", err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit application retention cleanup: %w", err)
	}
	return deletedActions.RowsAffected() + deletedPackageActions.RowsAffected() + deletedJobs.RowsAffected(), nil
}

func fileActionAssociatedData(tenantID, hostID, actionID string) []byte {
	return []byte("ubuntu-fleet-manager:file-action:v1:" + tenantID + ":" + hostID + ":" + actionID)
}
