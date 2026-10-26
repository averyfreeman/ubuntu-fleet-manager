package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/averyfreeman/ubuntu-fleet-manager/internal/hostops"
	"github.com/averyfreeman/ubuntu-fleet-manager/internal/mcpserver"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var errAPTActionNotFound = errors.New("APT action was not found in the authenticated personal tenant")
var errAPTActionExpired = errors.New("APT action audit and rollback data has expired")
var errAPTActionNotReversible = errors.New("APT action does not have complete rollback data")
var errAPTActionInProgress = errors.New("APT action rollback is already in progress")

type aptActionPayload struct {
	Operation         string                 `json:"operation"`
	RequestedPackages []string               `json:"requested_packages,omitempty"`
	Previous          []hostops.PackageState `json:"previous,omitempty"`
	ExpectedCurrent   []hostops.PackageState `json:"expected_current,omitempty"`
	Outcome           string                 `json:"outcome"`
	Reason            string                 `json:"reason,omitempty"`
	RollbackAvailable bool                   `json:"rollback_available"`
}

func (s *Service) updateHostAPTIndexes(ctx context.Context, input mcpserver.HostAPTUpdateInput) (mcpserver.HostAPTActionResult, error) {
	return s.runHostAPTAction(ctx, input.HostID, hostops.OperationAPTUpdate, nil)
}

func (s *Service) installHostPackages(ctx context.Context, input mcpserver.HostAPTActionInput) (mcpserver.HostAPTActionResult, error) {
	return s.runHostAPTAction(ctx, input.HostID, hostops.OperationAPTInstall, input.Packages)
}

func (s *Service) removeHostPackages(ctx context.Context, input mcpserver.HostAPTActionInput) (mcpserver.HostAPTActionResult, error) {
	return s.runHostAPTAction(ctx, input.HostID, hostops.OperationAPTRemove, input.Packages)
}

func (s *Service) upgradeHostPackages(ctx context.Context, input mcpserver.HostAPTActionInput) (mcpserver.HostAPTActionResult, error) {
	return s.runHostAPTAction(ctx, input.HostID, hostops.OperationAPTUpgrade, input.Packages)
}

func (s *Service) runHostAPTAction(ctx context.Context, hostID, operation string, packages []string) (mcpserver.HostAPTActionResult, error) {
	if !s.config.AllowAPTWrites {
		return mcpserver.HostAPTActionResult{}, fmt.Errorf("APT package changes are disabled by the control-plane policy")
	}
	var operationInput any = struct{}{}
	if operation != hostops.OperationAPTUpdate {
		operationInput = hostops.APTActionInput{Packages: packages}
	}
	target, encoded, err := s.runHostOperation(ctx, hostID, operation, operationInput)
	if err != nil {
		return mcpserver.HostAPTActionResult{}, err
	}
	var result hostops.APTActionResult
	if err := json.Unmarshal(encoded, &result); err != nil {
		return mcpserver.HostAPTActionResult{}, fmt.Errorf("host agent returned an invalid APT action result")
	}
	return mcpserver.HostAPTActionResult{
		HostID: target.HostID, Hostname: target.Hostname, RequestedAt: target.RequestedAt,
		ActionID: target.ActionID, Operation: result.Operation, Outcome: result.Outcome,
		ChangedPackages: countChangedAPTStates(result.Before, result.After), RollbackAvailable: result.RollbackAvailable,
		ExpiresAt: target.ExpiresAt, Reason: result.Reason,
	}, nil
}

func countChangedAPTStates(before, after []hostops.PackageState) int {
	current := make(map[string]hostops.PackageState, len(after))
	for _, state := range after {
		current[state.Name] = state
	}
	changed := 0
	for _, state := range before {
		if current[state.Name] != state {
			changed++
		}
	}
	return changed
}

func (s *Service) rollbackHostAPTAction(ctx context.Context, input mcpserver.HostAPTRollbackInput) (mcpserver.HostAPTRollbackResult, error) {
	if !s.config.AllowAPTWrites {
		return mcpserver.HostAPTRollbackResult{}, fmt.Errorf("APT rollback is disabled by the control-plane policy")
	}
	tenantID, ok := ctx.Value(personalTenantContextKey{}).(string)
	if !ok || tenantID == "" {
		return mcpserver.HostAPTRollbackResult{}, fmt.Errorf("authenticated personal tenant is unavailable")
	}
	hostID, err := uuid.Parse(input.HostID)
	if err != nil {
		return mcpserver.HostAPTRollbackResult{}, errHostNotFound
	}
	input.HostID = hostID.String()
	payload, alreadyRolledBack, err := s.store.beginAPTActionRollback(ctx, tenantID, input.HostID, input.ActionID)
	if err != nil {
		return mcpserver.HostAPTRollbackResult{}, err
	}
	if alreadyRolledBack {
		hostname, err := s.store.hostHostname(ctx, tenantID, input.HostID)
		if err != nil {
			return mcpserver.HostAPTRollbackResult{}, err
		}
		return mcpserver.HostAPTRollbackResult{
			HostID: input.HostID, Hostname: hostname, ActionID: input.ActionID,
			Outcome: hostops.APTOutcomeSucceeded, Exact: true, AlreadyRestored: true,
		}, nil
	}
	rollbackFinished := false
	defer func() {
		if rollbackFinished {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), jobCancellationCleanupTimeout)
		defer cancel()
		_ = s.store.finishAPTActionRollback(cleanupCtx, tenantID, input.HostID, input.ActionID, false)
	}()
	target, encoded, err := s.runHostOperation(ctx, input.HostID, hostops.OperationAPTRollback, hostops.APTRollbackInput{
		Previous: payload.Previous, ExpectedCurrent: payload.ExpectedCurrent,
	})
	if err != nil {
		return mcpserver.HostAPTRollbackResult{}, err
	}
	var result hostops.APTRollbackResult
	if err := json.Unmarshal(encoded, &result); err != nil {
		return mcpserver.HostAPTRollbackResult{}, fmt.Errorf("host agent returned an invalid APT rollback result")
	}
	exact := result.Outcome == hostops.APTOutcomeSucceeded
	if err := s.store.finishAPTActionRollback(ctx, tenantID, target.HostID, input.ActionID, exact); err != nil {
		return mcpserver.HostAPTRollbackResult{}, err
	}
	rollbackFinished = true
	restoredPackages := 0
	var reason string
	for _, packageResult := range result.Packages {
		if packageResult.Exact {
			restoredPackages++
		} else if reason == "" {
			reason = packageResult.Reason
		}
	}
	return mcpserver.HostAPTRollbackResult{
		HostID: target.HostID, Hostname: target.Hostname, ActionID: input.ActionID,
		Outcome: result.Outcome, RestoredPackages: restoredPackages, Exact: exact,
		Packages: result.Packages, Reason: reason, RequestedAt: target.RequestedAt,
	}, nil
}

func (s *postgresStore) persistAPTActionAndClearJob(ctx context.Context, tenantID, hostID, jobID string, payload aptActionPayload) (time.Time, error) {
	parsedJobID, err := uuid.Parse(jobID)
	if err != nil {
		return time.Time{}, fmt.Errorf("APT action identifier is invalid")
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return time.Time{}, fmt.Errorf("encode encrypted APT audit payload")
	}
	sealed, err := s.cipher.Seal(encoded, aptActionAssociatedData(tenantID, hostID, jobID))
	if err != nil {
		return time.Time{}, fmt.Errorf("encrypt APT audit payload")
	}
	transaction, err := s.pool.Begin(ctx)
	if err != nil {
		return time.Time{}, fmt.Errorf("begin APT action persistence: %w", err)
	}
	defer rollbackJobTransaction(transaction)
	var status, operation string
	if err := transaction.QueryRow(ctx, `
		SELECT status, operation FROM jobs
		WHERE id = $1 AND tenant_id = $2::uuid AND host_id = $3::uuid
		FOR UPDATE
	`, parsedJobID, tenantID, hostID).Scan(&status, &operation); err != nil {
		return time.Time{}, fmt.Errorf("lock completed APT job: %w", err)
	}
	if status != "completed" || operation != payload.Operation || operation == hostops.OperationAPTRollback {
		return time.Time{}, fmt.Errorf("APT action job is not completed")
	}
	actionStatus := "not_reversible"
	if payload.RollbackAvailable {
		actionStatus = "available"
	}
	var expiresAt time.Time
	err = transaction.QueryRow(ctx, `
		INSERT INTO package_actions (id, tenant_id, host_id, payload, status)
		VALUES ($1, $2::uuid, $3::uuid, $4::jsonb, $5)
		ON CONFLICT (id) DO NOTHING
		RETURNING expires_at
	`, parsedJobID, tenantID, hostID, sealed, actionStatus).Scan(&expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = transaction.QueryRow(ctx, `
			SELECT expires_at FROM package_actions
			WHERE id = $1 AND tenant_id = $2::uuid AND host_id = $3::uuid
		`, parsedJobID, tenantID, hostID).Scan(&expiresAt)
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("store encrypted APT audit record: %w", err)
	}
	if _, err := transaction.Exec(ctx, `
		UPDATE jobs SET input = '{}'::jsonb, result = NULL
		WHERE id = $1 AND tenant_id = $2::uuid AND host_id = $3::uuid AND status = 'completed'
	`, parsedJobID, tenantID, hostID); err != nil {
		return time.Time{}, fmt.Errorf("clear consumed APT job payload: %w", err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return time.Time{}, fmt.Errorf("commit encrypted APT action: %w", err)
	}
	return expiresAt.UTC(), nil
}

func (s *postgresStore) beginAPTActionRollback(ctx context.Context, tenantID, rawHostID, rawActionID string) (aptActionPayload, bool, error) {
	hostID, err := uuid.Parse(rawHostID)
	if err != nil {
		return aptActionPayload{}, false, errHostNotFound
	}
	actionID, err := uuid.Parse(rawActionID)
	if err != nil {
		return aptActionPayload{}, false, errAPTActionNotFound
	}
	transaction, err := s.pool.Begin(ctx)
	if err != nil {
		return aptActionPayload{}, false, fmt.Errorf("begin APT action rollback: %w", err)
	}
	defer rollbackJobTransaction(transaction)
	var status string
	var active bool
	var sealed []byte
	err = transaction.QueryRow(ctx, `
		SELECT status, expires_at > clock_timestamp(), payload
		FROM package_actions
		WHERE id = $1 AND tenant_id = $2::uuid AND host_id = $3
		FOR UPDATE
	`, actionID, tenantID, hostID).Scan(&status, &active, &sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		return aptActionPayload{}, false, errAPTActionNotFound
	}
	if err != nil {
		return aptActionPayload{}, false, fmt.Errorf("read encrypted APT action: %w", err)
	}
	if !active {
		return aptActionPayload{}, false, errAPTActionExpired
	}
	if status == "rolled_back" {
		if err := transaction.Commit(ctx); err != nil {
			return aptActionPayload{}, false, fmt.Errorf("commit completed APT rollback lookup: %w", err)
		}
		return aptActionPayload{}, true, nil
	}
	if status == "not_reversible" {
		return aptActionPayload{}, false, errAPTActionNotReversible
	}
	if status != "available" {
		return aptActionPayload{}, false, errAPTActionInProgress
	}
	encoded, err := s.cipher.Open(sealed, aptActionAssociatedData(tenantID, hostID.String(), actionID.String()))
	if err != nil {
		return aptActionPayload{}, false, fmt.Errorf("decrypt APT action payload")
	}
	var payload aptActionPayload
	if err := decodeFileActionPayload(encoded, &payload); err != nil {
		return aptActionPayload{}, false, fmt.Errorf("decode APT action payload")
	}
	if !payload.RollbackAvailable {
		return aptActionPayload{}, false, errAPTActionNotReversible
	}
	rollbackInput, err := json.Marshal(hostops.APTRollbackInput{Previous: payload.Previous, ExpectedCurrent: payload.ExpectedCurrent})
	if err != nil {
		return aptActionPayload{}, false, fmt.Errorf("APT action rollback data is invalid")
	}
	if _, err := hostops.ValidateJobInput(hostops.OperationAPTRollback, rollbackInput); err != nil {
		return aptActionPayload{}, false, fmt.Errorf("APT action rollback data is invalid")
	}
	if _, err := transaction.Exec(ctx, `
		UPDATE package_actions
		SET status = 'rolling_back', rollback_started_at = clock_timestamp()
		WHERE id = $1 AND tenant_id = $2::uuid AND host_id = $3 AND status = 'available'
	`, actionID, tenantID, hostID); err != nil {
		return aptActionPayload{}, false, fmt.Errorf("reserve APT action rollback: %w", err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return aptActionPayload{}, false, fmt.Errorf("commit APT rollback reservation: %w", err)
	}
	return payload, false, nil
}

func (s *postgresStore) finishAPTActionRollback(ctx context.Context, tenantID, rawHostID, rawActionID string, restored bool) error {
	hostID, err := uuid.Parse(rawHostID)
	if err != nil {
		return errHostNotFound
	}
	actionID, err := uuid.Parse(rawActionID)
	if err != nil {
		return errAPTActionNotFound
	}
	status := "available"
	if restored {
		status = "rolled_back"
	}
	commandTag, err := s.pool.Exec(ctx, `
		UPDATE package_actions
		SET status = $4, rollback_started_at = NULL
		WHERE id = $1 AND tenant_id = $2::uuid AND host_id = $3 AND status = 'rolling_back'
	`, actionID, tenantID, hostID, status)
	if err != nil {
		return fmt.Errorf("finish APT action rollback: %w", err)
	}
	if commandTag.RowsAffected() != 1 {
		return fmt.Errorf("APT action rollback state changed unexpectedly")
	}
	return nil
}

func aptActionAssociatedData(tenantID, hostID, actionID string) []byte {
	return []byte("ubuntu-fleet-manager:apt-action:v1:" + tenantID + ":" + hostID + ":" + actionID)
}
