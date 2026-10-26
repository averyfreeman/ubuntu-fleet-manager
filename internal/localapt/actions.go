package localapt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/averyfreeman/ubuntu-fleet-manager/internal/hostops"
	"github.com/averyfreeman/ubuntu-fleet-manager/internal/mcpserver"
	"github.com/averyfreeman/ubuntu-fleet-manager/internal/securepayload"
	"github.com/google/uuid"
)

const (
	localActionRetention = 7 * 24 * time.Hour
	localRollbackStale   = 2 * time.Minute
	maxLocalActionCount  = 1000
	maxLocalStoreBytes   = 64 << 20
	localStoreVersion    = 1
)

type ActionStore struct {
	mu     sync.Mutex
	policy hostops.APTPolicy
	cipher *securepayload.Cipher
	path   string
	runner hostops.APTCommandRunner
}

type diskState struct {
	Version int            `json:"version"`
	Actions []actionRecord `json:"actions"`
}

type actionRecord struct {
	ID                string          `json:"id"`
	CreatedAt         time.Time       `json:"created_at"`
	ExpiresAt         time.Time       `json:"expires_at"`
	Status            string          `json:"status"`
	RollbackStartedAt *time.Time      `json:"rollback_started_at,omitempty"`
	Payload           json.RawMessage `json:"payload"`
}

type actionPayload struct {
	Operation         string                     `json:"operation"`
	RequestedPackages []string                   `json:"requested_packages,omitempty"`
	Result            hostops.APTActionResult    `json:"result"`
	RollbackResult    *hostops.APTRollbackResult `json:"rollback_result,omitempty"`
}

// NewActionStore creates the local stdio action store. The key must contain
// exactly 32 bytes from a private key file; state records are encrypted before
// they are written to disk.
func NewActionStore(policy hostops.APTPolicy, key []byte, path string, runner hostops.APTCommandRunner) (*ActionStore, error) {
	policy, err := hostops.NormalizeAPTPolicy(policy)
	if err != nil {
		return nil, fmt.Errorf("invalid local APT policy: %w", err)
	}
	if !policy.Enabled {
		return nil, fmt.Errorf("local APT policy must be explicitly enabled")
	}
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("local APT action-store path must be absolute")
	}
	cipher, err := securepayload.New(key)
	if err != nil {
		return nil, err
	}
	if err := ensurePrivateDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	store := &ActionStore{policy: policy, cipher: cipher, path: path, runner: runner}
	if err := store.Cleanup(context.Background()); err != nil {
		return nil, fmt.Errorf("inspect local APT action store: %w", err)
	}
	return store, nil
}

// ToolHandlers returns the local forms of the shared APT MCP tools. host_id
// must be omitted so a local MCP process cannot be used to target another host.
func (s *ActionStore) ToolHandlers() mcpserver.APTToolHandlers {
	handlers := mcpserver.APTToolHandlers{}
	if policyAllowsOperation(s.policy, hostops.APTPolicyUpdate) {
		handlers.Update = func(ctx context.Context, input mcpserver.HostAPTUpdateInput) (mcpserver.HostAPTActionResult, error) {
			if input.HostID != "" {
				return mcpserver.HostAPTActionResult{}, fmt.Errorf("host_id must be omitted for local stdio APT actions")
			}
			return s.execute(ctx, hostops.OperationAPTUpdate, nil)
		}
	}
	if policyAllowsOperation(s.policy, hostops.APTPolicyInstall) {
		handlers.Install = func(ctx context.Context, input mcpserver.HostAPTActionInput) (mcpserver.HostAPTActionResult, error) {
			if input.HostID != "" {
				return mcpserver.HostAPTActionResult{}, fmt.Errorf("host_id must be omitted for local stdio APT actions")
			}
			return s.execute(ctx, hostops.OperationAPTInstall, input.Packages)
		}
	}
	if policyAllowsOperation(s.policy, hostops.APTPolicyRemove) {
		handlers.Remove = func(ctx context.Context, input mcpserver.HostAPTActionInput) (mcpserver.HostAPTActionResult, error) {
			if input.HostID != "" {
				return mcpserver.HostAPTActionResult{}, fmt.Errorf("host_id must be omitted for local stdio APT actions")
			}
			return s.execute(ctx, hostops.OperationAPTRemove, input.Packages)
		}
	}
	if policyAllowsOperation(s.policy, hostops.APTPolicyUpgrade) {
		handlers.Upgrade = func(ctx context.Context, input mcpserver.HostAPTActionInput) (mcpserver.HostAPTActionResult, error) {
			if input.HostID != "" {
				return mcpserver.HostAPTActionResult{}, fmt.Errorf("host_id must be omitted for local stdio APT actions")
			}
			return s.execute(ctx, hostops.OperationAPTUpgrade, input.Packages)
		}
	}
	if policyAllowsOperation(s.policy, hostops.APTPolicyRollback) {
		handlers.Rollback = func(ctx context.Context, input mcpserver.HostAPTRollbackInput) (mcpserver.HostAPTRollbackResult, error) {
			if input.HostID != "" {
				return mcpserver.HostAPTRollbackResult{}, fmt.Errorf("host_id must be omitted for local stdio APT actions")
			}
			return s.rollback(ctx, input.ActionID)
		}
	}
	return handlers
}

func (s *ActionStore) execute(ctx context.Context, operation string, packages []string) (mcpserver.HostAPTActionResult, error) {
	validated, err := hostops.ValidateAPTAction(s.policy, operation, packages)
	if err != nil {
		return mcpserver.HostAPTActionResult{}, err
	}
	unlock, err := s.acquire(ctx)
	if err != nil {
		return mcpserver.HostAPTActionResult{}, err
	}
	defer unlock()
	state, err := s.readState()
	if err != nil {
		return mcpserver.HostAPTActionResult{}, err
	}
	if s.prune(&state, time.Now().UTC()) {
		if err := s.writeState(state); err != nil {
			return mcpserver.HostAPTActionResult{}, err
		}
	}
	if len(state.Actions) >= maxLocalActionCount {
		return mcpserver.HostAPTActionResult{}, fmt.Errorf("local APT action store has reached its %d-record limit", maxLocalActionCount)
	}
	actionResult, err := hostops.RunAPTAction(ctx, operation, validated, s.policy, s.runner)
	if err != nil {
		return mcpserver.HostAPTActionResult{}, err
	}
	createdAt := time.Now().UTC()
	actionID := uuid.NewString()
	payload := actionPayload{Operation: operation, RequestedPackages: validated, Result: actionResult}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return mcpserver.HostAPTActionResult{}, fmt.Errorf("encode local APT action audit data")
	}
	sealed, err := s.cipher.Seal(encoded, localActionAssociatedData(actionID))
	if err != nil {
		return mcpserver.HostAPTActionResult{}, fmt.Errorf("encrypt local APT action audit data")
	}
	state.Actions = append(state.Actions, actionRecord{
		ID: actionID, CreatedAt: createdAt, ExpiresAt: createdAt.Add(localActionRetention),
		Status: actionStatus(actionResult.RollbackAvailable), Payload: sealed,
	})
	if err := s.writeState(state); err != nil {
		return mcpserver.HostAPTActionResult{}, fmt.Errorf("persist encrypted local APT action: %w", err)
	}
	return mcpserver.HostAPTActionResult{
		ActionID: actionID, Operation: actionResult.Operation, Outcome: actionResult.Outcome,
		ChangedPackages:   countChanged(actionResult.Before, actionResult.After),
		RollbackAvailable: actionResult.RollbackAvailable, ExpiresAt: createdAt.Add(localActionRetention),
		Reason: actionResult.Reason,
	}, nil
}

func (s *ActionStore) rollback(ctx context.Context, rawActionID string) (mcpserver.HostAPTRollbackResult, error) {
	actionID, err := uuid.Parse(rawActionID)
	if err != nil {
		return mcpserver.HostAPTRollbackResult{}, fmt.Errorf("local APT action was not found or has expired")
	}
	unlock, err := s.acquire(ctx)
	if err != nil {
		return mcpserver.HostAPTRollbackResult{}, err
	}
	defer unlock()
	state, err := s.readState()
	if err != nil {
		return mcpserver.HostAPTRollbackResult{}, err
	}
	if s.prune(&state, time.Now().UTC()) {
		if err := s.writeState(state); err != nil {
			return mcpserver.HostAPTRollbackResult{}, err
		}
	}
	index := -1
	for i := range state.Actions {
		if state.Actions[i].ID == actionID.String() {
			index = i
			break
		}
	}
	if index < 0 {
		return mcpserver.HostAPTRollbackResult{}, fmt.Errorf("local APT action was not found or has expired")
	}
	record := &state.Actions[index]
	payload, err := s.openPayload(*record)
	if err != nil {
		return mcpserver.HostAPTRollbackResult{}, err
	}
	if record.Status == "rolled_back" {
		if payload.RollbackResult == nil {
			return mcpserver.HostAPTRollbackResult{}, fmt.Errorf("local APT rollback record is incomplete")
		}
		return rollbackReceipt(actionID.String(), *payload.RollbackResult, true), nil
	}
	if record.Status == "not_reversible" {
		return mcpserver.HostAPTRollbackResult{}, fmt.Errorf("local APT action does not have complete rollback data")
	}
	if record.Status != "available" {
		return mcpserver.HostAPTRollbackResult{}, fmt.Errorf("local APT action rollback is already in progress")
	}
	if err := validateActionPayload(payload); err != nil {
		return mcpserver.HostAPTRollbackResult{}, err
	}
	now := time.Now().UTC()
	record.Status = "rolling_back"
	record.RollbackStartedAt = &now
	if err := s.writeState(state); err != nil {
		return mcpserver.HostAPTRollbackResult{}, fmt.Errorf("reserve local APT rollback: %w", err)
	}
	rollbackResult, runErr := hostops.RestoreAPTAction(ctx, payload.Result.Before, payload.Result.After, s.policy, s.runner)
	if runErr != nil {
		record.Status = "available"
		record.RollbackStartedAt = nil
		if err := s.writeState(state); err != nil {
			return mcpserver.HostAPTRollbackResult{}, fmt.Errorf("APT rollback failed (%v) and the retry state could not be saved: %w", runErr, err)
		}
		return mcpserver.HostAPTRollbackResult{}, runErr
	}
	payload.RollbackResult = &rollbackResult
	encoded, err := json.Marshal(payload)
	if err != nil {
		record.Status = "available"
		record.RollbackStartedAt = nil
		_ = s.writeState(state)
		return mcpserver.HostAPTRollbackResult{}, fmt.Errorf("encode local APT rollback audit data")
	}
	record.Payload, err = s.cipher.Seal(encoded, localActionAssociatedData(actionID.String()))
	if err != nil {
		record.Status = "available"
		record.RollbackStartedAt = nil
		_ = s.writeState(state)
		return mcpserver.HostAPTRollbackResult{}, fmt.Errorf("encrypt local APT rollback audit data")
	}
	record.RollbackStartedAt = nil
	if rollbackResult.Outcome == hostops.APTOutcomeSucceeded {
		record.Status = "rolled_back"
	} else {
		record.Status = "available"
	}
	if err := s.writeState(state); err != nil {
		return mcpserver.HostAPTRollbackResult{}, fmt.Errorf("persist local APT rollback result: %w", err)
	}
	return rollbackReceipt(actionID.String(), rollbackResult, false), nil
}

func (s *ActionStore) Cleanup(ctx context.Context) error {
	unlock, err := s.acquire(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	state, err := s.readState()
	if err != nil {
		return err
	}
	if s.prune(&state, time.Now().UTC()) {
		return s.writeState(state)
	}
	return nil
}

// RunCleanup removes expired encrypted action records while the local MCP
// server is running. It returns when ctx is cancelled.
func (s *ActionStore) RunCleanup(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = s.Cleanup(ctx)
		}
	}
}

func (s *ActionStore) acquire(ctx context.Context) (func(), error) {
	s.mu.Lock()
	lockPath := s.path + ".lock"
	fd, err := syscall.Open(lockPath, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("open local APT action-store lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), lockPath)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !ownedByCurrentUser(info) {
		_ = file.Close()
		s.mu.Unlock()
		return nil, fmt.Errorf("local APT action-store lock must be a private regular file owned by the current user")
	}
	for {
		err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() {
				_ = syscall.Flock(fd, syscall.LOCK_UN)
				_ = file.Close()
				s.mu.Unlock()
			}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			_ = file.Close()
			s.mu.Unlock()
			return nil, fmt.Errorf("lock local APT action store: %w", err)
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			s.mu.Unlock()
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (s *ActionStore) readState() (diskState, error) {
	fd, err := syscall.Open(s.path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, syscall.ENOENT) {
		return diskState{Version: localStoreVersion, Actions: []actionRecord{}}, nil
	}
	if err != nil {
		return diskState{}, fmt.Errorf("open local APT action store: %w", err)
	}
	file := os.NewFile(uintptr(fd), s.path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !ownedByCurrentUser(info) {
		return diskState{}, fmt.Errorf("local APT action store must be a private regular file owned by the current user with mode 0600")
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maxLocalStoreBytes+1))
	if err != nil {
		return diskState{}, fmt.Errorf("read local APT action store: %w", err)
	}
	if len(encoded) > maxLocalStoreBytes {
		return diskState{}, fmt.Errorf("local APT action store exceeds %d bytes", maxLocalStoreBytes)
	}
	var state diskState
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return diskState{}, fmt.Errorf("decode local APT action store: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return diskState{}, fmt.Errorf("local APT action store must contain one JSON object")
	}
	if state.Version != localStoreVersion || len(state.Actions) > maxLocalActionCount {
		return diskState{}, fmt.Errorf("local APT action store has an unsupported version or record count")
	}
	for _, record := range state.Actions {
		if _, err := uuid.Parse(record.ID); err != nil || record.CreatedAt.IsZero() || !record.ExpiresAt.After(record.CreatedAt) || !json.Valid(record.Payload) {
			return diskState{}, fmt.Errorf("local APT action store contains an invalid record")
		}
		switch record.Status {
		case "available", "rolling_back", "rolled_back", "not_reversible":
		default:
			return diskState{}, fmt.Errorf("local APT action store contains an unsupported record status")
		}
		if (record.Status == "rolling_back") != (record.RollbackStartedAt != nil) {
			return diskState{}, fmt.Errorf("local APT action store has inconsistent rollback metadata")
		}
	}
	return state, nil
}

func (s *ActionStore) writeState(state diskState) error {
	encoded, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode local APT action store")
	}
	if len(encoded) > maxLocalStoreBytes {
		return fmt.Errorf("local APT action store would exceed %d bytes", maxLocalStoreBytes)
	}
	temporary, err := os.CreateTemp(filepath.Dir(s.path), ".apt-actions-*.tmp")
	if err != nil {
		return fmt.Errorf("create private local APT action-store file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("secure local APT action-store file: %w", err)
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write local APT action store: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("flush local APT action store: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close local APT action store: %w", err)
	}
	if err := os.Rename(temporaryPath, s.path); err != nil {
		return fmt.Errorf("replace local APT action store: %w", err)
	}
	directory, err := os.Open(filepath.Dir(s.path))
	if err != nil {
		return fmt.Errorf("open local APT action-store directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("flush local APT action-store directory: %w", err)
	}
	return nil
}

func (s *ActionStore) prune(state *diskState, now time.Time) bool {
	changed := false
	active := state.Actions[:0]
	for _, record := range state.Actions {
		if !record.ExpiresAt.After(now) {
			changed = true
			continue
		}
		if record.Status == "rolling_back" && record.RollbackStartedAt != nil && record.RollbackStartedAt.Before(now.Add(-localRollbackStale)) {
			record.Status = "available"
			record.RollbackStartedAt = nil
			changed = true
		}
		active = append(active, record)
	}
	state.Actions = active
	return changed
}

func (s *ActionStore) openPayload(record actionRecord) (actionPayload, error) {
	encoded, err := s.cipher.Open(record.Payload, localActionAssociatedData(record.ID))
	if err != nil {
		return actionPayload{}, fmt.Errorf("decrypt local APT action record")
	}
	var payload actionPayload
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return actionPayload{}, fmt.Errorf("decode local APT action record")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return actionPayload{}, fmt.Errorf("local APT action record must contain one JSON object")
	}
	return payload, nil
}

func validateActionPayload(payload actionPayload) error {
	if payload.Operation == hostops.OperationAPTUpdate || !payload.Result.RollbackAvailable {
		return fmt.Errorf("local APT action does not have complete rollback data")
	}
	input, err := json.Marshal(hostops.APTActionInput{Packages: payload.RequestedPackages})
	if err != nil {
		return fmt.Errorf("local APT rollback record is invalid")
	}
	result, err := json.Marshal(payload.Result)
	if err != nil || hostops.ValidateJobResult(payload.Operation, input, result) != nil {
		return fmt.Errorf("local APT rollback record is invalid")
	}
	return nil
}

func actionStatus(rollbackAvailable bool) string {
	if rollbackAvailable {
		return "available"
	}
	return "not_reversible"
}

func countChanged(before, after []hostops.PackageState) int {
	current := make(map[string]hostops.PackageState, len(after))
	for _, state := range after {
		current[state.Name] = state
	}
	count := 0
	for _, state := range before {
		if current[state.Name] != state {
			count++
		}
	}
	return count
}

func rollbackReceipt(actionID string, result hostops.APTRollbackResult, alreadyRestored bool) mcpserver.HostAPTRollbackResult {
	restored := 0
	reason := ""
	for _, packageResult := range result.Packages {
		if packageResult.Exact {
			restored++
		} else if reason == "" {
			reason = packageResult.Reason
		}
	}
	return mcpserver.HostAPTRollbackResult{
		ActionID: actionID, Outcome: result.Outcome, RestoredPackages: restored,
		Exact: result.Outcome == hostops.APTOutcomeSucceeded, AlreadyRestored: alreadyRestored,
		Packages: result.Packages, Reason: reason,
	}
}

func localActionAssociatedData(actionID string) []byte {
	return []byte("ubuntu-fleet-manager:local-apt-action:v1:" + actionID)
}

func policyAllowsOperation(policy hostops.APTPolicy, operation string) bool {
	for _, allowed := range policy.AllowedOperations {
		if allowed == operation {
			return true
		}
	}
	return false
}

func ensurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create local APT action-store directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 || !ownedByCurrentUser(info) {
		return fmt.Errorf("local APT action-store directory must be private and owned by the current user")
	}
	return nil
}
