package hostops

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const (
	OperationGetSystemInfo  = "get_system_info"
	OperationListDirectory  = "list_directory"
	OperationReadFile       = "read_file"
	OperationSearchPackages = "search_packages"
	OperationWriteFile      = "write_file"
	OperationRestoreFile    = "restore_file"
	OperationExecuteCommand = "execute_command"
	MaxWriteFileBytes       = 256 << 10
)

type PathInput struct {
	Path string `json:"path"`
}

type PackageSearchInput struct {
	Query string `json:"query"`
	Limit int    `json:"limit,omitempty"`
}

type APTActionInput struct {
	Packages []string `json:"packages,omitempty"`
}

type APTRollbackInput struct {
	Previous        []PackageState `json:"previous"`
	ExpectedCurrent []PackageState `json:"expected_current"`
}

type WriteFileInput struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type FileState struct {
	Existed bool   `json:"existed"`
	Content []byte `json:"content,omitempty"`
	Mode    uint32 `json:"mode,omitempty"`
}

type FileFingerprint struct {
	Existed bool   `json:"existed"`
	SHA256  string `json:"sha256,omitempty"`
	Mode    uint32 `json:"mode,omitempty"`
}

type WriteFileResult struct {
	Path     string          `json:"path"`
	Previous FileState       `json:"previous"`
	Current  FileFingerprint `json:"current"`
}

type RestoreFileInput struct {
	Path            string          `json:"path"`
	Previous        FileState       `json:"previous"`
	ExpectedCurrent FileFingerprint `json:"expected_current"`
}

type RestoreFileResult struct {
	Path     string `json:"path"`
	Restored bool   `json:"restored"`
	Exact    bool   `json:"exact"`
	Reason   string `json:"reason,omitempty"`
}

func ValidateJobInput(operation string, input json.RawMessage) (json.RawMessage, error) {
	if len(input) == 0 {
		input = json.RawMessage(`{}`)
	}
	switch operation {
	case OperationGetSystemInfo:
		var fields map[string]json.RawMessage
		if err := decodeStrictObject(input, &fields); err != nil {
			return nil, fmt.Errorf("system-info input must be an empty object: %w", err)
		}
		if len(fields) != 0 {
			return nil, fmt.Errorf("system-info input must be an empty object")
		}
		return json.RawMessage(`{}`), nil
	case OperationListDirectory, OperationReadFile:
		var pathInput PathInput
		if err := decodeStrictObject(input, &pathInput); err != nil {
			return nil, fmt.Errorf("file operation input is invalid: %w", err)
		}
		if err := ValidatePath(pathInput.Path); err != nil {
			return nil, err
		}
		return json.Marshal(pathInput)
	case OperationWriteFile:
		var writeInput WriteFileInput
		if err := decodeStrictObject(input, &writeInput); err != nil {
			return nil, fmt.Errorf("write-file input is invalid: %w", err)
		}
		if err := validateWriteFileInput(writeInput); err != nil {
			return nil, err
		}
		return json.Marshal(writeInput)
	case OperationRestoreFile:
		var restoreInput RestoreFileInput
		if err := decodeStrictObject(input, &restoreInput); err != nil {
			return nil, fmt.Errorf("restore-file input is invalid: %w", err)
		}
		if err := validateRestoreFileInput(restoreInput); err != nil {
			return nil, err
		}
		return json.Marshal(restoreInput)
	case OperationSearchPackages:
		var searchInput PackageSearchInput
		if err := decodeStrictObject(input, &searchInput); err != nil {
			return nil, fmt.Errorf("package search input is invalid: %w", err)
		}
		query, limit, err := ValidatePackageSearchInput(searchInput.Query, searchInput.Limit)
		if err != nil {
			return nil, err
		}
		return json.Marshal(PackageSearchInput{Query: query, Limit: limit})
	case OperationExecuteCommand:
		var commandInput CommandInput
		if err := decodeStrictObject(input, &commandInput); err != nil {
			return nil, fmt.Errorf("command input is invalid: %w", err)
		}
		if err := validateCommandInput(commandInput); err != nil {
			return nil, err
		}
		return json.Marshal(commandInput)
	case OperationAPTUpdate:
		var fields map[string]json.RawMessage
		if err := decodeStrictObject(input, &fields); err != nil || len(fields) != 0 {
			return nil, fmt.Errorf("APT update input must be an empty object")
		}
		return json.RawMessage(`{}`), nil
	case OperationAPTInstall, OperationAPTRemove, OperationAPTUpgrade:
		var actionInput APTActionInput
		if err := decodeStrictObject(input, &actionInput); err != nil {
			return nil, fmt.Errorf("APT action input is invalid: %w", err)
		}
		packages, err := ValidateAPTActionInput(operation, actionInput.Packages)
		if err != nil {
			return nil, err
		}
		return json.Marshal(APTActionInput{Packages: packages})
	case OperationAPTRollback:
		var rollbackInput APTRollbackInput
		if err := decodeStrictObject(input, &rollbackInput); err != nil {
			return nil, fmt.Errorf("APT rollback input is invalid: %w", err)
		}
		if err := validateAPTRollbackInput(rollbackInput); err != nil {
			return nil, err
		}
		return json.Marshal(rollbackInput)
	default:
		return nil, fmt.Errorf("unsupported host operation %q", operation)
	}
}

func ValidateJobResult(operation string, input, encoded json.RawMessage) error {
	if len(encoded) == 0 {
		return fmt.Errorf("host operation result is empty")
	}
	switch operation {
	case OperationListDirectory:
		var request PathInput
		if err := decodeStrictObject(input, &request); err != nil {
			return fmt.Errorf("directory request is invalid: %w", err)
		}
		var result DirectoryListing
		if err := decodeStrictObject(encoded, &result); err != nil {
			return fmt.Errorf("directory result is invalid: %w", err)
		}
		if err := ValidatePath(result.Path); err != nil || filepath.Clean(result.Path) != filepath.Clean(request.Path) {
			return fmt.Errorf("directory result path does not match the request")
		}
		if len(result.Entries) > MaxDirectoryEntries {
			return fmt.Errorf("directory result exceeds the %d-entry limit", MaxDirectoryEntries)
		}
		for _, entry := range result.Entries {
			if entry.Name == "" || entry.Name == "." || entry.Name == ".." || len(entry.Name) > 255 || !utf8.ValidString(entry.Name) || strings.ContainsRune(entry.Name, filepath.Separator) {
				return fmt.Errorf("directory result contains an invalid entry name")
			}
			if entry.Path != filepath.Join(result.Path, entry.Name) || entry.SizeBytes < 0 || entry.Mode == "" {
				return fmt.Errorf("directory result contains invalid entry metadata")
			}
			switch entry.Type {
			case "file", "directory", "other":
				if entry.IsSymlink {
					return fmt.Errorf("directory result has inconsistent symlink metadata")
				}
			case "symlink":
				if !entry.IsSymlink {
					return fmt.Errorf("directory result has inconsistent symlink metadata")
				}
			default:
				return fmt.Errorf("directory result contains an unknown entry type")
			}
		}
		return nil
	case OperationReadFile:
		var request PathInput
		if err := decodeStrictObject(input, &request); err != nil {
			return fmt.Errorf("file request is invalid: %w", err)
		}
		var result FileReadResult
		if err := decodeStrictObject(encoded, &result); err != nil {
			return fmt.Errorf("file result is invalid: %w", err)
		}
		if err := ValidatePath(result.Path); err != nil || filepath.Clean(result.Path) != filepath.Clean(request.Path) {
			return fmt.Errorf("file result path does not match the request")
		}
		if len(result.Content) > MaxReadFileBytes || !utf8.ValidString(result.Content) || result.SizeBytes != int64(len(result.Content)) {
			return fmt.Errorf("file result exceeds the text or size limit")
		}
		return nil
	case OperationWriteFile:
		var request WriteFileInput
		if err := decodeStrictObject(input, &request); err != nil || validateWriteFileInput(request) != nil {
			return fmt.Errorf("write-file request is invalid")
		}
		var result WriteFileResult
		if err := decodeStrictObject(encoded, &result); err != nil {
			return fmt.Errorf("write-file result is invalid: %w", err)
		}
		if err := ValidatePath(result.Path); err != nil || filepath.Clean(result.Path) != filepath.Clean(request.Path) {
			return fmt.Errorf("write-file result path does not match the request")
		}
		if err := validateFileState(result.Previous); err != nil {
			return fmt.Errorf("write-file result contains invalid prior state: %w", err)
		}
		if err := validateFileFingerprint(result.Current); err != nil || !result.Current.Existed {
			return fmt.Errorf("write-file result contains an invalid current-file fingerprint")
		}
		expectedMode := uint32(0o600)
		if result.Previous.Existed {
			expectedMode = result.Previous.Mode
		}
		if result.Current.Mode != expectedMode {
			return fmt.Errorf("write-file result does not preserve the captured mode policy")
		}
		if result.Current.SHA256 != sha256String([]byte(request.Content)) {
			return fmt.Errorf("write-file result does not match the requested contents")
		}
		return nil
	case OperationRestoreFile:
		var request RestoreFileInput
		if err := decodeStrictObject(input, &request); err != nil || validateRestoreFileInput(request) != nil {
			return fmt.Errorf("restore-file request is invalid")
		}
		var result RestoreFileResult
		if err := decodeStrictObject(encoded, &result); err != nil {
			return fmt.Errorf("restore-file result is invalid: %w", err)
		}
		if err := ValidatePath(result.Path); err != nil || filepath.Clean(result.Path) != filepath.Clean(request.Path) {
			return fmt.Errorf("restore-file result path does not match the request")
		}
		if result.Exact != result.Restored || (result.Exact && result.Reason != "") || (!result.Exact && result.Reason == "") || len(result.Reason) > 1024 || !utf8.ValidString(result.Reason) || strings.ContainsAny(result.Reason, "\r\n\x00") {
			return fmt.Errorf("restore-file result has inconsistent restoration status")
		}
		return nil
	case OperationSearchPackages:
		var request PackageSearchInput
		if err := decodeStrictObject(input, &request); err != nil {
			return fmt.Errorf("package search request is invalid: %w", err)
		}
		query, limit, err := ValidatePackageSearchInput(request.Query, request.Limit)
		if err != nil {
			return err
		}
		var result PackageSearchResult
		if err := decodeStrictObject(encoded, &result); err != nil {
			return fmt.Errorf("package search result is invalid: %w", err)
		}
		if result.Query != query || len(result.Packages) > limit {
			return fmt.Errorf("package search result does not match the request or result limit")
		}
		for _, entry := range result.Packages {
			if entry.Name == "" || len(entry.Name) > MaxPackageNameBytes || !utf8.ValidString(entry.Name) || len(entry.Description) > MaxPackageDescriptionBytes || !utf8.ValidString(entry.Description) || strings.ContainsAny(entry.Name, "\r\n") || strings.ContainsAny(entry.Description, "\r\n") {
				return fmt.Errorf("package search result contains an invalid package entry")
			}
		}
		return nil
	case OperationExecuteCommand:
		var request CommandInput
		if err := decodeStrictObject(input, &request); err != nil || validateCommandInput(request) != nil {
			return fmt.Errorf("command request is invalid")
		}
		var result CommandResult
		if err := decodeStrictObject(encoded, &result); err != nil {
			return fmt.Errorf("command result is invalid: %w", err)
		}
		if result.ExitCode < -1 || result.ExitCode > 255 || len(result.Stdout)+len(result.Stderr) > MaxCommandOutputBytes || !utf8.ValidString(result.Stdout) || !utf8.ValidString(result.Stderr) {
			return fmt.Errorf("command result exceeds its exit-code or output limit")
		}
		sanitized := SanitizeCommandResult(result)
		if sanitized.Stdout != result.Stdout || sanitized.Stderr != result.Stderr || sanitized.OutputTruncated != result.OutputTruncated {
			return fmt.Errorf("command result is not bounded and redacted")
		}
		return nil
	case OperationAPTUpdate, OperationAPTInstall, OperationAPTRemove, OperationAPTUpgrade:
		var actionInput APTActionInput
		if operation != OperationAPTUpdate {
			if err := decodeStrictObject(input, &actionInput); err != nil {
				return fmt.Errorf("APT action request is invalid: %w", err)
			}
			if _, err := ValidateAPTActionInput(operation, actionInput.Packages); err != nil {
				return err
			}
		}
		var result APTActionResult
		if err := decodeStrictObject(encoded, &result); err != nil {
			return fmt.Errorf("APT action result is invalid: %w", err)
		}
		if result.Operation != operation || !validAPTOutcome(result.Outcome) || !validAPTResultReason(result.Reason) || (result.Outcome == APTOutcomeSucceeded) != (result.Reason == "") {
			return fmt.Errorf("APT action result has an invalid operation or outcome")
		}
		if operation == OperationAPTUpdate {
			if len(result.Before) != 0 || len(result.After) != 0 || result.RollbackAvailable {
				return fmt.Errorf("APT index refresh result cannot include package rollback state")
			}
		} else {
			if err := validatePackageStates(result.Before, true); err != nil {
				return fmt.Errorf("APT action pre-state is invalid: %w", err)
			}
			if err := validatePackageStates(result.After, true); err != nil {
				return fmt.Errorf("APT action post-state is invalid: %w", err)
			}
			if len(result.Before) != len(result.After) || !samePackageStateNames(result.Before, result.After) {
				return fmt.Errorf("APT action pre-state and post-state names do not match")
			}
			if result.RollbackAvailable && (result.Outcome == APTOutcomeUnknown || len(result.Before) == 0) {
				return fmt.Errorf("APT action cannot offer rollback without complete package state")
			}
		}
		return nil
	case OperationAPTRollback:
		var rollbackInput APTRollbackInput
		if err := decodeStrictObject(input, &rollbackInput); err != nil {
			return fmt.Errorf("APT rollback request is invalid: %w", err)
		}
		if err := validateAPTRollbackInput(rollbackInput); err != nil {
			return err
		}
		var result APTRollbackResult
		if err := decodeStrictObject(encoded, &result); err != nil {
			return fmt.Errorf("APT rollback result is invalid: %w", err)
		}
		if !validAPTOutcome(result.Outcome) || len(result.Packages) != len(rollbackInput.Previous) {
			return fmt.Errorf("APT rollback result does not match the captured package state")
		}
		seen := make(map[string]struct{}, len(result.Packages))
		for _, packageResult := range result.Packages {
			if !aptPackageNamePattern.MatchString(packageResult.Name) || packageResult.Exact != packageResult.Restored || !validAPTResultReason(packageResult.Reason) || (packageResult.Exact && packageResult.Reason != "") || (!packageResult.Exact && packageResult.Reason == "") {
				return fmt.Errorf("APT rollback result contains an invalid package status")
			}
			if _, duplicate := seen[packageResult.Name]; duplicate {
				return fmt.Errorf("APT rollback result contains a duplicate package")
			}
			seen[packageResult.Name] = struct{}{}
		}
		for _, state := range rollbackInput.Previous {
			if _, exists := seen[state.Name]; !exists {
				return fmt.Errorf("APT rollback result omits a captured package")
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported host operation %q", operation)
	}
}

func validateCommandInput(input CommandInput) error {
	if err := validateCommandPath(input.Executable); err != nil {
		return err
	}
	if err := validateCommandArguments(input.Arguments); err != nil {
		return err
	}
	if input.WorkingDirectory != "" && (!filepath.IsAbs(input.WorkingDirectory) || filepath.Clean(input.WorkingDirectory) != input.WorkingDirectory || strings.ContainsRune(input.WorkingDirectory, '\x00')) {
		return fmt.Errorf("command working directory must be an absolute, clean path")
	}
	return nil
}

func validateAPTRollbackInput(input APTRollbackInput) error {
	if len(input.Previous) == 0 || len(input.Previous) != len(input.ExpectedCurrent) || len(input.Previous) > MaxAPTActionStates {
		return fmt.Errorf("APT rollback package state is incomplete or exceeds the safety limit")
	}
	previous := make(map[string]struct{}, len(input.Previous))
	current := make(map[string]struct{}, len(input.ExpectedCurrent))
	for _, state := range input.Previous {
		if err := validatePackageState(state); err != nil {
			return err
		}
		if _, duplicate := previous[state.Name]; duplicate {
			return fmt.Errorf("APT rollback contains duplicate package state")
		}
		previous[state.Name] = struct{}{}
	}
	for _, state := range input.ExpectedCurrent {
		if err := validatePackageState(state); err != nil {
			return err
		}
		if _, duplicate := current[state.Name]; duplicate {
			return fmt.Errorf("APT rollback contains duplicate expected package state")
		}
		current[state.Name] = struct{}{}
	}
	if len(previous) != len(current) {
		return fmt.Errorf("APT rollback package state names do not match")
	}
	for name := range previous {
		if _, ok := current[name]; !ok {
			return fmt.Errorf("APT rollback package state names do not match")
		}
	}
	return nil
}

func validatePackageStates(states []PackageState, allowEmpty bool) error {
	if !allowEmpty && len(states) == 0 {
		return fmt.Errorf("package state is empty")
	}
	if len(states) > MaxAPTActionStates {
		return fmt.Errorf("package state exceeds the safety limit")
	}
	seen := make(map[string]struct{}, len(states))
	for _, state := range states {
		if err := validatePackageState(state); err != nil {
			return err
		}
		if _, duplicate := seen[state.Name]; duplicate {
			return fmt.Errorf("package state contains duplicate package names")
		}
		seen[state.Name] = struct{}{}
	}
	return nil
}

func samePackageStateNames(left, right []PackageState) bool {
	if len(left) != len(right) {
		return false
	}
	names := make(map[string]struct{}, len(left))
	for _, state := range left {
		names[state.Name] = struct{}{}
	}
	for _, state := range right {
		if _, ok := names[state.Name]; !ok {
			return false
		}
	}
	return true
}

func validAPTOutcome(outcome string) bool {
	switch outcome {
	case APTOutcomeSucceeded, APTOutcomeFailed, APTOutcomePartial, APTOutcomeUnknown:
		return true
	default:
		return false
	}
}

func validAPTResultReason(reason string) bool {
	return len(reason) <= 1024 && utf8.ValidString(reason) && !strings.ContainsAny(reason, "\r\n\x00")
}

func validateWriteFileInput(input WriteFileInput) error {
	if err := ValidatePath(input.Path); err != nil {
		return err
	}
	if len(input.Content) > MaxWriteFileBytes || !utf8.ValidString(input.Content) {
		return fmt.Errorf("file content must be valid UTF-8 text of at most %d bytes", MaxWriteFileBytes)
	}
	return nil
}

func validateRestoreFileInput(input RestoreFileInput) error {
	if err := ValidatePath(input.Path); err != nil {
		return err
	}
	if err := validateFileState(input.Previous); err != nil {
		return err
	}
	if err := validateFileFingerprint(input.ExpectedCurrent); err != nil {
		return err
	}
	if !input.ExpectedCurrent.Existed {
		return fmt.Errorf("expected current file state must exist")
	}
	return nil
}

func validateFileState(state FileState) error {
	if !state.Existed {
		if len(state.Content) != 0 || state.Mode != 0 {
			return fmt.Errorf("absent prior state must not contain bytes or a mode")
		}
		return nil
	}
	if len(state.Content) > MaxWriteFileBytes || state.Mode > 0o777 {
		return fmt.Errorf("captured file state exceeds the supported byte or mode limit")
	}
	return nil
}

func validateFileFingerprint(fingerprint FileFingerprint) error {
	if !fingerprint.Existed {
		if fingerprint.SHA256 != "" || fingerprint.Mode != 0 {
			return fmt.Errorf("absent file fingerprint must not contain a hash or mode")
		}
		return nil
	}
	if len(fingerprint.SHA256) != 64 || fingerprint.Mode > 0o777 {
		return fmt.Errorf("file fingerprint hash or mode is invalid")
	}
	for _, character := range fingerprint.SHA256 {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return fmt.Errorf("file fingerprint hash is invalid")
		}
	}
	return nil
}

func sha256String(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func decodeStrictObject(encoded []byte, destination any) error {
	encoded = bytes.TrimSpace(encoded)
	if len(encoded) == 0 || encoded[0] != '{' {
		return fmt.Errorf("input must be a JSON object")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("input must contain one JSON object")
	}
	return nil
}
