package hostops

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestValidateJobInputNormalizesTypedRequests(t *testing.T) {
	path := "/home/agent/settings.conf"
	encoded, err := ValidateJobInput(OperationReadFile, json.RawMessage(fmt.Sprintf(`{"path":%q}`, path)))
	if err != nil {
		t.Fatalf("validate read-file input: %v", err)
	}
	var pathInput PathInput
	if err := json.Unmarshal(encoded, &pathInput); err != nil || pathInput.Path != path {
		t.Fatalf("normalized path input = %s; decoded %#v, error %v", encoded, pathInput, err)
	}

	encoded, err = ValidateJobInput(OperationSearchPackages, json.RawMessage(`{"query":"  apt  "}`))
	if err != nil {
		t.Fatalf("validate package-search input: %v", err)
	}
	var packageInput PackageSearchInput
	if err := json.Unmarshal(encoded, &packageInput); err != nil {
		t.Fatalf("decode normalized package-search input: %v", err)
	}
	if packageInput.Query != "apt" || packageInput.Limit != DefaultPackageSearchResults {
		t.Fatalf("normalized package input = %#v, want trimmed query and default result limit", packageInput)
	}

	encoded, err = ValidateJobInput(OperationGetSystemInfo, nil)
	if err != nil || string(encoded) != `{}` {
		t.Fatalf("empty system-info input = %s, error %v; want {}", encoded, err)
	}
}

func TestValidateJobInputRejectsUnexpectedAndUnboundedFields(t *testing.T) {
	tests := []struct {
		operation string
		input     string
	}{
		{OperationReadFile, `{"path":"/home/agent/file","max_bytes":999999999}`},
		{OperationReadFile, `{"path":"relative/file"}`},
		{OperationListDirectory, `{"path":"/home/agent/../etc/passwd"}`},
		{OperationSearchPackages, `{"query":"apt","limit":101}`},
		{OperationSearchPackages, `{"query":"apt","extra":"ignored"}`},
		{OperationGetSystemInfo, `{"unexpected":true}`},
		{"execute_command", `{}`},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("%s-%s", test.operation, strings.ReplaceAll(test.input, "/", "_")), func(t *testing.T) {
			if _, err := ValidateJobInput(test.operation, json.RawMessage(test.input)); err == nil {
				t.Fatalf("accepted invalid %s input %s", test.operation, test.input)
			}
		})
	}
}

func TestValidateJobResultEnforcesRequestAndOutputBounds(t *testing.T) {
	path := "/home/agent/settings.conf"
	request := json.RawMessage(fmt.Sprintf(`{"path":%q}`, path))
	validFile := json.RawMessage(fmt.Sprintf(`{"path":%q,"content":"mode=safe\n","size_bytes":10}`, path))
	if err := ValidateJobResult(OperationReadFile, request, validFile); err != nil {
		t.Fatalf("validate bounded file result: %v", err)
	}

	invalidFileResults := []json.RawMessage{
		json.RawMessage(fmt.Sprintf(`{"path":%q,"content":"secret","size_bytes":5}`, path)),
		json.RawMessage(`{"path":"/etc/passwd","content":"secret","size_bytes":6}`),
		json.RawMessage(fmt.Sprintf(`{"path":%q,"content":%q,"size_bytes":%d}`, path, strings.Repeat("x", MaxReadFileBytes+1), MaxReadFileBytes+1)),
	}
	for _, invalid := range invalidFileResults {
		if err := ValidateJobResult(OperationReadFile, request, invalid); err == nil {
			t.Errorf("accepted invalid file result %s", invalid)
		}
	}

	packageInput, err := ValidateJobInput(OperationSearchPackages, json.RawMessage(`{"query":"apt","limit":1}`))
	if err != nil {
		t.Fatal(err)
	}
	validPackages := json.RawMessage(`{"query":"apt","packages":[{"name":"apt","description":"package manager"}],"truncated":false}`)
	if err := ValidateJobResult(OperationSearchPackages, packageInput, validPackages); err != nil {
		t.Fatalf("validate bounded package result: %v", err)
	}
	tooManyPackages := json.RawMessage(`{"query":"apt","packages":[{"name":"apt","description":"one"},{"name":"apt-doc","description":"two"}],"truncated":false}`)
	if err := ValidateJobResult(OperationSearchPackages, packageInput, tooManyPackages); err == nil {
		t.Fatal("accepted package result above requested limit")
	}

	directoryInput := json.RawMessage(`{"path":"/home/agent"}`)
	validDirectory := json.RawMessage(`{"path":"/home/agent","entries":[{"name":"settings.conf","path":"/home/agent/settings.conf","type":"file","size_bytes":10,"mode":"-rw-------","modified_at":"2026-01-01T00:00:00Z","is_symlink":false}],"truncated":false}`)
	if err := ValidateJobResult(OperationListDirectory, directoryInput, validDirectory); err != nil {
		t.Fatalf("validate bounded directory result: %v", err)
	}
	escapingDirectory := json.RawMessage(`{"path":"/home/agent","entries":[{"name":"settings.conf","path":"/etc/passwd","type":"file","size_bytes":10,"mode":"-rw-------","modified_at":"2026-01-01T00:00:00Z","is_symlink":false}],"truncated":false}`)
	if err := ValidateJobResult(OperationListDirectory, directoryInput, escapingDirectory); err == nil {
		t.Fatal("accepted a directory entry whose reported path does not match its parent")
	}
}

func TestValidateTypedAPTJobInputsAndResults(t *testing.T) {
	updateInput, err := ValidateJobInput(OperationAPTUpdate, json.RawMessage(`{}`))
	if err != nil || string(updateInput) != `{}` {
		t.Fatalf("validate empty APT update input: %s, %v", updateInput, err)
	}
	installInput, err := ValidateJobInput(OperationAPTInstall, json.RawMessage(`{"packages":["jq","curl"]}`))
	if err != nil {
		t.Fatalf("validate APT install input: %v", err)
	}
	var normalized APTActionInput
	if err := json.Unmarshal(installInput, &normalized); err != nil || len(normalized.Packages) != 2 || normalized.Packages[0] != "curl" {
		t.Fatalf("normalized APT input = %s, value %#v, error %v", installInput, normalized, err)
	}
	if _, err := ValidateJobInput(OperationAPTInstall, json.RawMessage(`{"packages":["curl;id"]}`)); err == nil {
		t.Fatal("accepted an APT package name with shell syntax")
	}
	if _, err := ValidateJobInput(OperationAPTUpdate, json.RawMessage(`{"packages":["curl"]}`)); err == nil {
		t.Fatal("accepted package names on an APT index refresh")
	}
	if _, err := ValidateJobInput(OperationAPTRemove, json.RawMessage(`{"packages":["curl"],"purge":true}`)); err == nil {
		t.Fatal("accepted an APT purge option")
	}

	before := []PackageState{{Name: "curl", Installed: true, Version: "1.0"}}
	after := []PackageState{{Name: "curl", Installed: true, Version: "2.0"}}
	validResult, err := json.Marshal(APTActionResult{Operation: OperationAPTUpgrade, Before: before, After: after, Outcome: APTOutcomeSucceeded, RollbackAvailable: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateJobResult(OperationAPTUpgrade, installInputForTest(t, OperationAPTUpgrade, "curl"), validResult); err != nil {
		t.Fatalf("validate successful APT upgrade result: %v", err)
	}
	invalidResult, _ := json.Marshal(APTActionResult{Operation: OperationAPTUpgrade, Before: before, After: []PackageState{{Name: "jq", Installed: true, Version: "1.0"}}, Outcome: APTOutcomeSucceeded, RollbackAvailable: true})
	if err := ValidateJobResult(OperationAPTUpgrade, installInputForTest(t, OperationAPTUpgrade, "curl"), invalidResult); err == nil {
		t.Fatal("accepted mismatched APT pre-state and post-state package names")
	}

	rollbackInput := APTRollbackInput{Previous: before, ExpectedCurrent: after}
	encodedRollback, err := json.Marshal(rollbackInput)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateJobInput(OperationAPTRollback, encodedRollback); err != nil {
		t.Fatalf("validate APT rollback input: %v", err)
	}
	rollbackResult, _ := json.Marshal(APTRollbackResult{Outcome: APTOutcomeSucceeded, Packages: []APTPackageRollbackResult{{Name: "curl", Restored: true, Exact: true}}})
	if err := ValidateJobResult(OperationAPTRollback, encodedRollback, rollbackResult); err != nil {
		t.Fatalf("validate successful APT rollback result: %v", err)
	}
}

func installInputForTest(t *testing.T, operation, packageName string) json.RawMessage {
	t.Helper()
	encoded, err := ValidateJobInput(operation, json.RawMessage(fmt.Sprintf(`{"packages":[%q]}`, packageName)))
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
