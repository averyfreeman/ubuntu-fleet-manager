package hostops

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteFileCreatesAndOverwritesWithCapturedPriorState(t *testing.T) {
	root := t.TempDir()
	newFile := filepath.Join(root, "new.conf")
	created, err := WriteFile(newFile, "first\n", []string{root})
	if err != nil {
		t.Fatalf("create file: %v", err)
	}
	if created.Previous.Existed || created.Previous.Mode != 0 || len(created.Previous.Content) != 0 {
		t.Fatalf("captured state for new file = %#v, want absent", created.Previous)
	}
	content, err := os.ReadFile(newFile)
	if err != nil || string(content) != "first\n" {
		t.Fatalf("created file = %q, error = %v", content, err)
	}
	info, err := os.Stat(newFile)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("created mode = %v, error = %v, want 0600", info, err)
	}

	if err := os.Chmod(newFile, 0o640); err != nil {
		t.Fatalf("set original mode: %v", err)
	}
	overwritten, err := WriteFile(newFile, "second\n", []string{root})
	if err != nil {
		t.Fatalf("overwrite file: %v", err)
	}
	if !overwritten.Previous.Existed || string(overwritten.Previous.Content) != "first\n" || overwritten.Previous.Mode != 0o640 {
		t.Fatalf("captured pre-state = %#v, want first contents and mode 0640", overwritten.Previous)
	}
	info, err = os.Stat(newFile)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("overwritten mode = %v, error = %v, want preserved 0640", info, err)
	}
	if overwritten.Current.SHA256 != sha256Hex([]byte("second\n")) || overwritten.Current.Mode != 0o640 {
		t.Fatalf("current file fingerprint = %#v, want current content hash and mode", overwritten.Current)
	}
}

func TestWriteFileAndRestoreRejectModesThatPreventAgentVerification(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "settings.conf")
	if err := os.WriteFile(path, []byte("original\n"), 0o600); err != nil {
		t.Fatalf("write initial file: %v", err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("remove owner-read permission: %v", err)
	}
	if _, err := WriteFile(path, "replacement\n", []string{root}); err == nil {
		t.Fatal("write replaced a file that the agent cannot read back")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o000 {
		t.Fatalf("rejected write changed file mode: mode=%v stat=%v", info, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("restore read permission to inspect rejected file: %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "original\n" {
		t.Fatalf("rejected write changed file content: got %q, error=%v", content, err)
	}

	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("restore readable mode for managed write: %v", err)
	}
	written, err := WriteFile(path, "managed\n", []string{root})
	if err != nil {
		t.Fatalf("write managed content: %v", err)
	}
	written.Previous.Mode = 0o000
	restored, err := RestoreFile(RestoreFileInput{Path: path, Previous: written.Previous, ExpectedCurrent: written.Current}, []string{root})
	if err != nil || restored.Exact || restored.Restored || !strings.Contains(restored.Reason, "permission") {
		t.Fatalf("restore result = %#v, error = %v, want a non-mutating permission explanation", restored, err)
	}
	info, err = os.Stat(path)
	content, readErr := os.ReadFile(path)
	if err != nil || readErr != nil || info.Mode().Perm() != 0o600 || string(content) != "managed\n" {
		t.Fatalf("refused restore changed current file: content=%q mode=%v stat=%v read=%v", content, info, err, readErr)
	}
}

func TestWriteFileRejectsUnconfiguredPathsTraversalAndSymlinks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	outsideFile := filepath.Join(outside, "secret")
	if err := os.WriteFile(outsideFile, []byte("do not modify"), 0o600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	link := filepath.Join(root, "escape")
	if err := os.Symlink(outsideFile, link); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	for _, test := range []struct {
		name  string
		path  string
		roots []string
	}{
		{name: "no writable boundaries", path: filepath.Join(root, "new"), roots: nil},
		{name: "outside boundary", path: outsideFile, roots: []string{root}},
		{name: "parent traversal", path: filepath.Join(root, "..", "secret"), roots: []string{root}},
		{name: "symlink", path: link, roots: []string{root}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := WriteFile(test.path, "changed", test.roots); err == nil {
				t.Fatal("write outside or through an invalid path was accepted")
			}
		})
	}
	content, err := os.ReadFile(outsideFile)
	if err != nil || string(content) != "do not modify" {
		t.Fatalf("outside file = %q, error = %v, want unchanged content", content, err)
	}
}

func TestRestoreFileRestoresCapturedBytesModeAndAbsenceSafely(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "settings.conf")
	if err := os.WriteFile(path, []byte("before\n"), 0o640); err != nil {
		t.Fatalf("write original file: %v", err)
	}
	written, err := WriteFile(path, "after\n", []string{root})
	if err != nil {
		t.Fatalf("write new content: %v", err)
	}
	restored, err := RestoreFile(RestoreFileInput{Path: path, Previous: written.Previous, ExpectedCurrent: written.Current}, []string{root})
	if err != nil || !restored.Restored || !restored.Exact {
		t.Fatalf("restore result = %#v, error = %v, want exact restoration", restored, err)
	}
	content, err := os.ReadFile(path)
	info, statErr := os.Stat(path)
	if err != nil || statErr != nil || string(content) != "before\n" || info.Mode().Perm() != 0o640 {
		t.Fatalf("restored file = %q mode=%v read=%v stat=%v, want original bytes and mode", content, info, err, statErr)
	}
	// Repeating the same rollback is safe and does not rewrite the already-restored file.
	repeated, err := RestoreFile(RestoreFileInput{Path: path, Previous: written.Previous, ExpectedCurrent: written.Current}, []string{root})
	if err != nil || !repeated.Restored || !repeated.Exact {
		t.Fatalf("repeat restore result = %#v, error = %v, want exact idempotent result", repeated, err)
	}

	newPath := filepath.Join(root, "created.conf")
	created, err := WriteFile(newPath, "new\n", []string{root})
	if err != nil {
		t.Fatalf("create file for absence restoration: %v", err)
	}
	removed, err := RestoreFile(RestoreFileInput{Path: newPath, Previous: created.Previous, ExpectedCurrent: created.Current}, []string{root})
	if err != nil || !removed.Restored || !removed.Exact {
		t.Fatalf("restore absent state = %#v, error = %v", removed, err)
	}
	if _, err := os.Lstat(newPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("newly created file still exists after rollback: %v", err)
	}
	repeatedRemove, err := RestoreFile(RestoreFileInput{Path: newPath, Previous: created.Previous, ExpectedCurrent: created.Current}, []string{root})
	if err != nil || !repeatedRemove.Restored || !repeatedRemove.Exact {
		t.Fatalf("repeat absent-state restore = %#v, error = %v", repeatedRemove, err)
	}
}

func TestRestoreFileRefusesToOverwriteAFileChangedAfterWrite(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "settings.conf")
	if err := os.WriteFile(path, []byte("before"), 0o600); err != nil {
		t.Fatalf("write original file: %v", err)
	}
	written, err := WriteFile(path, "managed", []string{root})
	if err != nil {
		t.Fatalf("write managed content: %v", err)
	}
	if err := os.WriteFile(path, []byte("operator changed this later"), 0o600); err != nil {
		t.Fatalf("change file after managed write: %v", err)
	}
	result, err := RestoreFile(RestoreFileInput{Path: path, Previous: written.Previous, ExpectedCurrent: written.Current}, []string{root})
	if err != nil || result.Exact || result.Restored || !strings.Contains(result.Reason, "changed") {
		t.Fatalf("restore result = %#v, error = %v, want non-destructive conflict explanation", result, err)
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "operator changed this later" {
		t.Fatalf("changed file = %q, error = %v, want operator content preserved", content, err)
	}
}

func TestWriteFileReportsFilesystemPermissionFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		root := "/proc/sys"
		if info, err := os.Stat(root); err != nil || !info.IsDir() {
			t.Skip("root test environment has no read-only procfs sysctl directory")
		}
		if _, err := WriteFile(filepath.Join(root, "kernel", "hostname"), "changed", []string{root}); err == nil {
			t.Fatal("write to read-only procfs path unexpectedly succeeded")
		}
		return
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o500); err != nil {
		t.Fatalf("remove directory write permission: %v", err)
	}
	if _, err := WriteFile(filepath.Join(root, "settings.conf"), "changed", []string{root}); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("permission failure = %v, want permission denied", err)
	}
}

func TestValidateWriteAndRestoreJobInputsAndResults(t *testing.T) {
	writeInput, err := json.Marshal(WriteFileInput{Path: "/etc/app.conf", Content: "mode=safe\n"})
	if err != nil {
		t.Fatal(err)
	}
	validated, err := ValidateJobInput(OperationWriteFile, writeInput)
	if err != nil {
		t.Fatalf("validate write input: %v", err)
	}
	if _, err := ValidateJobInput(OperationWriteFile, []byte(`{"path":"/etc/app.conf","content":"ok","unexpected":true}`)); err == nil {
		t.Fatal("write input with an unknown field was accepted")
	}
	if _, err := ValidateJobInput(OperationWriteFile, []byte(`{"path":"/etc/app.conf","content":"x"}`)); err != nil {
		t.Fatalf("validate write input with 1-byte content: %v", err)
	}
	if _, err := ValidateJobInput(OperationWriteFile, mustJSON(t, WriteFileInput{Path: "/etc/app.conf", Content: strings.Repeat("x", MaxWriteFileBytes+1)})); err == nil {
		t.Fatal("oversized file contents were accepted")
	}

	previous := FileState{Existed: true, Content: []byte("old"), Mode: 0o640}
	current := FileFingerprint{Existed: true, SHA256: sha256Hex([]byte("mode=safe\n")), Mode: 0o640}
	writeResult, _ := json.Marshal(WriteFileResult{Path: "/etc/app.conf", Previous: previous, Current: current})
	if err := ValidateJobResult(OperationWriteFile, validated, writeResult); err != nil {
		t.Fatalf("validate write result: %v", err)
	}
	if err := ValidateJobResult(OperationWriteFile, validated, []byte(`{"path":"/elsewhere","previous":{},"current":{}}`)); err == nil {
		t.Fatal("write result for a different path was accepted")
	}

	restoreInput, _ := json.Marshal(RestoreFileInput{Path: "/etc/app.conf", Previous: previous, ExpectedCurrent: current})
	validatedRestore, err := ValidateJobInput(OperationRestoreFile, restoreInput)
	if err != nil {
		t.Fatalf("validate restore input: %v", err)
	}
	if err := ValidateJobResult(OperationRestoreFile, validatedRestore, mustJSON(t, RestoreFileResult{Path: "/etc/app.conf", Restored: true, Exact: true})); err != nil {
		t.Fatalf("validate exact restore result: %v", err)
	}
	if err := ValidateJobResult(OperationRestoreFile, validatedRestore, mustJSON(t, RestoreFileResult{Path: "/etc/app.conf", Reason: "file changed"})); err != nil {
		t.Fatalf("validate unavailable restore result: %v", err)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func sha256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
