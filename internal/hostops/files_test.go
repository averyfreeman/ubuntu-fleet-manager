package hostops

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestReadFileStaysWithinAllowedRoot(t *testing.T) {
	allowedRoot := t.TempDir()
	outsideRoot := t.TempDir()
	insidePath := filepath.Join(allowedRoot, "config.conf")
	outsidePath := filepath.Join(outsideRoot, "secret.conf")
	if err := os.WriteFile(insidePath, []byte("key=value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outsidePath, []byte("secret=value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsidePath, filepath.Join(allowedRoot, "outside-link")); err != nil {
		t.Fatal(err)
	}

	result, err := ReadFile(insidePath, []string{allowedRoot})
	if err != nil {
		t.Fatalf("read permitted file: %v", err)
	}
	if result.Content != "key=value\n" || result.SizeBytes != int64(len("key=value\n")) {
		t.Fatalf("read result = %#v, want the permitted file contents and size", result)
	}

	traversalPath := filepath.Join(allowedRoot, "..", filepath.Base(outsideRoot), "secret.conf")
	if _, err := ReadFile(traversalPath, []string{allowedRoot}); err == nil {
		t.Fatal("path traversal outside the allowed root succeeded")
	}
	if err := ValidatePath(allowedRoot + "/../outside/secret.conf"); err == nil {
		t.Fatal("path containing a parent-directory traversal component was accepted")
	}
	if _, err := ReadFile(filepath.Join(allowedRoot, "outside-link"), []string{allowedRoot}); err == nil {
		t.Fatal("symlink escape outside the allowed root succeeded")
	}
}

func TestListDirectoryBoundsAndSortsEntries(t *testing.T) {
	directory := t.TempDir()
	for i := 0; i < MaxDirectoryEntries+1; i++ {
		name := fmt.Sprintf("entry-%03d", i)
		if err := os.WriteFile(filepath.Join(directory, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	outsideFile := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outsideFile, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideFile, filepath.Join(directory, "a-link")); err != nil {
		t.Fatal(err)
	}

	listing, err := ListDirectory(directory, []string{directory})
	if err != nil {
		t.Fatalf("list permitted directory: %v", err)
	}
	if len(listing.Entries) != MaxDirectoryEntries || !listing.Truncated {
		t.Fatalf("listing has %d entries and truncated=%t; want %d entries and truncated=true", len(listing.Entries), listing.Truncated, MaxDirectoryEntries)
	}
	if listing.Entries[0].Name != "a-link" || listing.Entries[0].Type != "symlink" || !listing.Entries[0].IsSymlink {
		t.Fatalf("symlink entry = %#v, want a symlink entry without following its target", listing.Entries[0])
	}
	for i := 1; i < len(listing.Entries); i++ {
		if listing.Entries[i-1].Name > listing.Entries[i].Name {
			t.Fatalf("directory entries are not sorted: %q is before %q", listing.Entries[i-1].Name, listing.Entries[i].Name)
		}
	}
}

func TestReadFileRejectsOversizedAndNonRegularFiles(t *testing.T) {
	directory := t.TempDir()
	largePath := filepath.Join(directory, "large")
	if err := os.WriteFile(largePath, make([]byte, MaxReadFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(largePath, []string{directory}); err == nil {
		t.Fatal("oversized file read succeeded")
	}
	if _, err := ReadFile(directory, []string{directory}); err == nil {
		t.Fatal("directory was read as a regular file")
	}
	if _, err := ReadFile(filepath.Join(directory, "missing"), []string{directory}); err == nil {
		t.Fatal("missing file read succeeded")
	}
}

func TestReadFileReportsPermissionFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read files regardless of mode bits")
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "private.conf")
	if err := os.WriteFile(path, []byte("secret=value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(path, []string{directory}); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("read unreadable file error = %v, want a permission error", err)
	}
}

func TestNormalizeAllowedPathsDefaultsToAgentHomeAndRejectsFiles(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	wantHome, err := filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := NormalizeAllowedPaths(nil)
	if err != nil {
		t.Fatalf("normalize default host read boundary: %v", err)
	}
	if len(paths) != 1 || paths[0] != wantHome {
		t.Fatalf("default allowed paths = %v, want agent home %q", paths, wantHome)
	}

	file := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(file, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NormalizeAllowedPaths([]string{file}); err == nil {
		t.Fatal("regular file was accepted as an allowed directory boundary")
	}
}
