package hostops

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	MaxPathBytes        = 4096
	MaxReadFileBytes    = 256 << 10
	MaxDirectoryEntries = 100
)

type DirectoryEntry struct {
	Name       string    `json:"name"`
	Path       string    `json:"path"`
	Type       string    `json:"type"`
	SizeBytes  int64     `json:"size_bytes"`
	Mode       string    `json:"mode"`
	ModifiedAt time.Time `json:"modified_at"`
	IsSymlink  bool      `json:"is_symlink"`
}

type DirectoryListing struct {
	Path      string           `json:"path"`
	Entries   []DirectoryEntry `json:"entries"`
	Truncated bool             `json:"truncated"`
}

type FileReadResult struct {
	Path      string `json:"path"`
	Content   string `json:"content"`
	SizeBytes int64  `json:"size_bytes"`
}

func ListDirectory(path string, allowedPaths []string) (DirectoryListing, error) {
	root, relativePath, canonicalPath, err := openAllowedPath(path, allowedPaths)
	if err != nil {
		return DirectoryListing{}, err
	}
	defer root.Close()

	directory, err := root.Open(relativePath)
	if err != nil {
		return DirectoryListing{}, fmt.Errorf("open permitted directory: %w", err)
	}
	defer directory.Close()
	info, err := directory.Stat()
	if err != nil {
		return DirectoryListing{}, fmt.Errorf("inspect permitted directory: %w", err)
	}
	if !info.IsDir() {
		return DirectoryListing{}, fmt.Errorf("path is not a directory")
	}
	entries, err := directory.ReadDir(MaxDirectoryEntries + 1)
	if err != nil {
		return DirectoryListing{}, fmt.Errorf("read permitted directory: %w", err)
	}
	truncated := len(entries) > MaxDirectoryEntries
	if truncated {
		entries = entries[:MaxDirectoryEntries]
	}
	listing := DirectoryListing{Path: canonicalPath, Entries: make([]DirectoryEntry, 0, len(entries)), Truncated: truncated}
	for _, entry := range entries {
		entryPath := filepath.Join(relativePath, entry.Name())
		entryInfo, err := root.Lstat(entryPath)
		if err != nil {
			return DirectoryListing{}, fmt.Errorf("inspect directory entry %q: %w", entry.Name(), err)
		}
		if !utf8.ValidString(entry.Name()) {
			return DirectoryListing{}, fmt.Errorf("directory contains a non-UTF-8 entry name")
		}
		entryType := "other"
		isSymlink := entryInfo.Mode()&os.ModeSymlink != 0
		switch {
		case isSymlink:
			entryType = "symlink"
		case entryInfo.IsDir():
			entryType = "directory"
		case entryInfo.Mode().IsRegular():
			entryType = "file"
		}
		listing.Entries = append(listing.Entries, DirectoryEntry{
			Name:       entry.Name(),
			Path:       filepath.Join(canonicalPath, entry.Name()),
			Type:       entryType,
			SizeBytes:  entryInfo.Size(),
			Mode:       entryInfo.Mode().String(),
			ModifiedAt: entryInfo.ModTime().UTC(),
			IsSymlink:  isSymlink,
		})
	}
	sort.Slice(listing.Entries, func(i, j int) bool { return listing.Entries[i].Name < listing.Entries[j].Name })
	return listing, nil
}

func ReadFile(path string, allowedPaths []string) (FileReadResult, error) {
	root, relativePath, canonicalPath, err := openAllowedPath(path, allowedPaths)
	if err != nil {
		return FileReadResult{}, err
	}
	defer root.Close()

	file, err := root.Open(relativePath)
	if err != nil {
		return FileReadResult{}, fmt.Errorf("open permitted file: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return FileReadResult{}, fmt.Errorf("inspect permitted file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return FileReadResult{}, fmt.Errorf("path is not a regular file")
	}
	content, err := io.ReadAll(io.LimitReader(file, MaxReadFileBytes+1))
	if err != nil {
		return FileReadResult{}, fmt.Errorf("read permitted file: %w", err)
	}
	if len(content) > MaxReadFileBytes {
		return FileReadResult{}, fmt.Errorf("file exceeds the %d-byte read limit", MaxReadFileBytes)
	}
	if !utf8.Valid(content) {
		return FileReadResult{}, fmt.Errorf("file is not valid UTF-8 text")
	}
	return FileReadResult{Path: canonicalPath, Content: string(content), SizeBytes: int64(len(content))}, nil
}

func ValidatePath(path string) error {
	if path == "" || len(path) > MaxPathBytes || strings.ContainsRune(path, '\x00') || !utf8.ValidString(path) {
		return fmt.Errorf("path is empty or exceeds the %d-byte limit", MaxPathBytes)
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("path must be absolute")
	}
	for _, part := range strings.Split(path, string(os.PathSeparator)) {
		if part == ".." {
			return fmt.Errorf("path traversal components are not allowed")
		}
	}
	return nil
}

func openAllowedPath(path string, allowedPaths []string) (*os.Root, string, string, error) {
	if err := ValidatePath(path); err != nil {
		return nil, "", "", err
	}
	canonicalPath := filepath.Clean(path)
	roots, err := NormalizeAllowedPaths(allowedPaths)
	if err != nil {
		return nil, "", "", err
	}
	for _, allowedRoot := range roots {
		relativePath, err := filepath.Rel(allowedRoot, canonicalPath)
		if err != nil || relativePath == ".." || strings.HasPrefix(relativePath, ".."+string(os.PathSeparator)) || filepath.IsAbs(relativePath) {
			continue
		}
		root, err := os.OpenRoot(allowedRoot)
		if err != nil {
			return nil, "", "", fmt.Errorf("open configured path boundary: %w", err)
		}
		return root, relativePath, canonicalPath, nil
	}
	return nil, "", "", fmt.Errorf("path is outside the configured allowed paths")
}

func NormalizeAllowedPaths(paths []string) ([]string, error) {
	if len(paths) == 0 {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("find the agent user's home directory: %w", err)
		}
		paths = []string{home}
	}
	canonicalPaths := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if path == "" || len(path) > MaxPathBytes || !filepath.IsAbs(path) || strings.ContainsRune(path, '\x00') || !utf8.ValidString(path) {
			return nil, fmt.Errorf("configured allowed paths must be absolute and at most %d bytes", MaxPathBytes)
		}
		canonicalPath, err := filepath.EvalSymlinks(filepath.Clean(path))
		if err != nil {
			return nil, fmt.Errorf("resolve configured allowed path: %w", err)
		}
		info, err := os.Stat(canonicalPath)
		if err != nil {
			return nil, fmt.Errorf("inspect configured allowed path: %w", err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("configured allowed path is not a directory")
		}
		if _, exists := seen[canonicalPath]; exists {
			continue
		}
		seen[canonicalPath] = struct{}{}
		canonicalPaths = append(canonicalPaths, canonicalPath)
	}
	if len(canonicalPaths) == 0 {
		return nil, fmt.Errorf("at least one allowed path is required")
	}
	return canonicalPaths, nil
}

// NormalizeWritablePaths returns nil when the operator did not grant write
// access. Unlike read boundaries, writable boundaries never default to home.
func NormalizeWritablePaths(paths []string) ([]string, error) {
	if len(paths) == 0 {
		return nil, nil
	}
	return NormalizeAllowedPaths(paths)
}
