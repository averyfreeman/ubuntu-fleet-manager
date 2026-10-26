package hostops

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func WriteFile(path, content string, writablePaths []string) (WriteFileResult, error) {
	input := WriteFileInput{Path: path, Content: content}
	if err := validateWriteFileInput(input); err != nil {
		return WriteFileResult{}, err
	}
	root, relativePath, canonicalPath, err := openAllowedWritePath(path, writablePaths)
	if err != nil {
		return WriteFileResult{}, err
	}
	defer root.Close()

	previous, err := readFileState(root, relativePath)
	if err != nil {
		return WriteFileResult{}, fmt.Errorf("capture permitted file state: %w", err)
	}
	currentBeforeWrite, err := readFileState(root, relativePath)
	if err != nil || !sameFileState(previous, currentBeforeWrite) {
		return WriteFileResult{}, fmt.Errorf("file changed while capturing the prior state; no write was applied")
	}
	mode := fs.FileMode(0o600)
	if previous.Existed {
		if previous.Mode&0o400 == 0 {
			return WriteFileResult{}, fmt.Errorf("existing file mode does not give the agent owner-read access needed to verify a reversible write")
		}
		mode = fs.FileMode(previous.Mode)
	}
	if err := writeAtomically(root, relativePath, []byte(content), mode); err != nil {
		return WriteFileResult{}, fmt.Errorf("replace permitted file: %w", err)
	}
	current, err := readFileState(root, relativePath)
	if err != nil {
		return WriteFileResult{}, fmt.Errorf("verify replaced file: %w", err)
	}
	if !current.Existed {
		return WriteFileResult{}, fmt.Errorf("replaced file is not present after writing")
	}
	return WriteFileResult{
		Path:     canonicalPath,
		Previous: previous,
		Current: FileFingerprint{
			Existed: true,
			SHA256:  sha256String(current.Content),
			Mode:    current.Mode,
		},
	}, nil
}

func RestoreFile(input RestoreFileInput, writablePaths []string) (RestoreFileResult, error) {
	if err := validateRestoreFileInput(input); err != nil {
		return RestoreFileResult{}, err
	}
	root, relativePath, canonicalPath, err := openAllowedWritePath(input.Path, writablePaths)
	if err != nil {
		return RestoreFileResult{}, err
	}
	defer root.Close()

	current, err := readFileState(root, relativePath)
	if err != nil {
		return RestoreFileResult{}, fmt.Errorf("inspect file before restoration: %w", err)
	}
	if sameFileState(current, input.Previous) {
		return RestoreFileResult{Path: canonicalPath, Restored: true, Exact: true}, nil
	}
	if fileFingerprint(current) != input.ExpectedCurrent {
		return RestoreFileResult{
			Path:   canonicalPath,
			Reason: "file changed after the managed write; current contents were preserved",
		}, nil
	}
	if input.Previous.Existed && input.Previous.Mode&0o400 == 0 {
		return RestoreFileResult{
			Path:   canonicalPath,
			Reason: "captured permission bits would prevent the agent from verifying restoration",
		}, nil
	}
	currentBeforeRestore, err := readFileState(root, relativePath)
	if err != nil || !sameFileState(current, currentBeforeRestore) {
		return RestoreFileResult{
			Path:   canonicalPath,
			Reason: "file changed during rollback; current contents were preserved",
		}, nil
	}

	if input.Previous.Existed {
		if err := writeAtomically(root, relativePath, input.Previous.Content, fs.FileMode(input.Previous.Mode)); err != nil {
			return RestoreFileResult{}, fmt.Errorf("restore captured file state: %w", err)
		}
	} else if err := root.Remove(relativePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return RestoreFileResult{}, fmt.Errorf("remove file created by managed write: %w", err)
	}

	restored, err := readFileState(root, relativePath)
	if err != nil {
		return RestoreFileResult{}, fmt.Errorf("verify restored file state: %w", err)
	}
	if !sameFileState(restored, input.Previous) {
		return RestoreFileResult{}, fmt.Errorf("restored bytes or mode do not match the captured file state")
	}
	return RestoreFileResult{Path: canonicalPath, Restored: true, Exact: true}, nil
}

func openAllowedWritePath(path string, writablePaths []string) (*os.Root, string, string, error) {
	if err := ValidatePath(path); err != nil {
		return nil, "", "", err
	}
	if len(writablePaths) == 0 {
		return nil, "", "", fmt.Errorf("host has no configured writable paths")
	}
	canonicalPath := filepath.Clean(path)
	roots, err := NormalizeAllowedPaths(writablePaths)
	if err != nil {
		return nil, "", "", err
	}
	for _, allowedRoot := range roots {
		relativePath, err := filepath.Rel(allowedRoot, canonicalPath)
		if err != nil || relativePath == "." || relativePath == ".." || strings.HasPrefix(relativePath, ".."+string(os.PathSeparator)) || filepath.IsAbs(relativePath) {
			continue
		}
		root, err := os.OpenRoot(allowedRoot)
		if err != nil {
			return nil, "", "", fmt.Errorf("open configured writable boundary: %w", err)
		}
		return root, relativePath, canonicalPath, nil
	}
	return nil, "", "", fmt.Errorf("path is outside the host's configured writable paths")
}

func readFileState(root *os.Root, relativePath string) (FileState, error) {
	info, err := root.Lstat(relativePath)
	if errors.Is(err, os.ErrNotExist) {
		return FileState{}, nil
	}
	if err != nil {
		return FileState{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return FileState{}, fmt.Errorf("symbolic links are not writable targets")
	}
	if !info.Mode().IsRegular() {
		return FileState{}, fmt.Errorf("path is not a regular file")
	}
	file, err := root.Open(relativePath)
	if err != nil {
		return FileState{}, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return FileState{}, err
	}
	if !openedInfo.Mode().IsRegular() {
		return FileState{}, fmt.Errorf("path is not a regular file")
	}
	if !os.SameFile(info, openedInfo) {
		return FileState{}, fmt.Errorf("file target changed during inspection")
	}
	content, err := io.ReadAll(io.LimitReader(file, MaxWriteFileBytes+1))
	if err != nil {
		return FileState{}, err
	}
	if len(content) > MaxWriteFileBytes {
		return FileState{}, fmt.Errorf("file exceeds the %d-byte reversible write limit", MaxWriteFileBytes)
	}
	return FileState{Existed: true, Content: content, Mode: uint32(openedInfo.Mode().Perm())}, nil
}

func writeAtomically(root *os.Root, relativePath string, content []byte, mode fs.FileMode) error {
	if mode.Perm() > 0o777 || len(content) > MaxWriteFileBytes {
		return fmt.Errorf("file content or mode exceeds the supported reversible write limits")
	}
	var randomName [16]byte
	if _, err := rand.Read(randomName[:]); err != nil {
		return fmt.Errorf("generate temporary file name: %w", err)
	}
	parent := filepath.Dir(relativePath)
	base := filepath.Base(relativePath)
	temporaryPath := filepath.Join(parent, "."+base+".ufm-"+hex.EncodeToString(randomName[:]))
	temporary, err := root.OpenFile(temporaryPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode.Perm())
	if err != nil {
		return err
	}
	keepTemporary := false
	defer func() {
		_ = temporary.Close()
		if !keepTemporary {
			_ = root.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(mode.Perm()); err != nil {
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := root.Rename(temporaryPath, relativePath); err != nil {
		return err
	}
	keepTemporary = true
	return nil
}

func fileFingerprint(state FileState) FileFingerprint {
	if !state.Existed {
		return FileFingerprint{}
	}
	return FileFingerprint{Existed: true, SHA256: sha256String(state.Content), Mode: state.Mode}
}

func sameFileState(left, right FileState) bool {
	if left.Existed != right.Existed || left.Mode != right.Mode || len(left.Content) != len(right.Content) {
		return false
	}
	for index := range left.Content {
		if left.Content[index] != right.Content[index] {
			return false
		}
	}
	return true
}
