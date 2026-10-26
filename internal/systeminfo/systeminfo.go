//go:build linux

package systeminfo

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type OperatingSystem struct {
	ID              string `json:"id" jsonschema:"distribution identifier"`
	PrettyName      string `json:"pretty_name" jsonschema:"human-readable distribution name"`
	VersionID       string `json:"version_id" jsonschema:"distribution version"`
	VersionCodename string `json:"version_codename,omitempty" jsonschema:"distribution codename when available"`
}

type KernelInfo struct {
	Name    string `json:"name" jsonschema:"kernel name"`
	Release string `json:"release" jsonschema:"kernel release"`
}

type MemoryInfo struct {
	TotalBytes     uint64 `json:"total_bytes" jsonschema:"physical memory in bytes"`
	AvailableBytes uint64 `json:"available_bytes" jsonschema:"estimated memory available to applications in bytes"`
}

type FilesystemInfo struct {
	TotalBytes     uint64 `json:"total_bytes" jsonschema:"total root filesystem capacity in bytes"`
	UsedBytes      uint64 `json:"used_bytes" jsonschema:"used root filesystem capacity in bytes"`
	FreeBytes      uint64 `json:"free_bytes" jsonschema:"free root filesystem capacity including reserved blocks in bytes"`
	AvailableBytes uint64 `json:"available_bytes" jsonschema:"root filesystem capacity available to the agent user in bytes"`
}

type Info struct {
	OS             OperatingSystem `json:"os" jsonschema:"operating system release information"`
	Hostname       string          `json:"hostname" jsonschema:"system hostname"`
	Kernel         KernelInfo      `json:"kernel" jsonschema:"kernel name and release"`
	Architecture   string          `json:"architecture" jsonschema:"Go architecture name"`
	Memory         MemoryInfo      `json:"memory" jsonschema:"memory capacity"`
	RootFilesystem FilesystemInfo  `json:"root_filesystem" jsonschema:"root filesystem capacity"`
	CollectedAt    time.Time       `json:"collected_at" jsonschema:"UTC time when this snapshot was collected"`
}

func Collect() (Info, error) {
	release, err := readOSReleaseOrUnknown("/etc/os-release")
	if err != nil {
		return Info{}, fmt.Errorf("read OS release: %w", err)
	}
	hostname, err := os.Hostname()
	if err != nil {
		return Info{}, fmt.Errorf("read hostname: %w", err)
	}
	memory, err := readMemoryInfo("/proc/meminfo")
	if err != nil {
		return Info{}, fmt.Errorf("read memory information: %w", err)
	}
	filesystem, err := rootFilesystemInfo()
	if err != nil {
		return Info{}, fmt.Errorf("read root filesystem information: %w", err)
	}
	var uts syscall.Utsname
	if err := syscall.Uname(&uts); err != nil {
		return Info{}, fmt.Errorf("read kernel information: %w", err)
	}
	return Info{
		OS:             release,
		Hostname:       hostname,
		Kernel:         KernelInfo{Name: utsString(uts.Sysname[:]), Release: utsString(uts.Release[:])},
		Architecture:   runtime.GOARCH,
		Memory:         memory,
		RootFilesystem: filesystem,
		CollectedAt:    time.Now().UTC(),
	}, nil
}

func readOSReleaseOrUnknown(path string) (OperatingSystem, error) {
	release, err := readOSRelease(path)
	if errors.Is(err, os.ErrNotExist) {
		return OperatingSystem{ID: "unknown", PrettyName: "Unknown Linux distribution"}, nil
	}
	return release, err
}

func readOSRelease(path string) (OperatingSystem, error) {
	file, err := os.Open(path)
	if err != nil {
		return OperatingSystem{}, err
	}
	defer file.Close()

	values := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if decoded, err := strconv.Unquote(value); err == nil {
			value = decoded
		}
		values[strings.TrimSpace(key)] = value
	}
	if err := scanner.Err(); err != nil {
		return OperatingSystem{}, err
	}
	if values["ID"] == "" || values["PRETTY_NAME"] == "" {
		return OperatingSystem{}, fmt.Errorf("%s is missing ID or PRETTY_NAME", path)
	}
	return OperatingSystem{
		ID:              values["ID"],
		PrettyName:      values["PRETTY_NAME"],
		VersionID:       values["VERSION_ID"],
		VersionCodename: values["VERSION_CODENAME"],
	}, nil
}

func readMemoryInfo(path string) (MemoryInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return MemoryInfo{}, err
	}
	defer file.Close()

	var result MemoryInfo
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), ":")
		if !ok || (key != "MemTotal" && key != "MemAvailable") {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) < 1 {
			return MemoryInfo{}, fmt.Errorf("%s has an invalid %s entry", path, key)
		}
		kibibytes, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return MemoryInfo{}, fmt.Errorf("parse %s: %w", key, err)
		}
		bytes := kibibytes * 1024
		switch key {
		case "MemTotal":
			result.TotalBytes = bytes
		case "MemAvailable":
			result.AvailableBytes = bytes
		}
	}
	if err := scanner.Err(); err != nil {
		return MemoryInfo{}, err
	}
	if result.TotalBytes == 0 || result.AvailableBytes == 0 {
		return MemoryInfo{}, fmt.Errorf("%s is missing MemTotal or MemAvailable", path)
	}
	return result, nil
}

func rootFilesystemInfo() (FilesystemInfo, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		return FilesystemInfo{}, err
	}
	blockSize := uint64(stat.Bsize)
	total := stat.Blocks * blockSize
	free := stat.Bfree * blockSize
	available := stat.Bavail * blockSize
	if total == 0 || free > total {
		return FilesystemInfo{}, fmt.Errorf("invalid root filesystem capacity")
	}
	return FilesystemInfo{
		TotalBytes:     total,
		UsedBytes:      total - free,
		FreeBytes:      free,
		AvailableBytes: available,
	}, nil
}

func utsString(value []int8) string {
	bytes := make([]byte, 0, len(value))
	for _, character := range value {
		if character == 0 {
			break
		}
		bytes = append(bytes, byte(character))
	}
	return string(bytes)
}
