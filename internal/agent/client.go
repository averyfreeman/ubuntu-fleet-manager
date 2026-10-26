// Package agent contains the unprivileged host agent's outbound control-plane client.
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/averyfreeman/ubuntu-fleet-manager/internal/hostops"
	"github.com/averyfreeman/ubuntu-fleet-manager/internal/systeminfo"
)

type Config struct {
	ServerURL     string                `json:"server_url"`
	HostID        string                `json:"host_id"`
	Credential    string                `json:"credential"`
	AllowedPaths  []string              `json:"allowed_paths,omitempty"`
	WritablePaths []string              `json:"writable_paths,omitempty"`
	APTPolicy     hostops.APTPolicy     `json:"apt_policy,omitempty"`
	CommandPolicy hostops.CommandPolicy `json:"command_policy,omitempty"`
}

type Client struct {
	httpClient *http.Client
	collect    SystemInfoCollector
	aptRunner  hostops.APTCommandRunner
}

const (
	maxAgentConfigBytes     = 16 << 10
	maxAgentJobPayloadBytes = 2 << 20
)

type SystemInfoCollector func() (systeminfo.Info, error)

type enrollmentRequest struct {
	PairingCode  string `json:"pairing_code"`
	Hostname     string `json:"hostname"`
	OSPrettyName string `json:"os_pretty_name"`
}

type enrollmentResponse struct {
	HostID     string `json:"host_id"`
	Credential string `json:"credential"`
}

type pollResponse struct {
	Status string    `json:"status"`
	Job    *agentJob `json:"job,omitempty"`
}

type agentJob struct {
	ID             string          `json:"id"`
	Operation      string          `json:"operation"`
	Input          json.RawMessage `json:"input,omitempty"`
	LeaseToken     string          `json:"lease_token"`
	LeaseExpiresAt time.Time       `json:"lease_expires_at"`
	Attempt        int             `json:"attempt"`
}

type jobResultSubmission struct {
	JobID      string          `json:"job_id"`
	LeaseToken string          `json:"lease_token"`
	Result     json.RawMessage `json:"result,omitempty"`
	Error      string          `json:"error,omitempty"`
}

func NewClient(client *http.Client) *Client {
	return NewClientWithSystemInfoCollector(client, systeminfo.Collect)
}

func NewClientWithSystemInfoCollector(client *http.Client, collect SystemInfoCollector) *Client {
	if collect == nil {
		collect = systeminfo.Collect
	}
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	} else {
		clientCopy := *client
		client = &clientCopy
	}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &Client{httpClient: client, collect: collect}
}

func DefaultConfigPath() (string, error) {
	configDirectory, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("find user configuration directory: %w", err)
	}
	return filepath.Join(configDirectory, "ubuntu-fleet-manager", "agent.json"), nil
}

func (c *Client) Enroll(ctx context.Context, serverURL, pairingCode, hostname, osPrettyName, configPath string) (string, error) {
	return c.EnrollWithAllowedPaths(ctx, serverURL, pairingCode, hostname, osPrettyName, configPath, nil)
}

func (c *Client) EnrollWithAllowedPaths(ctx context.Context, serverURL, pairingCode, hostname, osPrettyName, configPath string, allowedPaths []string) (string, error) {
	return c.EnrollWithPathPolicies(ctx, serverURL, pairingCode, hostname, osPrettyName, configPath, allowedPaths, nil)
}

func (c *Client) EnrollWithPathPolicies(ctx context.Context, serverURL, pairingCode, hostname, osPrettyName, configPath string, allowedPaths, writablePaths []string) (string, error) {
	return c.EnrollWithAPTPolicy(ctx, serverURL, pairingCode, hostname, osPrettyName, configPath, allowedPaths, writablePaths, hostops.APTPolicy{})
}

func (c *Client) EnrollWithAPTPolicy(ctx context.Context, serverURL, pairingCode, hostname, osPrettyName, configPath string, allowedPaths, writablePaths []string, aptPolicy hostops.APTPolicy) (string, error) {
	baseURL, err := parseServerURL(serverURL)
	if err != nil {
		return "", err
	}
	if pairingCode == "" || hostname == "" || osPrettyName == "" {
		return "", fmt.Errorf("pairing code, hostname, and operating system name are required")
	}
	if configPath == "" {
		configPath, err = DefaultConfigPath()
		if err != nil {
			return "", err
		}
	}
	allowedPaths, err = hostops.NormalizeAllowedPaths(allowedPaths)
	if err != nil {
		return "", err
	}
	writablePaths, err = hostops.NormalizeWritablePaths(writablePaths)
	if err != nil {
		return "", err
	}
	aptPolicy, err = hostops.NormalizeAPTPolicy(aptPolicy)
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(enrollmentRequest{PairingCode: pairingCode, Hostname: hostname, OSPrettyName: osPrettyName})
	if err != nil {
		return "", fmt.Errorf("encode enrollment request")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL(baseURL, "/agent/enroll"), strings.NewReader(string(encoded)))
	if err != nil {
		return "", fmt.Errorf("create enrollment request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("send enrollment request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 16<<10))
		return "", fmt.Errorf("control plane rejected host enrollment (HTTP %d)", response.StatusCode)
	}
	var enrollment enrollmentResponse
	if err := decodeJSON(response.Body, &enrollment); err != nil {
		return "", fmt.Errorf("read enrollment response: %w", err)
	}
	if enrollment.HostID == "" || enrollment.Credential == "" {
		return "", fmt.Errorf("control plane enrollment response is incomplete")
	}
	config := Config{ServerURL: strings.TrimRight(serverURL, "/"), HostID: enrollment.HostID, Credential: enrollment.Credential, AllowedPaths: allowedPaths, WritablePaths: writablePaths, APTPolicy: aptPolicy}
	if err := SaveConfig(configPath, config); err != nil {
		return "", err
	}
	return enrollment.HostID, nil
}

func (c *Client) PollOnce(ctx context.Context, config Config) error {
	baseURL, err := parseServerURL(config.ServerURL)
	if err != nil {
		return err
	}
	if config.HostID == "" || config.Credential == "" {
		return fmt.Errorf("agent configuration is missing its host identity or credential")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL(baseURL, "/agent/poll"), strings.NewReader(`{}`))
	if err != nil {
		return fmt.Errorf("create agent poll request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+config.Credential)
	request.Header.Set("Content-Type", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("send agent poll request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 16<<10))
		return fmt.Errorf("control plane rejected agent poll (HTTP %d)", response.StatusCode)
	}
	var result pollResponse
	if err := decodeJSONLimit(response.Body, &result, maxAgentJobPayloadBytes); err != nil {
		return fmt.Errorf("read agent poll response: %w", err)
	}
	switch result.Status {
	case "idle":
		if result.Job != nil {
			return fmt.Errorf("control plane returned a job with an idle status")
		}
		return nil
	case "job":
		if result.Job == nil || result.Job.ID == "" || result.Job.LeaseToken == "" || result.Job.Operation == "" {
			return fmt.Errorf("control plane returned an incomplete job lease")
		}
		return c.executeJob(ctx, baseURL, config, *result.Job)
	default:
		return fmt.Errorf("control plane returned an unsupported agent poll response")
	}
}

func (c *Client) executeJob(ctx context.Context, baseURL *url.URL, config Config, job agentJob) error {
	submission := jobResultSubmission{JobID: job.ID, LeaseToken: job.LeaseToken}
	input := job.Input
	if len(input) == 0 {
		input = json.RawMessage(`{}`)
	}
	switch job.Operation {
	case hostops.OperationGetSystemInfo:
		var empty struct{}
		if err := decodeJobJSON(strings.NewReader(string(input)), &empty); err != nil {
			submission.Error = "system-info job input is invalid"
			break
		}
		info, err := c.collect()
		if err != nil {
			submission.Error = safeAgentError(err)
		} else {
			submission.Result, err = json.Marshal(info)
			if err != nil {
				submission.Error = "system-info result could not be encoded"
			}
		}
	case hostops.OperationListDirectory, hostops.OperationReadFile:
		var operationInput hostops.PathInput
		if err := decodeJobJSON(strings.NewReader(string(input)), &operationInput); err != nil {
			submission.Error = "file operation input is invalid"
			break
		}
		var result any
		var err error
		if job.Operation == hostops.OperationListDirectory {
			result, err = hostops.ListDirectory(operationInput.Path, config.AllowedPaths)
		} else {
			result, err = hostops.ReadFile(operationInput.Path, config.AllowedPaths)
		}
		if err != nil {
			submission.Error = safeAgentError(err)
		} else {
			submission.Result, err = json.Marshal(result)
			if err != nil {
				submission.Error = "file operation result could not be encoded"
			}
		}
	case hostops.OperationSearchPackages:
		var operationInput hostops.PackageSearchInput
		if err := decodeJobJSON(strings.NewReader(string(input)), &operationInput); err != nil {
			submission.Error = "package search input is invalid"
			break
		}
		result, err := hostops.SearchPackages(ctx, operationInput.Query, operationInput.Limit, c.aptRunner)
		if err != nil {
			submission.Error = safeAgentError(err)
		} else {
			submission.Result, err = json.Marshal(result)
			if err != nil {
				submission.Error = "package search result could not be encoded"
			}
		}
	case hostops.OperationWriteFile:
		var operationInput hostops.WriteFileInput
		if err := decodeJobJSON(strings.NewReader(string(input)), &operationInput); err != nil {
			submission.Error = "write-file input is invalid"
			break
		}
		result, err := hostops.WriteFile(operationInput.Path, operationInput.Content, config.WritablePaths)
		if err != nil {
			submission.Error = "file write failed; check host writable-path policy, filesystem permissions, and available space"
		} else {
			submission.Result, err = json.Marshal(result)
			if err != nil {
				submission.Error = "write-file result could not be encoded"
			}
		}
	case hostops.OperationRestoreFile:
		var operationInput hostops.RestoreFileInput
		if err := decodeJobJSON(strings.NewReader(string(input)), &operationInput); err != nil {
			submission.Error = "restore-file input is invalid"
			break
		}
		result, err := hostops.RestoreFile(operationInput, config.WritablePaths)
		if err != nil {
			submission.Error = "file restoration failed; exact restoration is unavailable due to host policy or filesystem error"
		} else {
			submission.Result, err = json.Marshal(result)
			if err != nil {
				submission.Error = "restore-file result could not be encoded"
			}
		}
	case hostops.OperationAPTUpdate, hostops.OperationAPTInstall, hostops.OperationAPTRemove, hostops.OperationAPTUpgrade:
		actionInput := hostops.APTActionInput{}
		if job.Operation == hostops.OperationAPTUpdate {
			var empty struct{}
			if err := decodeJobJSON(strings.NewReader(string(input)), &empty); err != nil {
				submission.Error = "APT update input is invalid"
				break
			}
		} else if err := decodeJobJSON(strings.NewReader(string(input)), &actionInput); err != nil {
			submission.Error = "APT package action input is invalid"
			break
		}
		result, err := hostops.RunAPTAction(ctx, job.Operation, actionInput.Packages, config.APTPolicy, c.aptRunner)
		if err != nil {
			submission.Error = "APT action was denied by host package policy or could not run safely"
		} else {
			submission.Result, err = json.Marshal(result)
			if err != nil {
				submission.Error = "APT action result could not be encoded"
			}
		}
	case hostops.OperationAPTRollback:
		var rollbackInput hostops.APTRollbackInput
		if err := decodeJobJSON(strings.NewReader(string(input)), &rollbackInput); err != nil {
			submission.Error = "APT rollback input is invalid"
			break
		}
		result, err := hostops.RestoreAPTAction(ctx, rollbackInput.Previous, rollbackInput.ExpectedCurrent, config.APTPolicy, c.aptRunner)
		if err != nil {
			submission.Error = "APT rollback was denied by host package policy or could not run safely"
		} else {
			submission.Result, err = json.Marshal(result)
			if err != nil {
				submission.Error = "APT rollback result could not be encoded"
			}
		}
	case hostops.OperationExecuteCommand:
		var commandInput hostops.CommandInput
		if err := decodeJobJSON(strings.NewReader(string(input)), &commandInput); err != nil {
			submission.Error = "command input is invalid"
			break
		}
		result, err := hostops.ExecuteCommand(ctx, config.CommandPolicy, commandInput, nil)
		if err != nil {
			submission.Error = "command was denied by host policy or could not complete safely"
		} else {
			submission.Result, err = json.Marshal(result)
			if err != nil {
				submission.Error = "command result could not be encoded"
			}
		}
	default:
		submission.Error = "agent does not support the requested operation"
	}
	encoded, err := json.Marshal(submission)
	if err != nil {
		return fmt.Errorf("encode agent result")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL(baseURL, "/agent/result"), strings.NewReader(string(encoded)))
	if err != nil {
		return fmt.Errorf("create agent result request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+config.Credential)
	request.Header.Set("Content-Type", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("send agent result request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusConflict {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 16<<10))
		return nil
	}
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 16<<10))
		return fmt.Errorf("control plane rejected agent result (HTTP %d)", response.StatusCode)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 16<<10))
	return nil
}

func safeAgentError(err error) string {
	message := strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f {
			return ' '
		}
		return character
	}, strings.TrimSpace(err.Error()))
	message = strings.TrimSpace(message)
	if message == "" {
		return "system information collection failed"
	}
	if len(message) > 4096 {
		message = message[:4096]
	}
	return message
}

func (c *Client) Run(ctx context.Context, config Config, interval time.Duration) error {
	if interval <= 0 {
		return fmt.Errorf("agent poll interval must be greater than zero")
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := c.PollOnce(ctx, config); err != nil {
			return err
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func SaveConfig(path string, config Config) error {
	if _, err := parseServerURL(config.ServerURL); err != nil {
		return err
	}
	if config.HostID == "" || config.Credential == "" {
		return fmt.Errorf("agent configuration is missing its host identity or credential")
	}
	allowedPaths, err := hostops.NormalizeAllowedPaths(config.AllowedPaths)
	if err != nil {
		return err
	}
	config.AllowedPaths = allowedPaths
	writablePaths, err := hostops.NormalizeWritablePaths(config.WritablePaths)
	if err != nil {
		return err
	}
	config.WritablePaths = writablePaths
	aptPolicy, err := hostops.NormalizeAPTPolicy(config.APTPolicy)
	if err != nil {
		return fmt.Errorf("invalid agent APT policy: %w", err)
	}
	config.APTPolicy = aptPolicy
	commandPolicy, err := hostops.NormalizeCommandPolicy(config.CommandPolicy)
	if err != nil {
		return fmt.Errorf("invalid agent command policy: %w", err)
	}
	config.CommandPolicy = commandPolicy
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("encode agent configuration")
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maxAgentConfigBytes {
		return fmt.Errorf("agent configuration exceeds the %d KiB size limit", maxAgentConfigBytes>>10)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create agent configuration directory: %w", err)
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".agent-config-*")
	if err != nil {
		return fmt.Errorf("create temporary agent configuration: %w", err)
	}
	temporaryPath := file.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("set agent configuration permissions: %w", err)
	}
	if _, err := file.Write(encoded); err != nil {
		_ = file.Close()
		return fmt.Errorf("write agent configuration: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync agent configuration: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close agent configuration: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("save agent configuration: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("secure agent configuration: %w", err)
	}
	return nil
}

func LoadConfig(path string) (Config, error) {
	linkInfo, err := os.Lstat(path)
	if err != nil {
		return Config{}, fmt.Errorf("inspect agent configuration: %w", err)
	}
	if !linkInfo.Mode().IsRegular() {
		return Config{}, fmt.Errorf("agent configuration must be a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open agent configuration: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return Config{}, fmt.Errorf("inspect agent configuration: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return Config{}, fmt.Errorf("agent configuration permissions are too broad; set mode 0600")
	}
	if info.Size() > maxAgentConfigBytes {
		return Config{}, fmt.Errorf("agent configuration exceeds the 16 KiB size limit")
	}
	var config Config
	if err := decodeJSON(file, &config); err != nil {
		return Config{}, fmt.Errorf("decode agent configuration: %w", err)
	}
	if _, err := parseServerURL(config.ServerURL); err != nil {
		return Config{}, err
	}
	if config.HostID == "" || config.Credential == "" {
		return Config{}, fmt.Errorf("agent configuration is missing its host identity or credential")
	}
	config.AllowedPaths, err = hostops.NormalizeAllowedPaths(config.AllowedPaths)
	if err != nil {
		return Config{}, err
	}
	config.WritablePaths, err = hostops.NormalizeWritablePaths(config.WritablePaths)
	if err != nil {
		return Config{}, err
	}
	config.APTPolicy, err = hostops.NormalizeAPTPolicy(config.APTPolicy)
	if err != nil {
		return Config{}, fmt.Errorf("invalid agent APT policy: %w", err)
	}
	config.CommandPolicy, err = hostops.NormalizeCommandPolicy(config.CommandPolicy)
	if err != nil {
		return Config{}, fmt.Errorf("invalid agent command policy: %w", err)
	}
	return config, nil
}

func decodeJSON(reader io.Reader, destination any) error {
	return decodeJSONLimit(reader, destination, maxAgentConfigBytes)
}

func decodeJobJSON(reader io.Reader, destination any) error {
	return decodeJSONLimit(reader, destination, maxAgentJobPayloadBytes)
}

func decodeJSONLimit(reader io.Reader, destination any, maxBytes int64) error {
	if maxBytes <= 0 {
		return fmt.Errorf("JSON size limit must be greater than zero")
	}
	encoded, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil {
		return err
	}
	if int64(len(encoded)) > maxBytes {
		return fmt.Errorf("JSON input exceeds the %d-byte size limit", maxBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("JSON input must contain one value")
	}
	return nil
}

func parseServerURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("agent server URL must be absolute and must not contain credentials, a query, or a fragment")
	}
	if parsed.Scheme == "https" {
		return parsed, nil
	}
	if parsed.Scheme == "http" && loopbackHost(parsed.Hostname()) {
		return parsed, nil
	}
	return nil, fmt.Errorf("agent server URL must use HTTPS")
}

func endpointURL(baseURL *url.URL, endpoint string) string {
	joined := *baseURL
	joined.Path = strings.TrimRight(joined.Path, "/") + endpoint
	joined.RawPath = ""
	return joined.String()
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	parsed := net.ParseIP(host)
	return parsed != nil && parsed.IsLoopback()
}
