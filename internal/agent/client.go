// Package agent contains the unprivileged host agent's outbound control-plane client.
package agent

import (
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
)

type Config struct {
	ServerURL  string `json:"server_url"`
	HostID     string `json:"host_id"`
	Credential string `json:"credential"`
}

type Client struct {
	httpClient *http.Client
}

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
	Status string `json:"status"`
}

func NewClient(client *http.Client) *Client {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	} else {
		clientCopy := *client
		client = &clientCopy
	}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &Client{httpClient: client}
}

func DefaultConfigPath() (string, error) {
	configDirectory, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("find user configuration directory: %w", err)
	}
	return filepath.Join(configDirectory, "ubuntu-fleet-manager", "agent.json"), nil
}

func (c *Client) Enroll(ctx context.Context, serverURL, pairingCode, hostname, osPrettyName, configPath string) (string, error) {
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
	config := Config{ServerURL: strings.TrimRight(serverURL, "/"), HostID: enrollment.HostID, Credential: enrollment.Credential}
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
	if err := decodeJSON(response.Body, &result); err != nil {
		return fmt.Errorf("read agent poll response: %w", err)
	}
	if result.Status != "idle" {
		return fmt.Errorf("control plane returned an unsupported agent poll response")
	}
	return nil
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
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("encode agent configuration")
	}
	encoded = append(encoded, '\n')
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
	if info.Size() > 16<<10 {
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
	return config, nil
}

func decodeJSON(reader io.Reader, destination any) error {
	decoder := json.NewDecoder(io.LimitReader(reader, 16<<10))
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
