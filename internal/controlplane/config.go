package controlplane

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Config struct {
	ListenAddress         string
	DatabaseURL           string
	OIDCIssuerURL         string
	OIDCAudience          string
	PublicURL             string
	FileActionKeyFile     string
	AllowFileWrites       bool
	AllowAPTWrites        bool
	AllowCommandExecution bool

	allowInsecureOIDCTest bool
}

func LoadConfigFromEnv() (Config, error) {
	config := Config{
		ListenAddress:     strings.TrimSpace(os.Getenv("LISTEN_ADDR")),
		DatabaseURL:       strings.TrimSpace(os.Getenv("DATABASE_URL")),
		OIDCIssuerURL:     strings.TrimSpace(os.Getenv("OIDC_ISSUER_URL")),
		OIDCAudience:      strings.TrimSpace(os.Getenv("OIDC_AUDIENCE")),
		PublicURL:         strings.TrimSpace(os.Getenv("PUBLIC_URL")),
		FileActionKeyFile: strings.TrimSpace(os.Getenv("FILE_ACTION_KEY_FILE")),
	}
	if config.ListenAddress == "" {
		config.ListenAddress = ":8080"
	}
	if configured := strings.TrimSpace(os.Getenv("ALLOW_FILE_WRITES")); configured != "" {
		switch strings.ToLower(configured) {
		case "true":
			config.AllowFileWrites = true
		case "false":
			config.AllowFileWrites = false
		default:
			return Config{}, fmt.Errorf("ALLOW_FILE_WRITES must be true or false")
		}
	}
	if configured := strings.TrimSpace(os.Getenv("ALLOW_APT_WRITES")); configured != "" {
		switch strings.ToLower(configured) {
		case "true":
			config.AllowAPTWrites = true
		case "false":
			config.AllowAPTWrites = false
		default:
			return Config{}, fmt.Errorf("ALLOW_APT_WRITES must be true or false")
		}
	}
	if configured := strings.TrimSpace(os.Getenv("ALLOW_COMMAND_EXECUTION")); configured != "" {
		switch strings.ToLower(configured) {
		case "true":
			config.AllowCommandExecution = true
		case "false":
			config.AllowCommandExecution = false
		default:
			return Config{}, fmt.Errorf("ALLOW_COMMAND_EXECUTION must be true or false")
		}
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (c Config) Validate() error {
	if c.DatabaseURL == "" {
		return fmt.Errorf("DATABASE_URL is required")
	}
	parsedDB, err := pgxpool.ParseConfig(c.DatabaseURL)
	if err != nil || parsedDB.ConnConfig.Host == "" || parsedDB.ConnConfig.Database == "" {
		return fmt.Errorf("DATABASE_URL must be a valid PostgreSQL connection URL")
	}
	if err := validateURL("OIDC_ISSUER_URL", c.OIDCIssuerURL, false, c.allowInsecureOIDCTest); err != nil {
		return err
	}
	if c.OIDCAudience == "" {
		return fmt.Errorf("OIDC_AUDIENCE is required")
	}
	if err := validateURL("PUBLIC_URL", c.PublicURL, true, false); err != nil {
		return err
	}
	if c.FileActionKeyFile == "" || !filepath.IsAbs(c.FileActionKeyFile) {
		return fmt.Errorf("FILE_ACTION_KEY_FILE must be an absolute path to the mounted application encryption key")
	}
	if c.ListenAddress == "" {
		return fmt.Errorf("LISTEN_ADDR must not be empty")
	}
	if _, port, err := net.SplitHostPort(c.ListenAddress); err != nil {
		return fmt.Errorf("LISTEN_ADDR must be a host:port pair")
	} else if portNumber, err := strconv.Atoi(port); err != nil || portNumber < 1 || portNumber > 65535 {
		return fmt.Errorf("LISTEN_ADDR port must be between 1 and 65535")
	}
	return nil
}

func validateURL(name, raw string, allowLoopbackHTTP, allowTestHTTP bool) error {
	if raw == "" {
		return fmt.Errorf("%s is required", name)
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("%s must be an absolute URL without credentials, query, or fragment", name)
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname()) && (allowLoopbackHTTP || allowTestHTTP) {
		return nil
	}
	return fmt.Errorf("%s must use HTTPS", name)
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (c Config) resourceURL() string {
	base, _ := url.Parse(c.PublicURL)
	base.Path = strings.TrimRight(base.Path, "/") + "/mcp"
	base.RawPath = ""
	return base.String()
}

func (c Config) resourceMetadataURL() string {
	resource, _ := url.Parse(c.resourceURL())
	resource.Path = "/.well-known/oauth-protected-resource" + resource.Path
	resource.RawPath = ""
	return resource.String()
}

func (c Config) resourceMetadataPath() string {
	resource, _ := url.Parse(c.resourceMetadataURL())
	return resource.EscapedPath()
}
