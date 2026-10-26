//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/averyfreeman/ubuntu-fleet-manager/internal/agent"
	"github.com/averyfreeman/ubuntu-fleet-manager/internal/apthelper"
	"github.com/averyfreeman/ubuntu-fleet-manager/internal/controlplane"
	"github.com/averyfreeman/ubuntu-fleet-manager/internal/hostops"
	"github.com/averyfreeman/ubuntu-fleet-manager/internal/localapt"
	"github.com/averyfreeman/ubuntu-fleet-manager/internal/mcpserver"
	"github.com/averyfreeman/ubuntu-fleet-manager/internal/securepayload"
	"github.com/averyfreeman/ubuntu-fleet-manager/internal/systeminfo"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type systemInfoCollector func() (systeminfo.Info, error)

type allowedPathFlags []string

func (paths *allowedPathFlags) String() string { return strings.Join(*paths, ",") }

func (paths *allowedPathFlags) Set(path string) error {
	*paths = append(*paths, path)
	return nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	if len(os.Args) > 1 && os.Args[1] == "apt-helper" {
		err = runAPTPolicyHelper(ctx, os.Args[2:])
	} else if len(os.Args) > 1 && os.Args[1] == "agent" {
		err = runAgentCommand(ctx, os.Args[2:])
	} else {
		transport := flag.String("transport", "stdio", "MCP transport: stdio or streamable-http")
		localAPTPolicyFile := flag.String("local-apt-policy-file", "", "private JSON allowlist enabling local stdio APT actions (default: disabled)")
		localAPTKeyFile := flag.String("local-apt-key-file", "", "private 32-byte key file for encrypted local APT action records; required with --local-apt-policy-file")
		flag.Parse()
		if *transport == "streamable-http" && (*localAPTPolicyFile != "" || *localAPTKeyFile != "") {
			err = fmt.Errorf("--local-apt-policy-file and --local-apt-key-file apply only to stdio transport")
		} else {
			switch *transport {
			case "stdio":
				err = runStdioWithAPTPolicy(ctx, systeminfo.Collect, *localAPTPolicyFile, *localAPTKeyFile)
			case "streamable-http":
				err = runStreamableHTTP(ctx)
			default:
				err = fmt.Errorf("unsupported transport %q (choose stdio or streamable-http)", *transport)
			}
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runAPTPolicyHelper(ctx context.Context, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: ubuntu-fleet-manager apt-helper <update|install|remove|upgrade|rollback> <apt-get arguments>")
	}
	return apthelper.Run(ctx, args[0], args[1:])
}

func runStdio(ctx context.Context) error {
	return runStdioWithCollector(ctx, systeminfo.Collect)
}

func runStdioWithCollector(ctx context.Context, collect systemInfoCollector) error {
	return runStdioWithAPTPolicy(ctx, collect, "", "")
}

func runStdioWithAPTPolicy(ctx context.Context, collect systemInfoCollector, policyPath, keyPath string) error {
	if (policyPath == "") != (keyPath == "") {
		return fmt.Errorf("--local-apt-policy-file and --local-apt-key-file must be supplied together")
	}
	var aptHandlers []mcpserver.APTToolHandlers
	var store *localapt.ActionStore
	if policyPath != "" {
		policy, err := localapt.LoadPolicyFile(policyPath)
		if err != nil {
			return err
		}
		key, err := securepayload.LoadKeyFile(keyPath)
		if err != nil {
			return err
		}
		statePath, err := localapt.DefaultActionStorePath()
		if err != nil {
			for index := range key {
				key[index] = 0
			}
			return err
		}
		store, err = localapt.NewActionStore(policy, key, statePath, nil)
		for index := range key {
			key[index] = 0
		}
		if err != nil {
			return err
		}
		aptHandlers = append(aptHandlers, store.ToolHandlers())
	}
	if collect == nil {
		collect = systeminfo.Collect
	}
	if store != nil {
		go store.RunCleanup(ctx)
	}
	return mcpserver.New(mcpserver.SystemInfoCollector(collect), nil, nil, nil, nil, nil, nil, nil, nil, nil, aptHandlers...).Run(ctx, &mcp.StdioTransport{})
}

func runStreamableHTTP(ctx context.Context) error {
	config, err := controlplane.LoadConfigFromEnv()
	if err != nil {
		return err
	}
	service, err := controlplane.New(ctx, config)
	if err != nil {
		return err
	}
	defer service.Close()

	server := &http.Server{
		Addr:              config.ListenAddress,
		Handler:           service.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- server.ListenAndServe()
	}()

	select {
	case err := <-serverErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
			return fmt.Errorf("shut down HTTP server: %w", err)
		}
		if err := <-serverErrors; !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

func runAgentCommand(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: ubuntu-fleet-manager agent <enroll|run>")
	}
	switch args[0] {
	case "enroll":
		flags := flag.NewFlagSet("agent enroll", flag.ContinueOnError)
		flags.SetOutput(os.Stderr)
		serverURL := flags.String("server", "", "public HTTPS base URL of the control plane")
		pairingCode := flags.String("pairing-code", "", "one-time pairing code created by the authenticated operator")
		pairingCodeStdin := flags.Bool("pairing-code-stdin", false, "read the one-time pairing code from standard input")
		configPath := flags.String("config", "", "credential config file path (default: per-user config directory)")
		var allowedPaths allowedPathFlags
		flags.Var(&allowedPaths, "allowed-path", "absolute directory permitted for read-only file tools; repeat to add boundaries (default: agent user's home directory)")
		var writablePaths allowedPathFlags
		flags.Var(&writablePaths, "writable-path", "absolute directory permitted for reversible file writes; repeat to add boundaries (default: no writable paths)")
		var aptOperations allowedPathFlags
		flags.Var(&aptOperations, "apt-operation", "explicitly allow one APT action: update, install, remove, upgrade, or rollback; repeat to add actions (default: none)")
		var aptPackages allowedPathFlags
		flags.Var(&aptPackages, "apt-package", "package name the agent may install, remove, or upgrade under the selected APT policy; repeat to add packages")
		if err := flags.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}
			return err
		}
		hasPairingCode := *pairingCode != ""
		if flags.NArg() != 0 || *serverURL == "" || hasPairingCode == *pairingCodeStdin {
			return fmt.Errorf("usage: ubuntu-fleet-manager agent enroll --server https://control-plane (--pairing-code CODE | --pairing-code-stdin) [--config PATH] [--allowed-path DIR ...] [--writable-path DIR ...] [--apt-operation ACTION ...] [--apt-package NAME ...]")
		}
		code := *pairingCode
		if *pairingCodeStdin {
			encoded, err := io.ReadAll(io.LimitReader(os.Stdin, 2049))
			if err != nil {
				return fmt.Errorf("read pairing code from standard input: %w", err)
			}
			if len(encoded) > 2048 {
				return fmt.Errorf("pairing code input exceeds the 2048-byte limit")
			}
			code = strings.TrimSpace(string(encoded))
			if code == "" {
				return fmt.Errorf("pairing code input is empty")
			}
		}
		info, err := systeminfo.Collect()
		if err != nil {
			return fmt.Errorf("collect host identity for enrollment: %w", err)
		}
		aptPolicy := hostops.APTPolicy{}
		if len(aptOperations) > 0 || len(aptPackages) > 0 {
			aptPolicy = hostops.APTPolicy{Enabled: true, AllowedOperations: aptOperations, AllowedPackages: aptPackages}
		}
		hostID, err := agent.NewClient(nil).EnrollWithAPTPolicy(ctx, *serverURL, code, info.Hostname, info.OS.PrettyName, *configPath, allowedPaths, writablePaths, aptPolicy)
		if err != nil {
			return err
		}
		path := *configPath
		if path == "" {
			path, err = agent.DefaultConfigPath()
			if err != nil {
				return err
			}
		}
		_, err = fmt.Fprintf(os.Stdout, "Enrolled host %s. Its credential is stored in %s with mode 0600.\n", hostID, path)
		return err
	case "run":
		flags := flag.NewFlagSet("agent run", flag.ContinueOnError)
		flags.SetOutput(os.Stderr)
		configPath := flags.String("config", "", "credential config file path (default: per-user config directory)")
		interval := flags.Duration("interval", 30*time.Second, "time between outbound control-plane polls")
		if err := flags.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}
			return err
		}
		if flags.NArg() != 0 {
			return fmt.Errorf("usage: ubuntu-fleet-manager agent run [--config PATH] [--interval DURATION]")
		}
		path := *configPath
		if path == "" {
			var err error
			path, err = agent.DefaultConfigPath()
			if err != nil {
				return err
			}
		}
		config, err := agent.LoadConfig(path)
		if err != nil {
			return err
		}
		if err := agent.NewClient(nil).Run(ctx, config, *interval); err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
		return nil
	default:
		return fmt.Errorf("unsupported agent command %q (choose enroll or run)", args[0])
	}
}
