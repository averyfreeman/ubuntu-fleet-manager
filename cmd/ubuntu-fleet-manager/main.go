//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/averyfreeman/ubuntu-fleet-manager/internal/controlplane"
	"github.com/averyfreeman/ubuntu-fleet-manager/internal/mcpserver"
	"github.com/averyfreeman/ubuntu-fleet-manager/internal/systeminfo"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type systemInfoCollector func() (systeminfo.Info, error)

func main() {
	transport := flag.String("transport", "stdio", "MCP transport: stdio or streamable-http")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch *transport {
	case "stdio":
		err = runStdio(ctx)
	case "streamable-http":
		err = runStreamableHTTP(ctx)
	default:
		err = fmt.Errorf("unsupported transport %q (choose stdio or streamable-http)", *transport)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runStdio(ctx context.Context) error {
	return runStdioWithCollector(ctx, systeminfo.Collect)
}

func runStdioWithCollector(ctx context.Context, collect systemInfoCollector) error {
	return mcpserver.New(mcpserver.SystemInfoCollector(collect), nil).Run(ctx, &mcp.StdioTransport{})
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
