//go:build linux

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/averyfreeman/ubuntu-fleet-manager/internal/systeminfo"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type systemInfoCollector func() (systeminfo.Info, error)

func main() {
	if err := runStdio(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runStdio(ctx context.Context) error {
	return runStdioWithCollector(ctx, systeminfo.Collect)
}

func runStdioWithCollector(ctx context.Context, collect systemInfoCollector) error {
	return newServer(collect).Run(ctx, &mcp.StdioTransport{})
}

func newServer(collect systemInfoCollector) *mcp.Server {
	server := mcp.NewServer(
		&mcp.Implementation{Name: "ubuntu-fleet-manager", Version: "0.1.0-dev"},
		nil,
	)
	openWorld := false
	mcp.AddTool[struct{}, systeminfo.Info](
		server,
		&mcp.Tool{
			Name:        "get_system_info",
			Description: "Read OS, kernel, architecture, memory, and root filesystem information from the local Linux host.",
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint:   true,
				IdempotentHint: true,
				OpenWorldHint:  &openWorld,
			},
		},
		func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, systeminfo.Info, error) {
			info, err := collect()
			return nil, info, err
		},
	)
	return server
}
