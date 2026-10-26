// Package mcpserver registers the shared MCP contract for local and remote transports.
package mcpserver

import (
	"context"
	"time"

	"github.com/averyfreeman/ubuntu-fleet-manager/internal/systeminfo"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type SystemInfoCollector func() (systeminfo.Info, error)

type Host struct {
	ID           string    `json:"id" jsonschema:"host identifier"`
	Hostname     string    `json:"hostname" jsonschema:"managed host name"`
	OSPrettyName string    `json:"os_pretty_name" jsonschema:"operating system name reported by the host"`
	EnrolledAt   time.Time `json:"enrolled_at" jsonschema:"time the host was enrolled"`
	LastSeenAt   time.Time `json:"last_seen_at" jsonschema:"time the host last contacted the control plane"`
}

type ListHostsInput struct {
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum number of hosts to return (default 50, maximum 200)"`
	Cursor string `json:"cursor,omitempty" jsonschema:"opaque cursor returned by the previous page"`
}

type HostPage struct {
	Hosts      []Host `json:"hosts" jsonschema:"hosts in the authenticated operator's personal tenant"`
	NextCursor string `json:"next_cursor,omitempty" jsonschema:"opaque cursor for the next page when more hosts are available"`
}

type HostLister func(context.Context, ListHostsInput) (HostPage, error)

type PairingCode struct {
	Code      string    `json:"pairing_code" jsonschema:"one-time secret code to enter on the host being enrolled"`
	ExpiresAt time.Time `json:"expires_at" jsonschema:"UTC expiry time; the code is valid for ten minutes"`
}

type PairingCodeCreator func(context.Context) (PairingCode, error)

type HostRemoval struct {
	HostID  string `json:"host_id" jsonschema:"identifier of the removed host"`
	Removed bool   `json:"removed" jsonschema:"whether the host credential has been revoked"`
}

type HostRemover func(context.Context, string) (HostRemoval, error)

func New(collect SystemInfoCollector, listHosts HostLister, createPairingCode PairingCodeCreator, removeHost HostRemover) *mcp.Server {
	server := mcp.NewServer(
		&mcp.Implementation{Name: "ubuntu-fleet-manager", Version: "0.1.0-dev"},
		nil,
	)
	closedWorld := false
	destructive := true
	notDestructive := false
	mcp.AddTool[struct{}, systeminfo.Info](
		server,
		&mcp.Tool{
			Name:        "get_system_info",
			Description: "Read OS, kernel, architecture, memory, and root filesystem information from the local Linux host.",
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint:   true,
				IdempotentHint: true,
				OpenWorldHint:  &closedWorld,
			},
		},
		func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, systeminfo.Info, error) {
			info, err := collect()
			return nil, info, err
		},
	)
	if listHosts != nil {
		mcp.AddTool[ListHostsInput, HostPage](
			server,
			&mcp.Tool{
				Name:        "list_hosts",
				Description: "List managed hosts enrolled in the authenticated operator's personal tenant.",
				Annotations: &mcp.ToolAnnotations{
					ReadOnlyHint:   true,
					IdempotentHint: true,
					OpenWorldHint:  &closedWorld,
				},
			},
			func(ctx context.Context, _ *mcp.CallToolRequest, input ListHostsInput) (*mcp.CallToolResult, HostPage, error) {
				page, err := listHosts(ctx, input)
				return nil, page, err
			},
		)
	}
	if createPairingCode != nil {
		mcp.AddTool[struct{}, PairingCode](
			server,
			&mcp.Tool{
				Name:        "create_pairing_code",
				Description: "Create a one-time ten-minute pairing code for an Ubuntu host in your personal tenant. Treat the returned code as a secret and share it only with the host you intend to enroll.",
				Annotations: &mcp.ToolAnnotations{
					ReadOnlyHint:    false,
					DestructiveHint: &notDestructive,
					IdempotentHint:  false,
					OpenWorldHint:   &closedWorld,
				},
			},
			func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, PairingCode, error) {
				code, err := createPairingCode(ctx)
				return nil, code, err
			},
		)
	}
	if removeHost != nil {
		mcp.AddTool[struct {
			HostID string `json:"host_id" jsonschema:"identifier of the managed host to remove"`
		}, HostRemoval](
			server,
			&mcp.Tool{
				Name:        "remove_host",
				Description: "Remove a managed host from your active inventory and revoke its host credential. This disconnects the host from the control plane and cannot be undone by that host.",
				Annotations: &mcp.ToolAnnotations{
					ReadOnlyHint:    false,
					DestructiveHint: &destructive,
					IdempotentHint:  true,
					OpenWorldHint:   &closedWorld,
				},
			},
			func(ctx context.Context, _ *mcp.CallToolRequest, input struct {
				HostID string `json:"host_id" jsonschema:"identifier of the managed host to remove"`
			}) (*mcp.CallToolResult, HostRemoval, error) {
				result, err := removeHost(ctx, input.HostID)
				return nil, result, err
			},
		)
	}
	return server
}
