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

func New(collect SystemInfoCollector, listHosts HostLister) *mcp.Server {
	server := mcp.NewServer(
		&mcp.Implementation{Name: "ubuntu-fleet-manager", Version: "0.1.0-dev"},
		nil,
	)
	closedWorld := false
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
	return server
}
