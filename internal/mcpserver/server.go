// Package mcpserver registers the shared MCP contract for local and remote transports.
package mcpserver

import (
	"context"
	"time"

	"github.com/averyfreeman/ubuntu-fleet-manager/internal/hostops"
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

type HostSystemInfoInput struct {
	HostID string `json:"host_id" jsonschema:"identifier of the enrolled host to inspect"`
}

type HostSystemInfoResult struct {
	HostID      string          `json:"host_id" jsonschema:"identifier of the target host"`
	Hostname    string          `json:"hostname" jsonschema:"hostname reported during enrollment"`
	RequestedAt time.Time       `json:"requested_at" jsonschema:"UTC time when the control plane queued the request"`
	SystemInfo  systeminfo.Info `json:"system_info" jsonschema:"structured snapshot collected by the host agent"`
}

type HostSystemInfoGetter func(context.Context, HostSystemInfoInput) (HostSystemInfoResult, error)

type HostDirectoryInput struct {
	HostID string `json:"host_id" jsonschema:"identifier of the enrolled host to inspect"`
	Path   string `json:"path" jsonschema:"absolute directory path inside the host agent's configured read boundaries"`
}

type HostDirectoryResult struct {
	HostID      string                   `json:"host_id" jsonschema:"identifier of the target host"`
	Hostname    string                   `json:"hostname" jsonschema:"hostname reported during enrollment"`
	RequestedAt time.Time                `json:"requested_at" jsonschema:"UTC time when the control plane queued the request"`
	Listing     hostops.DirectoryListing `json:"listing" jsonschema:"directory entries, limited to 100, with a truncation indicator"`
}

type HostDirectoryLister func(context.Context, HostDirectoryInput) (HostDirectoryResult, error)

type HostFileInput struct {
	HostID string `json:"host_id" jsonschema:"identifier of the enrolled host to inspect"`
	Path   string `json:"path" jsonschema:"absolute regular-file path inside the host agent's configured read boundaries"`
}

type HostFileResult struct {
	HostID      string                 `json:"host_id" jsonschema:"identifier of the target host"`
	Hostname    string                 `json:"hostname" jsonschema:"hostname reported during enrollment"`
	RequestedAt time.Time              `json:"requested_at" jsonschema:"UTC time when the control plane queued the request"`
	File        hostops.FileReadResult `json:"file" jsonschema:"UTF-8 text file contents, limited to 256 KiB"`
}

type HostFileReader func(context.Context, HostFileInput) (HostFileResult, error)

type HostPackageSearchInput struct {
	HostID string `json:"host_id" jsonschema:"identifier of the enrolled host to search"`
	Query  string `json:"query" jsonschema:"literal text searched in configured APT package names and short descriptions (1 to 128 bytes)"`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum matches to return (default 50, maximum 100)"`
}

type HostPackageSearchResult struct {
	HostID      string                      `json:"host_id" jsonschema:"identifier of the target host"`
	Hostname    string                      `json:"hostname" jsonschema:"hostname reported during enrollment"`
	RequestedAt time.Time                   `json:"requested_at" jsonschema:"UTC time when the control plane queued the request"`
	Search      hostops.PackageSearchResult `json:"search" jsonschema:"package names and short descriptions from configured APT indexes"`
}

type HostPackageSearcher func(context.Context, HostPackageSearchInput) (HostPackageSearchResult, error)

type HostAPTUpdateInput struct {
	HostID string `json:"host_id,omitempty" jsonschema:"identifier of the enrolled host to refresh; required for remote fleet operations and omitted for local stdio"`
}

type HostAPTActionInput struct {
	HostID   string   `json:"host_id,omitempty" jsonschema:"identifier of the enrolled host to change; required for remote fleet operations and omitted for local stdio"`
	Packages []string `json:"packages" jsonschema:"one to 20 explicitly allowlisted APT package names"`
}

type HostAPTRollbackInput struct {
	HostID   string `json:"host_id,omitempty" jsonschema:"identifier of the host changed by the APT action; required for remote fleet operations and omitted for local stdio"`
	ActionID string `json:"action_id" jsonschema:"action_id returned by a package install, remove, or upgrade"`
}

type HostAPTActionResult struct {
	HostID            string    `json:"host_id,omitempty" jsonschema:"identifier of the target managed host; omitted for local stdio"`
	Hostname          string    `json:"hostname,omitempty" jsonschema:"hostname reported during enrollment; omitted for local stdio"`
	RequestedAt       time.Time `json:"requested_at,omitempty" jsonschema:"UTC time when the control plane queued the request"`
	ActionID          string    `json:"action_id" jsonschema:"identifier for the encrypted audit record and any available rollback"`
	Operation         string    `json:"operation" jsonschema:"APT operation that was attempted"`
	Outcome           string    `json:"outcome" jsonschema:"succeeded, failed, partial, or unknown"`
	ChangedPackages   int       `json:"changed_packages" jsonschema:"number of package states that changed during the operation"`
	RollbackAvailable bool      `json:"rollback_available" jsonschema:"whether captured package state supports a bounded compensating rollback"`
	ExpiresAt         time.Time `json:"expires_at" jsonschema:"UTC expiry time for the encrypted audit and rollback record"`
	Reason            string    `json:"reason,omitempty" jsonschema:"safe explanation for partial, failed, or unknown results"`
}

type HostAPTRollbackResult struct {
	HostID           string                             `json:"host_id,omitempty" jsonschema:"identifier of the target managed host; omitted for local stdio"`
	Hostname         string                             `json:"hostname,omitempty" jsonschema:"hostname reported during enrollment; omitted for local stdio"`
	ActionID         string                             `json:"action_id" jsonschema:"reversed APT action"`
	Outcome          string                             `json:"outcome" jsonschema:"succeeded or partial"`
	RestoredPackages int                                `json:"restored_packages" jsonschema:"number of named package states restored exactly"`
	Exact            bool                               `json:"exact" jsonschema:"whether all captured package states were restored exactly"`
	AlreadyRestored  bool                               `json:"already_restored" jsonschema:"whether this action had already been rolled back"`
	Packages         []hostops.APTPackageRollbackResult `json:"packages,omitempty" jsonschema:"per-package restoration result"`
	Reason           string                             `json:"reason,omitempty" jsonschema:"safe explanation when any package could not be restored"`
	RequestedAt      time.Time                          `json:"requested_at,omitempty" jsonschema:"UTC time when the control plane queued the rollback"`
}

type HostCommandInput struct {
	HostID           string   `json:"host_id" jsonschema:"identifier of the enrolled host to run the command on"`
	Executable       string   `json:"executable" jsonschema:"absolute executable path present in the host's exact command allowlist"`
	Arguments        []string `json:"args" jsonschema:"argument vector matching one exact host-policy rule; shell syntax is never interpreted"`
	WorkingDirectory string   `json:"working_directory,omitempty" jsonschema:"optional existing absolute directory in this command rule's working-directory allowlist"`
}

type HostCommandResult struct {
	HostID          string    `json:"host_id" jsonschema:"identifier of the target managed host"`
	Hostname        string    `json:"hostname" jsonschema:"hostname reported during enrollment"`
	RequestedAt     time.Time `json:"requested_at" jsonschema:"UTC time when the control plane queued the request"`
	ExitCode        int       `json:"exit_code" jsonschema:"process exit code, or -1 when terminated by a signal"`
	Stdout          string    `json:"stdout" jsonschema:"bounded UTF-8 standard output with common credential patterns redacted"`
	Stderr          string    `json:"stderr" jsonschema:"bounded UTF-8 standard error with common credential patterns redacted"`
	OutputTruncated bool      `json:"output_truncated" jsonschema:"whether command output exceeded the 64 KiB combined response limit"`
}

type HostCommandExecutor func(context.Context, HostCommandInput) (HostCommandResult, error)

type APTToolHandlers struct {
	Update         func(context.Context, HostAPTUpdateInput) (HostAPTActionResult, error)
	Install        func(context.Context, HostAPTActionInput) (HostAPTActionResult, error)
	Remove         func(context.Context, HostAPTActionInput) (HostAPTActionResult, error)
	Upgrade        func(context.Context, HostAPTActionInput) (HostAPTActionResult, error)
	Rollback       func(context.Context, HostAPTRollbackInput) (HostAPTRollbackResult, error)
	ExecuteCommand HostCommandExecutor
}

type HostFileWriteInput struct {
	HostID  string `json:"host_id" jsonschema:"identifier of the enrolled host to update"`
	Path    string `json:"path" jsonschema:"absolute file path inside the host agent's configured writable boundaries"`
	Content string `json:"content" jsonschema:"UTF-8 text to write, at most 256 KiB; file contents are stored encrypted for seven days to support rollback"`
}

type HostFileWriteResult struct {
	HostID       string    `json:"host_id" jsonschema:"identifier of the target host"`
	Hostname     string    `json:"hostname" jsonschema:"hostname reported during enrollment"`
	RequestedAt  time.Time `json:"requested_at" jsonschema:"UTC time when the control plane queued the request"`
	Path         string    `json:"path" jsonschema:"absolute file path that was updated"`
	ActionID     string    `json:"action_id" jsonschema:"identifier to pass to rollback_file within seven days"`
	Created      bool      `json:"created" jsonschema:"whether this operation created a new file"`
	BytesWritten int       `json:"bytes_written" jsonschema:"number of UTF-8 bytes written"`
	Mode         uint32    `json:"mode" jsonschema:"permission bits after the write; existing mode is preserved and new files use 0600"`
	ExpiresAt    time.Time `json:"expires_at" jsonschema:"UTC time after which the encrypted reversal payload is deleted"`
}

type HostFileWriter func(context.Context, HostFileWriteInput) (HostFileWriteResult, error)

type HostFileRollbackInput struct {
	HostID   string `json:"host_id" jsonschema:"identifier of the host changed by write_file"`
	ActionID string `json:"action_id" jsonschema:"action_id returned by write_file; valid for seven days"`
}

type HostFileRollbackResult struct {
	HostID          string    `json:"host_id" jsonschema:"identifier of the target host"`
	Hostname        string    `json:"hostname" jsonschema:"hostname reported during enrollment"`
	ActionID        string    `json:"action_id" jsonschema:"identifier of the reversed write action"`
	Restored        bool      `json:"restored" jsonschema:"whether the captured file state is now restored"`
	Exact           bool      `json:"exact" jsonschema:"whether captured existence, bytes, and permission bits match"`
	AlreadyRestored bool      `json:"already_restored" jsonschema:"whether the same action had already been rolled back"`
	Reason          string    `json:"reason,omitempty" jsonschema:"explanation when exact restoration could not be completed"`
	RequestedAt     time.Time `json:"requested_at" jsonschema:"UTC time when the rollback request was queued"`
}

type HostFileRollbacker func(context.Context, HostFileRollbackInput) (HostFileRollbackResult, error)

func New(collect SystemInfoCollector, listHosts HostLister, createPairingCode PairingCodeCreator, removeHost HostRemover, getHostSystemInfo HostSystemInfoGetter, listDirectory HostDirectoryLister, readFile HostFileReader, searchPackages HostPackageSearcher, writeFile HostFileWriter, rollbackFile HostFileRollbacker, aptToolHandlers ...APTToolHandlers) *mcp.Server {
	server := mcp.NewServer(
		&mcp.Implementation{Name: "ubuntu-fleet-manager", Version: "0.1.0"},
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
	if getHostSystemInfo != nil {
		mcp.AddTool[HostSystemInfoInput, HostSystemInfoResult](
			server,
			&mcp.Tool{
				Name:        "get_host_system_info",
				Description: "Get a fresh system-information snapshot from an enrolled host in your personal tenant. The host must be online and its authenticated agent must poll within 90 seconds.",
				Annotations: &mcp.ToolAnnotations{
					ReadOnlyHint:   true,
					IdempotentHint: true,
					OpenWorldHint:  &closedWorld,
				},
			},
			func(ctx context.Context, _ *mcp.CallToolRequest, input HostSystemInfoInput) (*mcp.CallToolResult, HostSystemInfoResult, error) {
				result, err := getHostSystemInfo(ctx, input)
				return nil, result, err
			},
		)
	}
	if listDirectory != nil {
		mcp.AddTool[HostDirectoryInput, HostDirectoryResult](
			server,
			&mcp.Tool{
				Name:        "list_directory",
				Description: "List at most 100 directory entries on an enrolled host. The absolute path must be inside the host agent's configured read boundaries; escaping symlinks are not followed.",
				Annotations: &mcp.ToolAnnotations{
					ReadOnlyHint:    true,
					DestructiveHint: &notDestructive,
					IdempotentHint:  true,
					OpenWorldHint:   &closedWorld,
				},
			},
			func(ctx context.Context, _ *mcp.CallToolRequest, input HostDirectoryInput) (*mcp.CallToolResult, HostDirectoryResult, error) {
				result, err := listDirectory(ctx, input)
				return nil, result, err
			},
		)
	}
	if readFile != nil {
		mcp.AddTool[HostFileInput, HostFileResult](
			server,
			&mcp.Tool{
				Name:        "read_file",
				Description: "Read a UTF-8 regular file of at most 256 KiB from an enrolled host. The absolute path must be inside the host agent's configured read boundaries; escaping symlinks are rejected.",
				Annotations: &mcp.ToolAnnotations{
					ReadOnlyHint:    true,
					DestructiveHint: &notDestructive,
					IdempotentHint:  true,
					OpenWorldHint:   &closedWorld,
				},
			},
			func(ctx context.Context, _ *mcp.CallToolRequest, input HostFileInput) (*mcp.CallToolResult, HostFileResult, error) {
				result, err := readFile(ctx, input)
				return nil, result, err
			},
		)
	}
	if searchPackages != nil {
		mcp.AddTool[HostPackageSearchInput, HostPackageSearchResult](
			server,
			&mcp.Tool{
				Name:        "search_packages",
				Description: "Search configured APT package indexes on an enrolled host without changing package state. Returns at most 100 matches (default 50); the query is treated as literal text.",
				Annotations: &mcp.ToolAnnotations{
					ReadOnlyHint:    true,
					DestructiveHint: &notDestructive,
					IdempotentHint:  true,
					OpenWorldHint:   &closedWorld,
				},
			},
			func(ctx context.Context, _ *mcp.CallToolRequest, input HostPackageSearchInput) (*mcp.CallToolResult, HostPackageSearchResult, error) {
				result, err := searchPackages(ctx, input)
				return nil, result, err
			},
		)
	}
	if writeFile != nil {
		mcp.AddTool[HostFileWriteInput, HostFileWriteResult](
			server,
			&mcp.Tool{
				Name:        "write_file",
				Description: "Write UTF-8 text of at most 256 KiB to a regular file within the host agent's separately configured writable paths. Existing permission bits are preserved; new files use mode 0600. The previous existence, bytes, and mode are encrypted in the control plane for seven days and can be restored with rollback_file. The control plane must enable ALLOW_FILE_WRITES and the MCP client must request per-call human confirmation.",
				Annotations: &mcp.ToolAnnotations{
					ReadOnlyHint:    false,
					DestructiveHint: &destructive,
					IdempotentHint:  false,
					OpenWorldHint:   &closedWorld,
				},
			},
			func(ctx context.Context, _ *mcp.CallToolRequest, input HostFileWriteInput) (*mcp.CallToolResult, HostFileWriteResult, error) {
				result, err := writeFile(ctx, input)
				return nil, result, err
			},
		)
	}
	if rollbackFile != nil {
		mcp.AddTool[HostFileRollbackInput, HostFileRollbackResult](
			server,
			&mcp.Tool{
				Name:        "rollback_file",
				Description: "Restore existence, bytes, and permission bits captured by write_file within seven days. The rollback is refused if the file no longer matches the managed write or captured prior state, so later manual edits are preserved. Ownership, ACLs, and extended attributes are not captured. The control plane must enable ALLOW_FILE_WRITES and the MCP client must request per-call human confirmation.",
				Annotations: &mcp.ToolAnnotations{
					ReadOnlyHint:    false,
					DestructiveHint: &destructive,
					IdempotentHint:  true,
					OpenWorldHint:   &closedWorld,
				},
			},
			func(ctx context.Context, _ *mcp.CallToolRequest, input HostFileRollbackInput) (*mcp.CallToolResult, HostFileRollbackResult, error) {
				result, err := rollbackFile(ctx, input)
				return nil, result, err
			},
		)
	}
	if len(aptToolHandlers) != 0 {
		registerHostOperationTools(server, aptToolHandlers[0], destructive, closedWorld)
	}
	return server
}

func registerHostOperationTools(server *mcp.Server, handlers APTToolHandlers, destructive, closedWorld bool) {
	annotations := func(idempotent bool) *mcp.ToolAnnotations {
		openWorld := true
		return &mcp.ToolAnnotations{
			ReadOnlyHint:    false,
			DestructiveHint: &destructive,
			IdempotentHint:  idempotent,
			OpenWorldHint:   &openWorld,
		}
	}
	if handlers.Update != nil {
		mcp.AddTool[HostAPTUpdateInput, HostAPTActionResult](server, &mcp.Tool{
			Name: "apt_update", Description: "Refresh the target host's existing APT indexes. This does not install packages and has no rollback. On HTTP, the control plane must enable ALLOW_APT_WRITES and the host must allow the update operation. On stdio, the operator must provide an explicit local APT policy and private action key. HTTP MCP clients must request per-call human confirmation.",
			Annotations: annotations(true),
		}, func(ctx context.Context, _ *mcp.CallToolRequest, input HostAPTUpdateInput) (*mcp.CallToolResult, HostAPTActionResult, error) {
			result, err := handlers.Update(ctx, input)
			return nil, result, err
		})
	}
	registerPackageAction := func(name, description string, handler func(context.Context, HostAPTActionInput) (HostAPTActionResult, error)) {
		if handler == nil {
			return
		}
		mcp.AddTool[HostAPTActionInput, HostAPTActionResult](server, &mcp.Tool{
			Name: name, Description: description, Annotations: annotations(false),
		}, func(ctx context.Context, _ *mcp.CallToolRequest, input HostAPTActionInput) (*mcp.CallToolResult, HostAPTActionResult, error) {
			result, err := handler(ctx, input)
			return nil, result, err
		})
	}
	registerPackageAction("apt_install", "Install one to 20 explicitly allowlisted packages from the host's existing APT repositories. The agent captures affected package versions and outcome. On HTTP, ALLOW_APT_WRITES and the host's package policy must allow the operation. On stdio, an explicit local APT policy and private action key are required. HTTP MCP clients must request per-call human confirmation.", handlers.Install)
	registerPackageAction("apt_remove", "Remove one to 20 explicitly allowlisted packages without purge or autoremove. The agent captures affected package versions and outcome. Rollback is best-effort and may be partial when package versions or dependencies have changed. On HTTP, ALLOW_APT_WRITES and the host's package policy must allow the operation. On stdio, an explicit local APT policy and private action key are required. HTTP MCP clients must request per-call human confirmation.", handlers.Remove)
	registerPackageAction("apt_upgrade", "Upgrade one to 20 already-installed, explicitly allowlisted packages from the host's existing APT repositories. Full-upgrade and package removal are not used. Rollback is best-effort and may be partial when package versions or dependencies have changed. On HTTP, ALLOW_APT_WRITES and the host's package policy must allow the operation. On stdio, an explicit local APT policy and private action key are required. HTTP MCP clients must request per-call human confirmation.", handlers.Upgrade)
	if handlers.Rollback != nil {
		mcp.AddTool[HostAPTRollbackInput, HostAPTRollbackResult](server, &mcp.Tool{
			Name: "rollback_apt_action", Description: "Attempt to restore the package versions and installed state captured by an apt_install, apt_remove, or apt_upgrade action. Later package changes are preserved; unavailable versions or dependency constraints produce a partial result. On HTTP, ALLOW_APT_WRITES and the host's rollback policy must allow the operation. On stdio, an explicit local APT policy and private action key are required. HTTP MCP clients must request per-call human confirmation.",
			Annotations: annotations(true),
		}, func(ctx context.Context, _ *mcp.CallToolRequest, input HostAPTRollbackInput) (*mcp.CallToolResult, HostAPTRollbackResult, error) {
			result, err := handlers.Rollback(ctx, input)
			return nil, result, err
		})
	}
	if handlers.ExecuteCommand != nil {
		mcp.AddTool[HostCommandInput, HostCommandResult](server, &mcp.Tool{
			Name:        "execute_command",
			Description: "Run one exact host-allowlisted executable with an exact allowed argument vector and optional allowed working directory. Arguments are passed directly; no shell is invoked. Sudo is disabled unless the host policy enables this exact rule and matching non-interactive sudoers permission exists. Output is capped and common credential patterns are redacted. The command may change host state and has no rollback. HTTP MCP clients must request per-call human confirmation.",
			Annotations: annotations(false),
		}, func(ctx context.Context, _ *mcp.CallToolRequest, input HostCommandInput) (*mcp.CallToolResult, HostCommandResult, error) {
			result, err := handlers.ExecuteCommand(ctx, input)
			return nil, result, err
		})
	}
}
