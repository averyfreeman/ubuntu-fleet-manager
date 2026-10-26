# Try the local MCP server

This tutorial builds the Go MCP runtime and connects it to Codex so you can inspect the Linux system running the MCP process.

## Before you begin

- Use a Linux host with the Go version listed in [`go.mod`](../../go.mod).
- Install Codex and know where its user configuration file is stored.

## Build the runtime

From the repository root, build the Go binary:

```sh
go build -o ./build/ubuntu-fleet-manager ./cmd/ubuntu-fleet-manager
```

The binary uses stdio by default. It writes MCP messages to standard output and diagnostics to standard error.

## Connect Codex

Add this server entry to `~/.codex/config.toml`, replacing the path with the absolute path to the binary you built:

```toml
[mcp_servers.ubuntu_fleet_manager]
command = "/absolute/path/to/ubuntu-fleet-manager/build/ubuntu-fleet-manager"
args = []
startup_timeout_sec = 30
tool_timeout_sec = 30
```

Restart Codex and run `/mcp` to confirm that `ubuntu_fleet_manager` is connected. Discover the available tool and call `get_system_info`.

## Check the result

The result contains the OS release, hostname, kernel, architecture, memory, root filesystem capacity, and collection time. It describes the Linux host where the MCP process runs. It does not inspect another host or change system state.

For managed remote hosts, deploy the Streamable HTTP control plane and enroll a host agent using [Deploy the self-hosted control plane](../how-to/deploy-control-plane.md) and [Enroll and run a host agent](../how-to/enroll-host-agent.md).
