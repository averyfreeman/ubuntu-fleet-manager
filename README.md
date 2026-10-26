# Ubuntu Fleet Manager

Ubuntu Fleet Manager is an early-stage, self-hosted MCP service for administering Ubuntu hosts. Its Go runtime is being built in small, reviewable steps. The first Go implementation exposes one read-only tool, `get_system_info`, over MCP stdio. Remote host enrollment, the control plane, and host administration tools are planned work and are not available yet.

The repository retains the original Python server while the Go runtime and independent connector packages are developed. The current Python package documentation describes that legacy implementation; use the Go instructions below to run the new runtime.

## Build and run

The Go command requires Linux and the Go version listed in [`go.mod`](go.mod). Build the MCP server with:

```sh
go build -o ./build/ubuntu-fleet-manager ./cmd/ubuntu-fleet-manager
```

The server communicates over standard input and output using the MCP stdio transport. Configure an MCP client to launch the built binary directly. For Codex, add a server entry to `~/.codex/config.toml`:

```toml
[mcp_servers.ubuntu_fleet_manager]
command = "/absolute/path/to/ubuntu-fleet-manager/build/ubuntu-fleet-manager"
args = []
startup_timeout_sec = 30
tool_timeout_sec = 30
```

Restart Codex and use `/mcp` to check the connection. The server writes protocol messages to standard output; diagnostics go to standard error.

## Available tool

`get_system_info` reads the local host's OS release, hostname, kernel, architecture, memory, and root filesystem capacity. It accepts no arguments and returns typed structured content. The tool contract, fields, and error behavior are documented in [Get system information](docs/reference/tools/get-system-info.md).

The tool is read-only and does not execute commands or return credentials. It currently reads Linux system interfaces including `/etc/os-release`, `/proc/meminfo`, and the root filesystem statistics.

## Development

Run the Go test suite and static checks with the pinned toolchain:

```sh
GOTOOLCHAIN=go1.27.3 go test ./...
GOTOOLCHAIN=go1.27.3 go vet ./...
GOTOOLCHAIN=go1.27.3 go build ./...
```

Go behavior tests exercise the public MCP stdio contract. The official Go MCP SDK is pinned in [`go.mod`](go.mod).

## Project documentation

- [`GLOSSARY.md`](GLOSSARY.md) defines the domain terms used in the project.
- [`docs/adr/`](docs/adr/) records accepted architecture decisions.
- [Ubuntu Server documentation](https://documentation.ubuntu.com/server/) is the source for Ubuntu administration guidance. Feature docs use its Tutorial, How-to, Reference, and Explanation conventions.
- [Project specification and implementation tickets](https://github.com/averyfreeman/ubuntu-fleet-manager/issues) track the v0.1.0 work.

This project is not affiliated with Canonical. Ubuntu is a registered trademark of Canonical Ltd.
