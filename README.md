# Ubuntu Fleet Manager

Ubuntu Fleet Manager is an early-stage, self-hosted MCP service for administering Ubuntu hosts. The Go runtime exposes local system information over MCP stdio and an authenticated Streamable HTTP control plane with a tenant-scoped host inventory. Host enrollment and host administration tools are planned work and are not available yet.

The repository retains the original Python server while the Go runtime and independent connector packages are developed. The current Python package documentation describes that legacy implementation; use the Go instructions below to run the new runtime.

## Build and run

The Go command requires Linux and the Go version listed in [`go.mod`](go.mod). Build the MCP server with:

```sh
go build -o ./build/ubuntu-fleet-manager ./cmd/ubuntu-fleet-manager
```

The default `stdio` transport is for a local MCP client. Configure the client to launch the built binary directly. For Codex, add a server entry to `~/.codex/config.toml`:

```toml
[mcp_servers.ubuntu_fleet_manager]
command = "/absolute/path/to/ubuntu-fleet-manager/build/ubuntu-fleet-manager"
args = []
startup_timeout_sec = 30
tool_timeout_sec = 30
```

Restart Codex and use `/mcp` to check the connection. The server writes protocol messages to standard output; diagnostics go to standard error.

## Self-hosted control plane

The Streamable HTTP service uses PostgreSQL and a provider-neutral OIDC issuer. It creates one private tenant for each `(issuer, subject)` identity and scopes `list_hosts` to that tenant. The service verifies access tokens; the identity provider performs interactive sign-in and issues tokens.

For a local deployment, copy `.env.example` to `.env`, set a long URL-safe `POSTGRES_PASSWORD`, and configure `OIDC_ISSUER_URL` and `OIDC_AUDIENCE`. Start the stack with:

```sh
docker compose up --build --detach
docker compose ps
```

The service binds to `127.0.0.1:8080`. Put a TLS reverse proxy in front of it for remote access and set `PUBLIC_URL` to the external HTTPS base URL before starting the stack. See [Deploy the self-hosted control plane](docs/how-to/deploy-control-plane.md) and [Control plane configuration](docs/reference/control-plane-configuration.md) for the required settings and readiness endpoint.

## Available tools

- `get_system_info` reads OS release, hostname, kernel, architecture, memory, and root filesystem capacity from the host running the Go MCP server. It accepts no arguments and returns typed structured content. See [Get system information](docs/reference/tools/get-system-info.md).
- `list_hosts` is available over authenticated Streamable HTTP. It returns paginated inventory for the caller's personal tenant. See [List managed hosts](docs/reference/tools/list-hosts.md).

Both tools are read-only. The service does not execute commands or return credentials.

## Development

Run the stdio contract tests and static checks with the pinned toolchain:

```sh
GOTOOLCHAIN=go1.27.3 go test ./...
GOTOOLCHAIN=go1.27.3 go vet ./...
GOTOOLCHAIN=go1.27.3 go build ./...
```

The control-plane integration test uses a local PostgreSQL database. Set `UFM_TEST_DATABASE_URL` to a disposable test database URL to run it; without that variable, the Go test suite skips only the PostgreSQL integration test. CI runs it against PostgreSQL 18 and a local test OIDC issuer. The official Go MCP SDK is pinned in [`go.mod`](go.mod).

## Project documentation

- [`GLOSSARY.md`](GLOSSARY.md) defines the domain terms used in the project.
- [`docs/adr/`](docs/adr/) records accepted architecture decisions.
- [`AGENTS.md`](AGENTS.md) and [`docs/agents/`](docs/agents/) describe repository and issue-tracker conventions.
- [Ubuntu Server documentation](https://documentation.ubuntu.com/server/) is the source for Ubuntu administration guidance. Feature docs use its Tutorial, How-to, Reference, and Explanation conventions.
- [Project specification and implementation tickets](https://github.com/averyfreeman/ubuntu-fleet-manager/issues) track the v0.1.0 work.

This project is not affiliated with Canonical. Ubuntu is a registered trademark of Canonical Ltd.
