# Ubuntu Fleet Manager

Ubuntu Fleet Manager is an early-stage, self-hosted MCP service for administering Ubuntu hosts. The Go runtime exposes local system information over MCP stdio and an authenticated Streamable HTTP control plane with a tenant-scoped host inventory, one-time host enrollment, outbound agent liveness polling, and typed host operations.

The repository retains the original Python server as a legacy implementation alongside the Go runtime and independent Python and Node MCP connector packages. The root Python package documentation describes the legacy server; use the Go instructions below to run the fleet manager.

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

The service binds to `127.0.0.1:8080`. Put a TLS reverse proxy in front of it for remote access and set `PUBLIC_URL` to the external HTTPS base URL before starting the stack. See [Deploy the self-hosted control plane](docs/how-to/deploy-control-plane.md) and [Control plane configuration](docs/reference/control-plane-configuration.md) for the required settings, agent endpoints, and readiness endpoint.

The control plane also requires a private 32-byte application encryption key at `secrets/file-action-key`; see the deployment guide before running Compose. Reversible file tools stay disabled unless `ALLOW_FILE_WRITES=true` and each host has explicit `writable_paths`. APT tools stay disabled unless `ALLOW_APT_WRITES=true` and each host has agent and root-owned package policies plus the dedicated sudo helper rule. Generic command execution stays disabled unless `ALLOW_COMMAND_EXECUTION=true` and each host has an exact executable and argv policy.

## Available tools

- `get_system_info` reads OS release, hostname, kernel, architecture, memory, and root filesystem capacity from the host running the Go MCP server. It accepts no arguments and returns typed structured content. See [Get system information](docs/reference/tools/get-system-info.md).
- `get_host_system_info` requests a fresh snapshot from one enrolled host in the authenticated operator's personal tenant. It waits up to 90 seconds for the host agent. See [Get system information from a managed host](docs/reference/tools/get-host-system-info.md).
- `list_directory` lists at most 100 entries on an enrolled host inside the agent's configured read boundaries. See [List a directory on a managed host](docs/reference/tools/list-directory.md).
- `read_file` reads at most 256 KiB of UTF-8 text from an enrolled host inside the agent's configured read boundaries. See [Read a file on a managed host](docs/reference/tools/read-file.md).
- `search_packages` searches configured APT indexes on an enrolled host without changing package state. See [Search APT packages on a managed host](docs/reference/tools/search-packages.md).
- `apt_update` refreshes indexes from existing configured APT repositories. See [Refresh APT package indexes](docs/reference/tools/apt-update.md).
- `apt_install`, `apt_remove`, and `apt_upgrade` operate on allowlisted package names with captured package state for bounded rollback. See [Install APT packages](docs/reference/tools/apt-install.md), [Remove APT packages](docs/reference/tools/apt-remove.md), and [Upgrade APT packages](docs/reference/tools/apt-upgrade.md).
- `rollback_apt_action` attempts to restore captured package versions and installation state for seven days. Dependency and repository changes can make the result partial. See [Roll back an APT action](docs/reference/tools/rollback-apt-action.md).
- `execute_command` runs only an exact host-allowlisted executable and argument vector, directly without a shell. It is disabled by default, has no rollback, and requires a client that requests per-call human confirmation. See [Execute an allowlisted command](docs/reference/tools/execute-command.md).
- `write_file` writes at most 256 KiB of UTF-8 text inside a separately configured host writable boundary and records encrypted reversal data for seven days. See [Write a file on a managed host](docs/reference/tools/write-file.md).
- `rollback_file` restores the prior existence, contents, and mode captured by `write_file`, while preserving later manual edits. See [Roll back a managed file write](docs/reference/tools/rollback-file.md).
- `list_hosts` is available over authenticated Streamable HTTP. It returns paginated inventory for the caller's personal tenant. See [List managed hosts](docs/reference/tools/list-hosts.md).
- `create_pairing_code` creates a one-time code that expires after ten minutes and belongs to the authenticated operator's personal tenant. The code is a secret and appears only in the tool result. See [Create a host pairing code](docs/reference/tools/create-pairing-code.md).
- `remove_host` removes a host from active inventory and immediately revokes its credential. See [Remove a managed host](docs/reference/tools/remove-host.md).

`get_system_info`, `get_host_system_info`, `list_hosts`, `list_directory`, `read_file`, and `search_packages` are read-only. `create_pairing_code` creates enrollment state, `remove_host` revokes access, and the optional file and package tools perform typed operations under server-side and host policy. The optional command tool does not invoke a shell and runs only exact executable and argv pairs allowed by the host policy. The credential is returned only to the agent during successful enrollment and is not included in MCP results.

## Run a host agent

Build or install the Go binary on the Ubuntu host, then enroll and run it as an unprivileged account. The enrollment guide shows how to pass the pairing code through standard input, store the credential with mode `0600`, and configure a systemd service. See [Enroll and run a host agent](docs/how-to/enroll-host-agent.md). To enable APT operations, follow [Configure APT package policy](docs/how-to/configure-apt-policy.md). To enable constrained commands, follow [Configure constrained command execution](docs/how-to/configure-command-policy.md).

## Python and Node clients

The independent packages in [`connectors/python`](connectors/python/) and [`connectors/node`](connectors/node/) use the official MCP client SDKs to launch the Go runtime over stdio or connect to its authenticated Streamable HTTP endpoint. They return the SDK's tool definitions, results, and errors without reimplementing host operations. See [Connect Python and Node clients](docs/how-to/connect-python-and-node-clients.md).

## Development

Run the stdio contract tests and static checks with the pinned toolchain:

```sh
GOTOOLCHAIN=go1.27.3 go test ./...
GOTOOLCHAIN=go1.27.3 go vet ./...
GOTOOLCHAIN=go1.27.3 go build ./...
```

The control-plane integration test uses a local PostgreSQL database. Set `UFM_TEST_DATABASE_URL` to a disposable test database URL to run it; without that variable, the Go test suite skips only the PostgreSQL integration test. CI runs it against PostgreSQL 18 and a local test OIDC issuer. The official Go MCP SDK is pinned in [`go.mod`](go.mod).

## Project documentation

- [Documentation index](docs/index.md) organizes Tutorials, How-to, Reference, and Explanation pages.
- [`GLOSSARY.md`](GLOSSARY.md) defines the domain terms used in the project.
- [`SKILL.md`](SKILL.md) describes safe local development, deployment, MCP connections, and test commands for coding agents.
- [`docs/adr/`](docs/adr/) records accepted architecture decisions.
- [Reference index](docs/reference/index.md) links to tool schemas, limits, host-agent endpoints, and configuration.
- [`AGENTS.md`](AGENTS.md) and [`docs/agents/`](docs/agents/) describe repository and issue-tracker conventions.
- [Ubuntu Server documentation](https://documentation.ubuntu.com/server/) is the source for Ubuntu administration guidance. Feature docs use its Tutorial, How-to, Reference, and Explanation conventions.
- [Project specification and implementation tickets](https://github.com/averyfreeman/ubuntu-fleet-manager/issues) track the v0.1.0 work.

This project is not affiliated with Canonical. Ubuntu is a registered trademark of Canonical Ltd.
