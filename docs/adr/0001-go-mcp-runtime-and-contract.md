# Go MCP runtime and shared contract

Status: Accepted

## Context

The existing Python server combines MCP transport, host operations, and security policy in one process. The new project needs a Go runtime that can serve local stdio clients and remote self-hosted deployments while Python and Node connector packages remain independently maintainable.

## Decision

Make Go the sole implementation of MCP tools and host-operation policy. Use the official Model Context Protocol Go SDK, pinning v1.8.0 for the initial implementation and Go 1.27.3 as the current toolchain baseline. Expose the same typed MCP contract over stdio and Streamable HTTP; keep transport code separate from domain operations. Python and Node packages are clients that launch the Go binary over stdio or connect to its MCP HTTP endpoint. They do not duplicate host-operation logic. Do not add a custom REST API.

Keep `get_system_info` as the no-argument local-runtime snapshot on both transports. Expose remote host snapshots as the separate authenticated HTTP tool `get_host_system_info(host_id)`. The target is explicit, and the existing local tool schema remains stable.

The selected SDK supports the 2026-07-28 MCP revision and negotiates supported older revisions; interoperability tests must cover the client revisions used by supported connectors. See the [official Go SDK releases](https://github.com/modelcontextprotocol/go-sdk/releases), [SDK protocol compatibility](https://github.com/modelcontextprotocol/go-sdk), and [Go release history](https://go.dev/doc/devel/release).

## Alternatives considered

- Keep Python as the runtime and add Go subprocesses for selected operations: rejected because it preserves two policy and execution layers.
- Reimplement the server separately in Go, Python, and Node: rejected because tool behavior and authorization could drift.
- Add a private REST API between connectors and Go: rejected because MCP stdio and Streamable HTTP already provide the agreed shared interface.

## Consequences

Go unit and contract tests are authoritative for tool behavior. Python and Node require parity tests against the same schemas and results. Go SDK upgrades must include protocol interoperability checks. A breaking tool-schema change is allowed before v0.1.0; after release, published names and schemas are backward compatible.
