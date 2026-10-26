# Python and Node connector clients

Status: Accepted

## Context

The Go runtime owns the MCP contract, host operations, and authorization policy. Python and Node applications need independently maintained ways to launch that runtime locally or connect to its authenticated Streamable HTTP endpoint.

## Decision

Maintain separate connector packages under `connectors/python` and `connectors/node`, using the official MCP client SDKs. Each package supports stdio process launch and Streamable HTTP. HTTP callers supply an already issued bearer token; the connector does not implement interactive identity-provider flows.

Return the official SDK client and MCP result types without renaming tools, changing schemas or annotations, converting structured results, or replacing SDK authentication, policy, and transport errors. Host-operation policy and rollback remain in Go. The Python package uses an async context manager; the Node package returns a connection with an explicit `close()` lifecycle.

Use a Go-generated shared contract fixture and a test-only Streamable HTTP server to check names, schemas, annotations, representative structured results, bearer authentication, and MCP policy errors from Python and Node. The test fixture is not part of the production image.

## Alternatives considered

- Port host operations into both client packages: rejected because policy and results would drift across runtimes.
- Add a custom REST bridge: rejected because the existing Go MCP transports are the canonical interface.
- Translate protocol errors into connector-specific application errors: rejected because the wrappers would obscure the official SDK behavior.

## Consequences

Connector SDK upgrades require both cross-language contract suites. A change to the Go tool schema must update the Go-generated fixture and pass Python and Node parity tests. Client applications remain responsible for token acquisition and for prompting users based on tool annotations.
