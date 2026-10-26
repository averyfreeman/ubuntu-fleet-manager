# Ubuntu Fleet Manager Python client

This package connects to the Go MCP runtime with the official Python MCP SDK. It exposes the SDK client without changing tool names, schemas, annotations, results, or protocol errors.

Use `connect_stdio()` for a local process or `connect_http()` for a Streamable HTTP endpoint. Host operations and their policy remain in the Go runtime.
