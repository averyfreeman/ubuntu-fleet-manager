# Python and Node connector API

The connector packages are clients for the Go MCP server. Their functions establish a protocol connection and expose the official MCP SDK client. They do not define a separate tool contract or host-operation policy.

## Python

Package: `ubuntu-fleet-manager-client` from `connectors/python`.

| Function | Options | Result |
| --- | --- | --- |
| `connect_stdio(command, *, args=(), env=None)` | `command` is the Go runtime path; `args` is the argument sequence; `env` adds explicit child-process environment values to the Python SDK's minimal environment. | An asynchronous context manager that yields an official `mcp.Client`. Leaving the context closes the process and session. |
| `connect_http(url, *, token=None)` | `url` is the Streamable HTTP `/mcp` endpoint; `token` is an optional already-issued access token sent as a bearer credential. | An asynchronous context manager that yields an official `mcp.Client`. Leaving the context closes the MCP session and HTTP client. |

The client exposes SDK methods such as `list_tools()` and `call_tool(name, arguments)`. See [Connect Python and Node clients](../how-to/connect-python-and-node-clients.md) for examples.

## Node

Package: `@ubuntu-fleet-manager/client` from `connectors/node`. Node.js 20 or later is required by the MCP SDK.

| Function | Options | Result |
| --- | --- | --- |
| `connectStdio({command, args=[], env, cwd, stderr})` | `command` is the Go runtime path; `args` is the process argument array; `env` adds child-process environment values; `cwd` and `stderr` are passed to the MCP stdio transport. | A promise resolving to `{client, close()}`. `client` is the official MCP SDK `Client`. |
| `connectHttp({url, token})` | `url` is the Streamable HTTP `/mcp` endpoint; `token` is an optional already-issued access token sent as a bearer credential. | A promise resolving to `{client, close()}`. `close()` terminates the remote MCP session and closes the SDK client. |

Call SDK methods such as `client.listTools()` and `client.callTool({name, arguments})`. Always await `close()` in a `finally` block. See [Connect Python and Node clients](../how-to/connect-python-and-node-clients.md) for examples.

## Contract and errors

Both packages forward tool definitions, including input and output schemas and annotations, and preserve MCP call results including `isError` and structured content. Host policy failures remain MCP tool results. Authentication and transport failures remain errors from the corresponding official SDK; Python and Node use their native exception types. The wrapper does not obtain or refresh tokens.

The Python transport follows the [official Python MCP client transport documentation](https://github.com/modelcontextprotocol/python-sdk/blob/main/docs/client/transports.md). The Node transport follows the [official TypeScript MCP SDK client documentation](https://github.com/modelcontextprotocol/typescript-sdk/blob/main/docs/clients/connect.md) and [machine authentication guidance](https://github.com/modelcontextprotocol/typescript-sdk/blob/main/docs/clients/machine-auth.md).
