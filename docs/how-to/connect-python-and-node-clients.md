# Connect Python and Node clients

The Python and Node packages are thin clients for the Go MCP runtime. Use stdio when the client should launch a local binary. Use Streamable HTTP for a deployed control plane. Both packages return the official MCP SDK client so discovery, annotations, results, and errors stay on the Go server's MCP contract.

These packages do not implement host operations or obtain user tokens. For HTTP, supply an access token issued by the configured identity provider. The control plane verifies the token; interactive sign-in and token renewal belong to the MCP host or application.

## Install from a checkout

Python package:

```sh
uv venv
uv pip install --python .venv/bin/python ./connectors/python
```

Node package:

```sh
npm install /absolute/path/to/ubuntu-fleet-manager/connectors/node
```

The Go runtime must be built or installed separately. See [Try the local MCP server](../tutorials/try-local-mcp-server.md) for a local build and Codex connection.

## Connect over stdio

Python clients use an asynchronous context manager. The MCP SDK manages the child process and closes it when the context exits:

```python
import asyncio
from ubuntu_fleet_manager_client import connect_stdio


async def main():
    async with connect_stdio("/usr/local/bin/ubuntu-fleet-manager") as client:
        tools = await client.list_tools()
        print([tool.name for tool in tools.tools])
        result = await client.call_tool("get_system_info", {})
        print(result.model_dump(by_alias=True).get("structuredContent"))


asyncio.run(main())
```

Pass process arguments using `args=[...]`. Pass additional environment values explicitly using `env={...}`; the Python SDK supplies a minimal child environment.

Node clients return an object with an SDK client and a `close()` method:

```js
import { connectStdio } from '@ubuntu-fleet-manager/client';

const connection = await connectStdio({
  command: '/usr/local/bin/ubuntu-fleet-manager',
});

try {
  const { tools } = await connection.client.listTools();
  console.log(tools.map((tool) => tool.name));
  const result = await connection.client.callTool({
    name: 'get_system_info',
    arguments: {},
  });
  console.log(result.structuredContent);
} finally {
  await connection.close();
}
```

Supply child arguments as `args` and additional environment entries as `env`. The Node MCP SDK uses a constrained inherited environment and launches the command without a shell.

## Connect over authenticated Streamable HTTP

Deploy the control plane first and configure a client with the public `/mcp` endpoint. The examples read a previously issued bearer token from the environment so it is not embedded in source code:

```sh
export UFM_ACCESS_TOKEN='token-issued-for-the-configured-audience'
```

Python:

```python
import asyncio
import os
from ubuntu_fleet_manager_client import connect_http


async def main():
    async with connect_http(
        "https://fleet.example.com/mcp",
        token=os.environ["UFM_ACCESS_TOKEN"],
    ) as client:
        tools = await client.list_tools()
        print([tool.name for tool in tools.tools])


asyncio.run(main())
```

Node:

```js
import { connectHttp } from '@ubuntu-fleet-manager/client';

const connection = await connectHttp({
  url: 'https://fleet.example.com/mcp',
  token: process.env.UFM_ACCESS_TOKEN,
});

try {
  const { tools } = await connection.client.listTools();
  console.log(tools.map((tool) => tool.name));
} finally {
  await connection.close();
}
```

The client surfaces HTTP authentication and transport failures from its SDK. MCP tool policy failures are returned in the MCP call result, including its `isError` field and content. Each SDK uses its own language-specific exception types; the connector packages do not translate or suppress those errors.

## Confirmation and policy

The Go control plane applies operator, tenant, host, and per-operation policy. Tool annotations describe read-only, destructive, idempotent, and open-world behavior. Configure the MCP host to ask for human approval for destructive calls. An annotation is a request to the client; the server cannot prove that a prompt was shown.

See [Control plane configuration](../reference/control-plane-configuration.md), [Configure APT package policy](configure-apt-policy.md), and [Configure constrained command execution](configure-command-policy.md) before enabling mutation tools.
