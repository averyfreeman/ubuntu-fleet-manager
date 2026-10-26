# Ubuntu Fleet Manager Node.js client

Thin Node.js client helpers for the Go MCP runtime, using the official MCP client SDK. The package does not implement host operations, policy checks, authentication flows, or rollback behavior.

Requires Node.js 20 or later.

## Install from a checkout

```sh
npm install /absolute/path/to/ubuntu-fleet-manager/connectors/node
```

Build or install the Go runtime separately. For a local process, pass the executable path to `connectStdio`:

```js
import { connectStdio } from '@ubuntu-fleet-manager/client';

const connection = await connectStdio({
  command: '/usr/local/bin/ubuntu-fleet-manager',
  args: [],
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

For an authenticated control plane, pass its `/mcp` URL and an access token issued for the configured audience:

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

`connectStdio` accepts `args`, `env`, `cwd`, and `stderr` options supported by the MCP SDK. Both helpers return the SDK client unchanged. MCP schemas, annotations, structured results, and policy errors come from the Go runtime; HTTP authentication and transport errors use the SDK's native behavior.
