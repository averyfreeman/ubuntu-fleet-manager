import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';

const CLIENT_VERSION = '0.1.0';

function newClient() {
  return new Client({ name: 'ubuntu-fleet-manager-node-client', version: CLIENT_VERSION });
}

async function connect(client, transport, terminateSession = false) {
  try {
    await client.connect(transport);
  } catch (error) {
    try {
      await client.close();
    } catch {
      // Preserve the connection error; cleanup is best-effort after a failed handshake.
    }
    throw error;
  }

  let closed = false;
  return {
    client,
    async close() {
      if (closed) return;
      closed = true;
      if (terminateSession) {
        try {
          await transport.terminateSession();
        } finally {
          await client.close();
        }
      } else {
        await client.close();
      }
    },
  };
}

/** Spawn the Go runtime over stdio. SDK tool results and errors are returned unchanged. */
export async function connectStdio({ command, args = [], env, cwd, stderr } = {}) {
  const client = newClient();
  const transport = new StdioClientTransport({ command, args, env, cwd, stderr });
  return connect(client, transport);
}

/** Connect to a Streamable HTTP endpoint, optionally sending a bearer token. */
export async function connectHttp({ url, token } = {}) {
  const client = newClient();
  const authProvider = token === undefined ? undefined : { token: async () => token };
  const transport = new StreamableHTTPClientTransport(
    url instanceof URL ? url : new URL(url),
    authProvider === undefined ? undefined : { authProvider },
  );
  return connect(client, transport, true);
}
