import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import os from 'node:os';
import path from 'node:path';
import { createInterface } from 'node:readline';
import test from 'node:test';

import { connectHttp, connectStdio } from '../index.js';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const contractPath = path.join(repositoryRoot, 'schemas', 'mcp-local-stdio-contract.json');

test('Node connector surfaces stdio process startup failures', async () => {
  await assert.rejects(
    connectStdio({ command: '/definitely/not/an/ubuntu-fleet-manager-binary' }),
    (error) => error.code === 'ENOENT',
  );
});

test('Node connector preserves the Go MCP discovery and structured result', async () => {
  const command = process.env.UFM_SERVER_BINARY;
  assert.ok(command, 'set UFM_SERVER_BINARY to the built Go runtime');

  const contract = JSON.parse(await readFile(contractPath, 'utf8'));
  const connection = await connectStdio({ command });
  try {
    const listed = await connection.client.listTools();
    assert.deepEqual(listed.tools, contract.tools);

    const result = await connection.client.callTool({
      name: 'get_system_info',
      arguments: {},
    });
    assert.notEqual(result.isError, true);
    assert.ok(result.structuredContent);
    assert.deepEqual(Object.keys(result.structuredContent).sort(), contract.resultFields);
    assert.ok(result.structuredContent.hostname);
    assert.ok(result.structuredContent.architecture);
    assert.ok(result.structuredContent.memory.total_bytes > 0);
    assert.ok(result.structuredContent.root_filesystem.total_bytes > 0);
  } finally {
    await connection.close();
  }
});

test('Node connector preserves host policy errors and confirmation annotations', async () => {
  const command = process.env.UFM_SERVER_BINARY;
  assert.ok(command, 'set UFM_SERVER_BINARY to the built Go runtime');

  const directory = await mkdtemp(path.join(os.tmpdir(), 'ufm-client-contract-'));
  const home = path.join(directory, 'home');
  const policyPath = path.join(directory, 'apt-policy.json');
  const keyPath = path.join(directory, 'action-key');
  await mkdir(home, { mode: 0o700 });
  await writeFile(policyPath, JSON.stringify({
    enabled: true,
    allowed_operations: ['install', 'rollback'],
    allowed_packages: ['curl'],
  }), { mode: 0o600 });
  await writeFile(keyPath, '0123456789abcdef0123456789abcdef', { mode: 0o600 });

  try {
    const connection = await connectStdio({
      command,
      args: ['--local-apt-policy-file', policyPath, '--local-apt-key-file', keyPath],
      env: { HOME: home },
    });
    try {
      const listed = await connection.client.listTools();
      const install = listed.tools.find((tool) => tool.name === 'apt_install');
      assert.ok(install);
      assert.equal(install.annotations.destructiveHint, true);
      assert.equal(install.annotations.readOnlyHint, false);
      assert.equal(install.annotations.idempotentHint, false);

      const result = await connection.client.callTool({
        name: 'apt_install',
        arguments: { packages: ['wget'] },
      });
      assert.equal(result.isError, true);
      assert.ok(result.content.length > 0);
    } finally {
      await connection.close();
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('Node connector sends bearer auth and surfaces an HTTP authentication failure', async () => {
  let authorization;
  const server = createServer((request, response) => {
    authorization = request.headers.authorization;
    response.writeHead(401, { 'content-length': '0' });
    response.end();
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  try {
    await assert.rejects(
      connectHttp({ url: `http://127.0.0.1:${address.port}/mcp`, token: 'test-token' }),
    );
    assert.equal(authorization, 'Bearer test-token');
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});

test('Node connector discovers and calls the authenticated Go Streamable HTTP runtime', async () => {
  const command = process.env.UFM_HTTP_SERVER_BINARY;
  assert.ok(command, 'set UFM_HTTP_SERVER_BINARY to the MCP HTTP contract fixture');

  const contract = JSON.parse(await readFile(contractPath, 'utf8'));
  const child = spawn(command, { stdio: ['ignore', 'pipe', 'pipe'] });
  const lines = createInterface({ input: child.stdout });
  try {
    const line = await Promise.race([
      once(lines, 'line').then(([value]) => value),
      once(child, 'exit').then(([code]) => { throw new Error(`HTTP contract fixture exited with ${code}`); }),
    ]);
    const connection = await connectHttp({ url: line.trim(), token: 'fixture-token' });
    try {
      const listed = await connection.client.listTools();
      assert.deepEqual(listed.tools, contract.tools);
      const result = await connection.client.callTool({ name: 'get_system_info', arguments: {} });
      assert.notEqual(result.isError, true);
      assert.deepEqual(Object.keys(result.structuredContent).sort(), contract.resultFields);
    } finally {
      await connection.close();
    }
  } finally {
    lines.close();
    if (child.exitCode === null) {
      child.kill('SIGTERM');
      await once(child, 'exit');
    }
  }
});
