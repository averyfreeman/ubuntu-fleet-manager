# Read a file on a managed host

`read_file` reads a UTF-8 text file on one enrolled host in the authenticated operator's personal tenant. It is available over authenticated Streamable HTTP and is marked read-only, idempotent, and closed-world. It never executes the file contents.

## Request

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `host_id` | string | Yes | Identifier returned by host enrollment and `list_hosts`. |
| `path` | string | Yes | Absolute path to a regular file inside the host agent's configured read boundaries. |

The host agent defaults its allowed read boundary to its own user's home directory. A host administrator may add existing absolute directories with repeated `--allowed-path DIR` flags when enrolling the agent. Paths containing a `..` component or resolving outside the configured boundary are rejected. Symlinks that escape the boundary are rejected.

## Result

The result contains `host_id`, enrollment-time `hostname`, `requested_at`, and a `file` object with `path`, `content`, and `size_bytes`. The reported size is the UTF-8 content size in bytes.

## Example

```json
{
  "host_id": "c0c326bc-cf08-4e15-98dc-cf8b5fa8d66d",
  "path": "/srv/application-config/service.conf"
}
```

Example result:

```json
{
  "host_id": "c0c326bc-cf08-4e15-98dc-cf8b5fa8d66d",
  "hostname": "web-01",
  "requested_at": "2026-10-26T12:00:00Z",
  "file": {
    "path": "/srv/application-config/service.conf",
    "content": "mode=safe\n",
    "size_bytes": 10
  }
}
```

## Limits and errors

- The path is limited to 4096 UTF-8 bytes and must be absolute.
- Only regular UTF-8 text files are returned; the maximum content size is 256 KiB.
- The tool returns an MCP error for traversal, a path outside the configured boundary, a missing or unreadable file, a non-regular file, binary or invalid UTF-8 content, or content larger than 256 KiB.
- The host agent must poll and return the result within the 90-second job deadline.

See [Host agent API](../host-agent-api.md) for the leased job envelope, [Host agent configuration](../host-agent-configuration.md) for the local boundary settings, and [Enroll and run a host agent](../../how-to/enroll-host-agent.md) for service setup.
