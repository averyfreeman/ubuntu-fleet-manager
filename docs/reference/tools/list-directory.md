# List a directory on a managed host

`list_directory` lists a directory on one enrolled host in the authenticated operator's personal tenant. It is available over authenticated Streamable HTTP and is marked read-only, idempotent, and closed-world.

## Request

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `host_id` | string | Yes | Identifier returned by host enrollment and `list_hosts`. |
| `path` | string | Yes | Absolute directory path inside the host agent's configured read boundaries. |

The control plane resolves `host_id` within the caller's personal tenant. The host agent defaults its allowed read boundary to its own user's home directory. A host administrator may add existing absolute directories with repeated `--allowed-path DIR` flags when enrolling the agent. The path boundary is stored in the host agent's local configuration.

Paths containing a `..` component and paths outside configured boundaries are rejected. An in-boundary symlink is listed as a symlink without following its target. Opening a directory through a symlink that resolves outside the allowed boundary fails.

## Result

The result contains `host_id`, enrollment-time `hostname`, `requested_at`, and a `listing` object:

| Field | Type | Description |
| --- | --- | --- |
| `path` | string | The requested absolute directory path. |
| `entries` | array | Up to 100 entries, sorted by name. Each entry has `name`, `path`, `type`, `size_bytes`, `mode`, `modified_at`, and `is_symlink`. |
| `truncated` | boolean | True when the directory has more than 100 entries. |

Entry `type` is one of `file`, `directory`, `symlink`, or `other`. Symlink entries expose metadata only; the tool does not read their targets.

## Example

```json
{
  "host_id": "c0c326bc-cf08-4e15-98dc-cf8b5fa8d66d",
  "path": "/home/ubuntu-fleet-agent"
}
```

The result wraps the listing with the target host and request time:

```json
{
  "host_id": "c0c326bc-cf08-4e15-98dc-cf8b5fa8d66d",
  "hostname": "web-01",
  "requested_at": "2026-10-26T12:00:00Z",
  "listing": {
    "path": "/home/ubuntu-fleet-agent",
    "entries": [],
    "truncated": false
  }
}
```

## Limits and errors

- The path is limited to 4096 UTF-8 bytes and must be absolute.
- At most 100 entries are returned. Check `truncated` before treating the result as complete.
- The tool returns an MCP error for a path outside the configured boundary, traversal, an unavailable directory, a permission failure, or a non-directory path.
- The host agent must poll and return the result within the 90-second job deadline.

See [Host agent API](../host-agent-api.md) for the leased job envelope, [Host agent configuration](../host-agent-configuration.md) for the local boundary settings, and [Enroll and run a host agent](../../how-to/enroll-host-agent.md) for service setup.
