# Write a file on a managed host

`write_file` replaces or creates one UTF-8 text file on an enrolled host. It captures the prior file existence, bytes, and permission bits so the operator can request a rollback for seven days.

## Availability and approval

The control plane registers this tool only when `ALLOW_FILE_WRITES=true`. The host agent must also have the target beneath one of its separately configured `writable_paths`; an empty list denies every write. The agent runs with its existing unprivileged account and systemd sandbox.

The tool is marked as mutating and destructive. Use an MCP client that presents a per-call human confirmation for destructive tools. MCP annotations are advisory metadata, so a server cannot prove that a particular client displayed or received a human confirmation.

## Input

| Field | Type | Required | Constraints |
| --- | --- | --- | --- |
| `host_id` | string | Yes | Active host identifier in the authenticated operator's personal tenant. |
| `path` | string | Yes | Absolute regular-file path inside the host agent's configured writable boundaries. Parent directories must already exist. |
| `content` | string | Yes | UTF-8 text, at most 256 KiB. Empty text is allowed. |

The operation rejects `..` path components, symlink targets, directories, non-regular files, paths outside the configured boundary, unreadable prior files, and prior files larger than 256 KiB. Replacing a file preserves its permission bits. A new file is created with mode `0600`. The update uses a temporary file in the target directory and an atomic rename; it does not create parent directories.

## Result

| Field | Type | Description |
| --- | --- | --- |
| `host_id` | string | Target host identifier. |
| `hostname` | string | Hostname reported during enrollment. |
| `requested_at` | timestamp | UTC time when the control plane queued the request. |
| `path` | string | Canonical target path. |
| `action_id` | UUID | Identifier required by `rollback_file`; reversal data expires seven days after creation. |
| `created` | boolean | Whether the write created a previously absent file. |
| `bytes_written` | integer | UTF-8 byte count written. |
| `mode` | integer | Permission bits after the write; existing mode is preserved and new files use `0600`. |
| `expires_at` | timestamp | UTC expiry time for the encrypted reversal payload. |

The result does not include captured prior bytes. The control plane encrypts the job input, job result, and reversal payload with AES-256-GCM before PostgreSQL storage. It clears the job payload after the encrypted reversal record is committed. Keep the operator-managed key available for the full retention window. See [Control plane configuration](../control-plane-configuration.md) and [Host agent configuration](../host-agent-configuration.md).

Rollback restores captured existence, bytes, and permission bits. Ownership, ACLs, and extended attributes are not captured. The write fails if the agent cannot read the prior file or cannot safely replace it; the control plane does not report an action ID until its encrypted reversal record is stored.

## Example

```json
{
  "host_id": "c0c326bc-cf08-4e15-98dc-cf8b5fa8d66d",
  "path": "/srv/application-config/service.conf",
  "content": "mode=safe\n"
}
```

See [Roll back a managed file write](rollback-file.md) for reversal behavior.
