# Roll back a managed file write

`rollback_file` restores the existence, bytes, and permission bits captured by a successful `write_file` operation. Its `action_id` is valid for seven days.

## Availability and approval

The control plane registers this tool only when `ALLOW_FILE_WRITES=true`; the target host must still be active and the restored path must remain within its configured `writable_paths`. The tool is marked mutating and destructive. Use an MCP client that presents per-call human confirmation for destructive tools. MCP annotations are advisory; the server cannot verify that a client displayed a confirmation prompt.

## Input

| Field | Type | Required | Constraints |
| --- | --- | --- | --- |
| `host_id` | string | Yes | Active host identifier that received the original write. |
| `action_id` | UUID | Yes | `action_id` returned by `write_file`; it must belong to the authenticated operator's tenant and the specified host. |

## Example

```json
{
  "host_id": "c0c326bc-cf08-4e15-98dc-cf8b5fa8d66d",
  "action_id": "779df315-35c9-4262-935d-0d580be27a65"
}
```

## Behavior

The control plane decrypts the reversal record and queues a typed `restore_file` job for that host. The agent compares the current file's existence, bytes, and permission bits to the state written by the managed action. If they match, it restores the captured prior state. If the captured prior state is already present, it reports success without changing the file again. If the file has changed since the managed write, the agent refuses to overwrite the later contents and reports why exact restoration is unavailable.

If the original write created a new file, rollback removes it, but only if its current state still matches that write. A repeated rollback after success returns `already_restored=true`. The record remains encrypted until its seven-day expiry. ACLs, ownership, and extended attributes are outside the captured state.

## Result

| Field | Type | Description |
| --- | --- | --- |
| `host_id` | string | Target host identifier. |
| `hostname` | string | Hostname reported during enrollment. |
| `action_id` | UUID | Reversed write action. |
| `restored` | boolean | Whether the captured prior state is now present. |
| `exact` | boolean | Whether captured existence, bytes, and permission bits match. |
| `already_restored` | boolean | Whether an earlier rollback completed. |
| `reason` | string | Explanation when exact restoration could not be completed. |
| `requested_at` | timestamp | UTC time when the rollback request was queued. |

The operator key must remain available to decrypt reversal data. Expired records cannot be rolled back. See [Write a file on a managed host](write-file.md) and [Control plane configuration](../control-plane-configuration.md).
