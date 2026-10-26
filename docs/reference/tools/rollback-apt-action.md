# Roll back an APT action

`rollback_apt_action` attempts to restore package installation state and versions captured by `apt_install`, `apt_remove`, or `apt_upgrade`. It is marked mutating, destructive, idempotent, and open-world. It does not run a general package-manager command supplied by the caller.

## Availability and approval

Over authenticated Streamable HTTP, the control plane must set `ALLOW_APT_WRITES=true`; the enrolled agent and root-owned helper policies must allow `rollback`. The MCP client must request per-call human confirmation.

Over local stdio, the tool is omitted by default. Both `--local-apt-policy-file` and `--local-apt-key-file` must be supplied; the tool is registered only when `rollback` is in the local policy's `allowed_operations`. The root-owned policy must also allow rollback. MCP annotations are advisory; the server cannot prove that a client displayed a prompt. See [Configure APT package policy](../../how-to/configure-apt-policy.md).

## Request

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `host_id` | string | HTTP only | Active target host identifier. Omit for stdio. |
| `action_id` | UUID | Yes | Identifier returned by a prior install, remove, or upgrade result. The record is valid for seven days. |

The record belongs to the same authenticated tenant and host. Cross-tenant, cross-host, expired, or non-reversible records are rejected.

## Result

| Field | Type | Description |
| --- | --- | --- |
| `action_id` | UUID | Reversed action identifier. |
| `outcome` | string | `succeeded` when every captured state was restored, otherwise `partial`. |
| `restored_packages` | integer | Count of captured package states restored exactly. |
| `exact` | boolean | True only when all captured states now match the pre-action state. |
| `already_restored` | boolean | True when a prior call completed exact rollback. |
| `packages` | array | Per-package `name`, `restored`, `exact`, and optional `reason`. |
| `reason` | string | First safe per-package explanation for a partial result. |

HTTP results also include `host_id`, `hostname`, and `requested_at`; local stdio omits those fields.

## Rollback limits

Before changing a package, the agent compares the current installed state with the state captured after the original operation. If a package changed later, it is preserved and reported as partial. The helper only permits package names in its root-owned allowlist. A dependency outside that list is left untouched. An older version may no longer be available from configured repositories, or dependency constraints may prevent reinstalling it. Rollback is therefore compensating and best-effort, not a filesystem or package-database snapshot restore.

An exact rollback is idempotent: repeating the call returns `already_restored=true`. A partial rollback remains available for retry until the seven-day expiry. The encrypted record is then deleted from the active application store. Operator backups may retain encrypted database pages longer.

## Example

```json
{
  "host_id": "c0c326bc-cf08-4e15-98dc-cf8b5fa8d66d",
  "action_id": "6a1b4c1e-51c0-4bdd-a993-a72b8d76a624"
}
```

Omit `host_id` for local stdio.
