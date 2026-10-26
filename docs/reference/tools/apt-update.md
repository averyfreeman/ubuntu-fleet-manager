# Refresh APT package indexes

`apt_update` refreshes the APT indexes from the repositories already configured on the target host. It does not install packages or change installed package state. The tool is marked mutating, destructive, idempotent, and open-world because it contacts configured repositories.

## Availability and approval

Over authenticated Streamable HTTP, the control plane registers this tool only when `ALLOW_APT_WRITES=true`. The enrolled agent policy and the root-owned APT helper policy must both allow `update`. The MCP client must request per-call human confirmation for this destructive tool.

Over local stdio, the tool is omitted by default. Start the server with both `--local-apt-policy-file` and `--local-apt-key-file`, and include `update` in the local policy's `allowed_operations`, to register it. The root-owned helper policy must also allow it.

MCP annotations are advisory. A server cannot prove that a particular client displayed a confirmation prompt. See [Configure APT package policy](../../how-to/configure-apt-policy.md) for the host sudo and policy setup.

## Request

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `host_id` | string | HTTP only | Active host identifier in the authenticated operator's personal tenant. Omit for stdio. |

The agent invokes the root-owned helper with the fixed command `apt-get -q update`. The helper validates the exact arguments and checks the root-owned policy before running APT. The repository configuration is not changed.

## Result

| Field | Type | Description |
| --- | --- | --- |
| `host_id` | string | Target identifier; omitted for stdio. |
| `hostname` | string | Enrollment-time hostname; omitted for stdio. |
| `requested_at` | timestamp | UTC time the control plane queued the job; omitted for stdio. |
| `action_id` | UUID | Encrypted audit record identifier. It cannot be passed to `rollback_apt_action` because index refresh has no inverse. |
| `operation` | string | `apt_update`. |
| `outcome` | string | `succeeded` or `failed`. |
| `changed_packages` | integer | Always zero for index refresh. |
| `rollback_available` | boolean | Always false. |
| `expires_at` | timestamp | UTC expiry time for the encrypted audit record, seven days after creation. |
| `reason` | string | Safe failure explanation when the operation did not succeed. |

The control plane encrypts the action record with the application key and clears the completed job payload after it stores the record. Index files themselves remain on the host. See the Ubuntu [`apt-get` reference](https://manpages.ubuntu.com/manpages/resolute/man8/apt-get.8.html).

## Example

Remote request:

```json
{"host_id":"c0c326bc-cf08-4e15-98dc-cf8b5fa8d66d"}
```

Local stdio request:

```json
{}
```
