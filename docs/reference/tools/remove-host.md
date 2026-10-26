# Remove a managed host

Removes a host from active inventory and revokes its host credential.

## Availability

The `remove_host` tool is available through authenticated Streamable HTTP. It is not exposed by the local stdio transport.

## Input

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `host_id` | string | Yes | Identifier returned by `list_hosts`. |

The operation is scoped to the authenticated operator's personal tenant. A host in another tenant cannot be removed with this tool.

## Output

| Field | Type | Description |
| --- | --- | --- |
| `host_id` | string | Identifier of the removed host. |
| `removed` | boolean | `true` when the host credential has been revoked. |

The tool marks the host as removed, immediately revokes all credentials for it, cancels pending and leased jobs plus completed jobs whose snapshots have not yet been delivered, and excludes it from subsequent `list_hosts` results. The host record remains in PostgreSQL. A later enrollment may reuse the same hostname and creates a new host identity and credential.

## Effects and limitations

This operation disconnects the host from the control plane. The agent's next poll or result submission is rejected with HTTP `401 Unauthorized`. An MCP request waiting for this host's system information returns an error. It cannot be undone by that host; enroll it again with a new pairing code if it should return.

The tool is destructive and idempotent for a host that remains in the authenticated operator's tenant. It does not stop or remove local processes on the host.

## Errors

The tool returns an MCP error when the host identifier is invalid or no matching host exists in the caller's personal tenant.
