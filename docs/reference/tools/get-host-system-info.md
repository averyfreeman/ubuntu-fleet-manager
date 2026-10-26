# Get system information from a managed host

`get_host_system_info` requests a fresh system-information snapshot from one enrolled host in the authenticated operator's personal tenant. The host must be active and its agent must poll the control plane within 90 seconds. This tool is available over authenticated Streamable HTTP. The existing `get_system_info` tool remains a no-argument snapshot of the MCP server's local host.

## Request

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `host_id` | string | Yes | Identifier returned by host enrollment and `list_hosts`. |

The control plane resolves `host_id` inside the caller's personal tenant. A malformed, unknown, removed, or other-tenant identifier returns the same not-found tool error.

The MCP tool is marked read-only, idempotent, and closed-world. It creates a temporary durable job for the enrolled host; it does not execute a command or change host configuration.

## Result

The structured result contains:

| Field | Type | Description |
| --- | --- | --- |
| `host_id` | string | Identifier of the target host. |
| `hostname` | string | Hostname reported during enrollment. |
| `requested_at` | string | UTC timestamp when the control plane queued the request. |
| `system_info` | object | Snapshot collected by the host agent, in the same format as [`get_system_info`](get-system-info.md). |

`system_info.hostname` is the hostname observed by the agent when it collected the snapshot. It may differ from the enrollment-time `hostname` if the host was renamed. Its `collected_at` timestamp identifies when the host gathered the data; it is the freshness timestamp for the snapshot.

Example:

```json
{
  "host_id": "c0c326bc-cf08-4e15-98dc-cf8b5fa8d66d",
  "hostname": "web-01",
  "requested_at": "2026-10-26T12:00:00Z",
  "system_info": {
    "os": {
      "id": "ubuntu",
      "pretty_name": "Ubuntu 26.04 LTS",
      "version_id": "26.04",
      "version_codename": "resolute"
    },
    "hostname": "web-01",
    "kernel": {"name": "Linux", "release": "6.14.0-example"},
    "architecture": "amd64",
    "memory": {"total_bytes": 8589934592, "available_bytes": 4294967296},
    "root_filesystem": {
      "total_bytes": 107374182400,
      "used_bytes": 21474836480,
      "free_bytes": 85899345920,
      "available_bytes": 81604378624
    },
    "collected_at": "2026-10-26T12:00:30Z"
  }
}
```

The control plane clears the stored snapshot after the MCP request retrieves it. The durable job record remains for its terminal status and retry history.

## Job lifecycle and limits

The MCP request queues one `get_system_info` job. The agent receives it on its next authenticated `POST /agent/poll`, collects the typed snapshot, and submits it to `POST /agent/result`. The agent accepts only this operation; it does not run a shell or interpret arbitrary commands.

- Each lease lasts 60 seconds and carries a fresh lease token.
- If a lease expires while the MCP request remains active, the next agent poll may receive the job again with an incremented `attempt` and fresh lease token.
- The MCP request waits at most 90 seconds.
- If the caller cancels the MCP request or the wait expires, a pending or leased job is cancelled and no further retries are offered. A late or stale result cannot become a successful MCP result.
- Removing a host revokes its credential and cancels its outstanding jobs.

See [Host agent API](../host-agent-api.md) for HTTP request and response schemas.

## Errors

The tool returns an MCP tool error when:

- `host_id` is invalid, missing, removed, unknown, or outside the caller's tenant.
- The host agent does not return a snapshot within 90 seconds.
- The agent reports a collection failure.
- The request is cancelled or the host is removed before result delivery.
- The agent returns an incomplete or invalid system-information snapshot.
