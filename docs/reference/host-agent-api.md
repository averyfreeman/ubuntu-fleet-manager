# Host agent API

The host agent uses these HTTP endpoints to enroll, report liveness, lease typed work, and return results. The agent initiates every connection; the managed host does not need an inbound port. Configure a TLS reverse proxy and use the public HTTPS URL when enrolling the agent. Plain HTTP is accepted by the Go client only for loopback development.

The agent's request timeout is 15 seconds. Its default poll interval is 30 seconds. A job lease lasts 60 seconds. An expired lease may be granted again while its MCP request remains active; the request waits up to 90 seconds and cancellation or timeout ends further retries. The control plane stores only SHA-256 hashes of pairing codes and host credentials. Do not log enrollment request bodies, job results, or `Authorization` headers at a reverse proxy.

## Enroll a host

`POST /agent/enroll` consumes a one-time pairing code and returns a new host identity and credential.

### Request

The request must use `Content-Type: application/json` and contain one JSON object. The body limit is 16 KiB; unknown fields are rejected.

| Field | Type | Required | Constraints |
| --- | --- | --- | --- |
| `pairing_code` | string | Yes | Unexpired, unused code returned by `create_pairing_code`. |
| `hostname` | string | Yes | 1 to 253 bytes; leading/trailing whitespace and control characters are rejected. |
| `os_pretty_name` | string | Yes | 1 to 200 bytes; leading/trailing whitespace and control characters are rejected. |

The caller cannot supply a tenant identifier. The new host belongs to the personal tenant that created the pairing code.

### Response

On success, the control plane returns HTTP `201 Created`, `Cache-Control: no-store`, and one JSON object:

| Field | Type | Description |
| --- | --- | --- |
| `host_id` | string | Identifier for later MCP inventory and removal calls. |
| `credential` | string | One-time bearer credential scoped to this host. |

The agent saves the credential in its local configuration file with mode `0600`. The control plane stores only the credential's SHA-256 verifier. The credential is not returned by any later endpoint or MCP tool.

### Errors

| Status | Meaning |
| --- | --- |
| `400 Bad Request` | Invalid JSON, missing or invalid fields, an oversized body, or an unknown field such as a caller-supplied tenant ID. |
| `401 Unauthorized` | Pairing code is invalid, expired, or already consumed. |
| `409 Conflict` | The pairing code's tenant already has an active host with that hostname. The transaction does not consume the code. |
| `500 Internal Server Error` | Enrollment could not be committed. |

## Poll for work and report liveness

`POST /agent/poll` uses the host credential to authenticate the agent. The request body is the empty JSON object `{}`. Each poll updates the host's `last_seen_at` value. The control plane returns either an idle response or one typed job scoped to the authenticated host.

### Request

```http
POST /agent/poll HTTP/1.1
Authorization: Bearer ufm_host_...
Content-Type: application/json

{}
```

### Response

When no work is queued, an active credential receives HTTP `200 OK` and `{"status":"idle"}`. Responses use `Cache-Control: no-store`.

When work is available, the control plane returns HTTP `200 OK` with one leased job:

```json
{
  "status": "job",
  "job": {
    "id": "c0c326bc-cf08-4e15-98dc-cf8b5fa8d66d",
    "operation": "get_system_info",
    "lease_token": "6a1b4c1e-51c0-4bdd-a993-a72b8d76a624",
    "lease_expires_at": "2026-10-26T12:01:00Z",
    "attempt": 1
  }
}
```

The only supported operation is `get_system_info`. The agent collects a structured snapshot from its local Linux host and submits it to `POST /agent/result`. It does not interpret the operation as a command and does not invoke a shell. `attempt` starts at 1 and counts lease grants. After a lease expires, the next poll may receive the job again with a new lease token if the associated MCP request is still active. The request's 90-second deadline or caller cancellation cancels the job, so it is not retried after the request ends.

### Errors

| Status | Meaning |
| --- | --- |
| `400 Bad Request` | Request body is not one empty JSON object. |
| `401 Unauthorized` | Credential is missing, invalid, revoked, or belongs to a removed host. |
| `500 Internal Server Error` | The control plane could not update host liveness or lease work. |

## Submit a job result

`POST /agent/result` accepts a result only from the enrolled host that owns the current lease. The request must use `Content-Type: application/json`, contain one JSON object, and include exactly one of `result` or `error`. The body limit is 16 KiB; unknown fields are rejected.

Successful result requests use the `systeminfo.Info` structure returned by `get_system_info`, including OS release, hostname, kernel, architecture, memory, root filesystem, and `collected_at`. For a collection failure or unsupported operation, the agent sends a non-empty `error` string instead.

Example success request:

```json
{
  "job_id": "c0c326bc-cf08-4e15-98dc-cf8b5fa8d66d",
  "lease_token": "6a1b4c1e-51c0-4bdd-a993-a72b8d76a624",
  "result": {
    "os": {"id": "ubuntu", "pretty_name": "Ubuntu 26.04 LTS", "version_id": "26.04"},
    "hostname": "web-01",
    "kernel": {"name": "Linux", "release": "6.14.0-example"},
    "architecture": "amd64",
    "memory": {"total_bytes": 8589934592, "available_bytes": 4294967296},
    "root_filesystem": {"total_bytes": 107374182400, "used_bytes": 21474836480, "free_bytes": 85899345920, "available_bytes": 81604378624},
    "collected_at": "2026-10-26T12:00:30Z"
  }
}
```

On acceptance, the control plane returns HTTP `200 OK`, `Cache-Control: no-store`, and `{"accepted":true}`. Repeating an already accepted submission with the same lease token is idempotent; it does not overwrite the first result. The control plane clears the snapshot after the MCP request retrieves it.

| Status | Meaning |
| --- | --- |
| `400 Bad Request` | Invalid JSON, oversized body, unknown fields, invalid system-info snapshot, or both/neither result and error supplied. |
| `401 Unauthorized` | Credential is missing, invalid, revoked, or belongs to a removed host. |
| `409 Conflict` | Job is unknown to this host, cancelled, failed, completed with another lease token, or the submitted lease is stale or expired. Discard this result and continue polling. |
| `500 Internal Server Error` | The control plane could not persist the result. |

Removing a host revokes its credential and cancels pending or leased jobs plus completed jobs whose snapshots have not been delivered. An MCP `get_host_system_info` request is cancelled when its caller disconnects or the 90-second wait expires. See [Get system information from a managed host](tools/get-host-system-info.md) for the MCP tool behavior and result schema.
