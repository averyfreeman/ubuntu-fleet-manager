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
    "input": {},
    "lease_token": "6a1b4c1e-51c0-4bdd-a993-a72b8d76a624",
    "lease_expires_at": "2026-10-26T12:01:00Z",
    "attempt": 1
  }
}
```

The supported operations are `get_system_info`, `list_directory`, `read_file`, `search_packages`, `write_file`, `restore_file`, `apt_update`, `apt_install`, `apt_remove`, `apt_upgrade`, `apt_rollback`, and `execute_command`. The `input` object is specific to the operation:

| Operation | Input fields |
| --- | --- |
| `get_system_info` | Empty object `{}`. |
| `list_directory` | `path`: absolute directory path inside the host agent's configured read boundary. |
| `read_file` | `path`: absolute regular-file path inside the host agent's configured read boundary. |
| `search_packages` | `query`: literal search text; `limit`: optional maximum result count, default 50, maximum 100. |
| `write_file` | `path`: absolute path inside the separately configured writable boundary; `content`: UTF-8 text, at most 256 KiB. |
| `restore_file` | `path`, `previous`, and `expected_current`: authenticated control-plane payload containing captured state and the fingerprint needed for a safe restore. |
| `apt_update` | Empty object `{}`. The agent package policy and root-owned helper policy must allow `update`. |
| `apt_install`, `apt_remove`, `apt_upgrade` | `packages`: one to 20 unique Debian package names, each in the agent and root-owned helper allowlists. |
| `apt_rollback` | `previous` and `expected_current`: authenticated package states captured by the control plane for one rollback action. |
| `execute_command` | `executable`: exact absolute executable path; `args`: exact argument vector; optional `working_directory`: exact configured directory. The host's `command_policy` must allow the request. |

The agent validates each typed input. `execute_command` passes the configured executable and arguments directly without invoking a shell. Read paths default to the agent user's home directory; write paths, APT operations, and generic commands default to none. Local host configuration can add permitted directories, package operations, and exact command vectors. APT writes call `/usr/local/bin/ubuntu-fleet-manager apt-helper` through non-interactive sudo; the root-owned helper validates the exact argument layout and its independent allowlist before it invokes `/usr/bin/apt-get`. See [Enroll and run a host agent](../how-to/enroll-host-agent.md), [Configure APT package policy](../how-to/configure-apt-policy.md), and [Configure constrained command execution](../how-to/configure-command-policy.md).

`attempt` starts at 1 and counts lease grants. After a lease expires, the next poll may receive the job again with a new lease token if the associated MCP request is still active. The request's 90-second deadline or caller cancellation cancels the job, so it is not retried after the request ends.

### Errors

| Status | Meaning |
| --- | --- |
| `400 Bad Request` | Request body is not one empty JSON object. |
| `401 Unauthorized` | Credential is missing, invalid, revoked, or belongs to a removed host. |
| `500 Internal Server Error` | The control plane could not update host liveness or lease work. |

## Submit a job result

`POST /agent/result` accepts a result only from the enrolled host that owns the current lease. The request must use `Content-Type: application/json`, contain one JSON object, and include exactly one of `result` or `error`. The body limit is 4 MiB; unknown fields are rejected. Errors are limited to 4096 bytes. Successful results must match the leased operation's typed schema and requested bounds.

Successful result requests use the structure for the leased operation:

- `get_system_info` returns OS release, hostname, kernel, architecture, memory, root filesystem, and `collected_at`.
- `list_directory` returns `path`, `entries` (maximum 100), and `truncated`; each entry has `name`, `path`, `type`, `size_bytes`, `mode`, `modified_at`, and `is_symlink`.
- `read_file` returns `path`, UTF-8 `content`, and `size_bytes`; the content limit is 256 KiB.
- `search_packages` returns the normalized `query`, `packages` (at most the requested limit), and `truncated`; each package has `name` and short `description`. It reads configured indexes and keeps any generated APT cache files in a temporary directory removed after the search.
- `write_file` returns `path`, `previous`, and `current`. The `previous` state includes prior existence, bytes, and permission bits; it is encrypted before PostgreSQL storage.
- `restore_file` returns `path`, `restored`, `exact`, and an optional `reason`. If the file no longer matches the managed write or captured prior state, later contents are preserved and exact restoration is reported unavailable.
- `apt_update` returns its operation and outcome without package state; it has no rollback.
- `apt_install`, `apt_remove`, and `apt_upgrade` return `operation`, `before`, `after`, `outcome`, `rollback_available`, and an optional safe `reason`. Package states include `name`, `installed`, and `version` when installed.
- `apt_rollback` returns an `outcome` and one package result per captured package. Each package result contains `name`, `restored`, `exact`, and an optional `reason`.
- `execute_command` returns `exit_code`, bounded `stdout`, bounded `stderr`, and `output_truncated`. Common credential patterns are redacted before a result is submitted; host policy denials return a generic error without raw command output.

For a collection failure, denied path, unavailable APT index, rejected package policy, unavailable sudo helper, or other operation error, the agent sends a non-empty generic `error` string instead. It does not send raw command output through the result endpoint.

For APT operations, the agent records installed package state with `dpkg-query`. The Ubuntu [`dpkg-query` reference](https://manpages.ubuntu.com/manpages/resolute/man1/dpkg-query.1.html) documents the machine-readable `${binary:Package}`, `${Version}`, and `${db:Status-Abbrev}` fields used by the agent. The control plane encrypts package audit and rollback state for seven days and clears consumed job input and result payloads after it stores that encrypted record.

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

Example successful file result:

```json
{
  "job_id": "c0c326bc-cf08-4e15-98dc-cf8b5fa8d66d",
  "lease_token": "6a1b4c1e-51c0-4bdd-a993-a72b8d76a624",
  "result": {
    "path": "/home/ubuntu-fleet-agent/settings.conf",
    "content": "mode=safe\n",
    "size_bytes": 10
  }
}
```

Example successful package search result:

```json
{
  "job_id": "c0c326bc-cf08-4e15-98dc-cf8b5fa8d66d",
  "lease_token": "6a1b4c1e-51c0-4bdd-a993-a72b8d76a624",
  "result": {
    "query": "apt",
    "packages": [{"name": "apt", "description": "command-line package manager"}],
    "truncated": false
  }
}
```

On acceptance, the control plane returns HTTP `200 OK`, `Cache-Control: no-store`, and `{"accepted":true}`. Repeating an already accepted submission with the same lease token is idempotent; it does not overwrite the first result. The control plane encrypts new job inputs and results with the mounted application key. It clears delivered, failed, and cancelled job payloads, while successful `write_file` results are moved into a separate encrypted reversal record before the job payload is cleared.

| Status | Meaning |
| --- | --- |
| `400 Bad Request` | Invalid JSON, oversized body, unknown fields, result that does not match the leased operation, invalid error text, or both/neither result and error supplied. |
| `401 Unauthorized` | Credential is missing, invalid, revoked, or belongs to a removed host. |
| `409 Conflict` | Job is unknown to this host, cancelled, failed, completed with another lease token, or the submitted lease is stale or expired. Discard this result and continue polling. |
| `500 Internal Server Error` | The control plane could not persist the result. |

The service removes job records and encrypted reversal records from its active application store after seven days. Cleanup runs at startup and once per minute, so an expired row can remain for up to a minute while the service is running. Backups are operator-managed and may retain older encrypted database pages. See [Control plane configuration](control-plane-configuration.md).

Removing a host revokes its credential and cancels pending or leased jobs plus completed jobs whose results have not been delivered. An MCP host-operation request is cancelled when its caller disconnects or the 90-second wait expires. See [Get system information from a managed host](tools/get-host-system-info.md), [List a directory on a managed host](tools/list-directory.md), [Read a file on a managed host](tools/read-file.md), [Search APT packages on a managed host](tools/search-packages.md), [Write a file on a managed host](tools/write-file.md), and [Roll back a managed file write](tools/rollback-file.md) for MCP tool schemas and results.
