# Host agent API

The host agent uses these HTTP endpoints to enroll and report liveness. The agent initiates every connection; the managed host does not need an inbound port. Configure a TLS reverse proxy and use the public HTTPS URL when enrolling the agent. Plain HTTP is accepted by the Go client only for loopback development.

The agent's request timeout is 15 seconds. Its default poll interval is 30 seconds. The control plane stores only SHA-256 hashes of pairing codes and host credentials. Do not log enrollment request bodies or `Authorization` headers at a reverse proxy.

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

`POST /agent/poll` uses the host credential to authenticate the agent. The request body is the empty JSON object `{}`. The control plane updates the host's `last_seen_at` value and, until job delivery is implemented, returns an idle result.

### Request

```http
POST /agent/poll HTTP/1.1
Authorization: Bearer ufm_host_...
Content-Type: application/json

{}
```

### Response

An active credential receives HTTP `200 OK` and `{"status":"idle"}`. Responses use `Cache-Control: no-store`.

| Status | Meaning |
| --- | --- |
| `400 Bad Request` | Request body is not one empty JSON object. |
| `401 Unauthorized` | Credential is missing, invalid, revoked, or belongs to a removed host. |
| `500 Internal Server Error` | The control plane could not update host liveness. |

Ticket #5 extends the polling path to lease durable jobs and return typed results. The current `idle` response means no work is available in this version.
