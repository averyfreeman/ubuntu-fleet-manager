# Self-hosted control plane and outbound host agents

Status: Accepted

## Context

The v0.1 proof of concept is operated by users on their own infrastructure. Hosts may sit behind NAT or firewalls, so requiring inbound host ports or SSH access would complicate deployment and increase exposure.

## Decision

The operator runs the Go control plane and PostgreSQL in a portable container deployment, and runs one unprivileged host agent on each managed host. Agents initiate outbound HTTPS polls to receive leased jobs and return results. No inbound host port is required. `POST /agent/poll` records `last_seen_at`; when work is queued it grants a host-scoped lease. `POST /agent/result` accepts the typed result only from the current lease holder. PostgreSQL stores durable state and the job queue; do not add a separate broker until measured usage justifies it. The v0.1 service is self-hosted; cloud control-plane hosting, subscriptions, and public directory submission are future work.

The first remote operation is system information only. It is requested through the authenticated `get_host_system_info(host_id)` MCP tool; the existing `get_system_info` tool continues to inspect the MCP process host. A lease lasts 60 seconds. If it expires while the MCP request is active, the job may be leased again with a fresh token. The MCP call waits at most 90 seconds, and its cancellation or timeout cancels pending or leased work; retries do not continue after the request ends. Lease tokens prevent a stale agent attempt from completing or overwriting a newer attempt. Host removal also cancels undelivered work. The control plane clears a successful snapshot after delivering it to the caller. The agent handles only the typed system-info operation and never invokes a shell or arbitrary command.

## Alternatives considered

- A centrally hosted fleet control plane: deferred until adoption evidence supports the cost and operational obligations.
- SSH or inbound agent callbacks: rejected because hosts behind NAT would need additional ingress configuration and expose more network surface.
- A dedicated queue broker: deferred because PostgreSQL is already a required durable dependency and the initial scale does not justify another service.

## Consequences

The PostgreSQL schema, migrations, job leases, request-bound retries, cancellation, and backup behavior are operationally important and must be documented. Job execution must be idempotent where possible and must detect expired leases. Agents must authenticate every poll and result submission, and the control plane scopes each job to its enrolled host. Removing a host revokes its credential and cancels its pending work in the same transaction.
