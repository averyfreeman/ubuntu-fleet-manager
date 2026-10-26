# Self-hosted control plane and outbound host agents

Status: Accepted

## Context

The v0.1 proof of concept is operated by users on their own infrastructure. Hosts may sit behind NAT or firewalls, so requiring inbound host ports or SSH access would complicate deployment and increase exposure.

## Decision

The operator runs the Go control plane and PostgreSQL in a portable container deployment, and runs one unprivileged host agent on each managed host. Agents initiate outbound HTTPS polls to receive leased jobs and return results. No inbound host port is required. Until job delivery is implemented, `POST /agent/poll` records `last_seen_at` and returns an idle result; the same authenticated path is extended by the job ticket. PostgreSQL stores durable state and the job queue; do not add a separate broker until measured usage justifies it. The v0.1 service is self-hosted; cloud control-plane hosting, subscriptions, and public directory submission are future work.

## Alternatives considered

- A centrally hosted fleet control plane: deferred until adoption evidence supports the cost and operational obligations.
- SSH or inbound agent callbacks: rejected because hosts behind NAT would need additional ingress configuration and expose more network surface.
- A dedicated queue broker: deferred because PostgreSQL is already a required durable dependency and the initial scale does not justify another service.

## Consequences

The PostgreSQL schema, migrations, job leases, retry limits, and backup behavior are operationally important and must be documented. Job execution must be idempotent where possible and must detect expired leases. Agents must authenticate every poll and scope each job to their enrolled host.
