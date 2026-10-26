# Identity, personal tenancy, and host enrollment

Status: Accepted

## Context

A remote control plane needs to distinguish operators, isolate their hosts and audit data, and let each host authenticate without opening inbound access. The v0.1 self-hosted proof of concept does not include shared organizations or team administration.

## Decision

Authenticate operators over Streamable HTTP with provider-neutral OAuth 2.1/OIDC. Create one personal tenant for each authenticated user; do not provide shared team or organization tenants in v0.1. Treat local stdio as a local-user trust boundary. Require authenticated user authorization for all remote reads and writes.

An authenticated operator creates a cryptographically random pairing code with a ten-minute expiry. The code is one-use, scoped to that operator's tenant, stored only as a hash, and invalidated after successful enrollment or expiry. Enrollment issues a revocable host credential scoped to one host and tenant; store its verifier, not its plaintext value. Revoke credentials immediately when an operator removes a host.

## Alternatives considered

- Shared organization tenancy: deferred because access delegation and role management are outside the proof-of-concept scope.
- Long-lived shared enrollment secrets: rejected because they are difficult to revoke per host and easy to reuse accidentally.
- Unauthenticated remote MCP: rejected because host inventory and operations are private and potentially consequential.

## Consequences

Tests must cover tenant isolation, invalid and expired pairing codes, replay attempts, credential revocation, and host-to-tenant scoping. Setup documentation must explain OIDC issuer configuration and credential storage. The ten-minute pairing lifetime is a documented default that can be revisited with evidence.
