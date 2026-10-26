# Identity, personal tenancy, and host enrollment

Status: Accepted

## Context

A remote control plane needs to distinguish operators, isolate their hosts and audit data, and let each host authenticate without opening inbound access. The v0.1 self-hosted proof of concept does not include shared organizations or team administration.

## Decision

Authenticate operators over Streamable HTTP with provider-neutral OAuth 2.1/OIDC. Create one personal tenant for each authenticated user; do not provide shared team or organization tenants in v0.1. Treat local stdio as a local-user trust boundary. Require authenticated user authorization for all remote reads and writes.

An authenticated operator uses the `create_pairing_code` MCP tool to create a cryptographically random pairing code with a ten-minute expiry. The code has 256 bits of random material, is one-use, scoped to that operator's tenant, stored only as a SHA-256 hash, and invalidated after successful enrollment or expiry. `POST /agent/enroll` atomically consumes the code, creates the host in the code's tenant, and returns one host-scoped credential to the agent. The credential also has 256 bits of random material; store its SHA-256 verifier, not its plaintext value. The agent CLI saves the credential in a mode-0600 configuration file and initiates HTTPS `POST /agent/poll` requests every 30 seconds. Revoke credentials immediately when an operator removes a host with `remove_host`; keep the host record but exclude it from active inventory. A removed host's hostname may be enrolled again as a new host identity.

## Alternatives considered

- Shared organization tenancy: deferred because access delegation and role management are outside the proof-of-concept scope.
- Long-lived shared enrollment secrets: rejected because they are difficult to revoke per host and easy to reuse accidentally.
- Unauthenticated remote MCP: rejected because host inventory and operations are private and potentially consequential.

## Consequences

Tests must cover tenant isolation, invalid and expired pairing codes, replay attempts, credential revocation, and host-to-tenant scoping. Operators must not log pairing-code request bodies or host authorization headers at the TLS reverse proxy. Setup documentation must explain OIDC issuer configuration and credential storage. The ten-minute pairing lifetime is a documented default that can be revisited with evidence.
