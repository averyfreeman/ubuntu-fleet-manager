# Control plane configuration

The `streamable-http` transport requires the settings below. The Go command reads them from the process environment before opening PostgreSQL or serving MCP requests.

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `LISTEN_ADDR` | No | `:8080` | Host and port where the HTTP server listens inside its runtime environment. |
| `DATABASE_URL` | Yes | — | PostgreSQL connection URL used for migrations, tenants, and host inventory. |
| `OIDC_ISSUER_URL` | Yes | — | HTTPS issuer identifier used for OpenID Connect discovery and bearer-token signature verification. |
| `OIDC_AUDIENCE` | Yes | — | Expected audience claim for access tokens issued to this control plane. |
| `PUBLIC_URL` | Yes | — | Public base URL used to identify the MCP resource and generate the OAuth metadata challenge. |

`DATABASE_URL` must be a PostgreSQL URL with a host and database name. URL-encode reserved characters in credentials. The bundled Compose stack sets `sslmode=disable` for its private container network; deployments that connect to a remote database should use the TLS mode required by that database, such as `verify-full` with a trusted root certificate.

The issuer URL must use HTTPS. HTTP is accepted for `PUBLIC_URL` only when its hostname is loopback, for local development. The server does not issue or store OAuth access tokens. It verifies bearer JWTs against the issuer's discovered keys and checks issuer, subject, audience, and expiry.

The public service endpoints are:

| Path | Access | Purpose |
| --- | --- | --- |
| `/mcp` | Bearer token required | MCP Streamable HTTP transport. |
| `/.well-known/oauth-protected-resource/mcp` | Public | RFC 9728 metadata for the `/mcp` resource. |
| `/livez` | Public | Process liveness check. |
| `/readyz` | Public | Readiness check that requires a reachable PostgreSQL database. |
| `/agent/enroll` | One-time pairing code in the request body | Consumes a code and returns one host-scoped credential to the enrolling agent once. See [Host agent API](host-agent-api.md). |
| `/agent/poll` | Active host credential as a bearer token | Records host liveness and returns an idle response when there is no job to run. See [Host agent API](host-agent-api.md). |

Every authenticated control-plane user can call `get_system_info`. Over Streamable HTTP, that tool reports the Linux system running the shared control plane, not a host from that user's inventory. Grant issuer access only to users trusted with those shared system facts. `list_hosts` remains scoped to the caller's personal tenant.

The agent endpoints do not use the operator's OIDC token. They require the high-entropy host credential created during enrollment. The host agent initiates every request over HTTPS; no inbound host port is used. The reference deployment terminates TLS at its reverse proxy before forwarding to the control plane. `/agent/enroll` and `/agent/poll` are public application paths at that proxy, and request logs should not record authorization headers or request bodies.

For a Compose deployment, see [Deploy the self-hosted control plane](../how-to/deploy-control-plane.md).
