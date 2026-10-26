# Control plane configuration

The `streamable-http` transport requires the settings below. The Go command reads them from the process environment before opening PostgreSQL or serving MCP requests.

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `LISTEN_ADDR` | No | `:8080` | Host and port where the HTTP server listens inside its runtime environment. |
| `DATABASE_URL` | Yes | — | PostgreSQL connection URL used for migrations, tenants, and host inventory. |
| `OIDC_ISSUER_URL` | Yes | — | HTTPS issuer identifier used for OpenID Connect discovery and bearer-token signature verification. |
| `OIDC_AUDIENCE` | Yes | — | Expected audience claim for access tokens issued to this control plane. |
| `PUBLIC_URL` | Yes | — | Public base URL used to identify the MCP resource and generate the OAuth metadata challenge. |
| `FILE_ACTION_KEY_FILE` | Yes | — | Absolute path to a mounted, private file containing exactly 32 random bytes for AES-256-GCM encryption of file and package actions. The key file must be regular and have no group or other permissions. |
| `ALLOW_FILE_WRITES` | No | `false` | Explicit operator policy that registers `write_file` and `rollback_file`. Set to `true` only when enrolled agents also have deliberately configured writable paths and the MCP client requests confirmation for destructive tools. |
| `ALLOW_APT_WRITES` | No | `false` | Explicit operator policy that registers the typed APT tools. Set to `true` only after each host has an agent package policy, root-owned helper policy, sudo rule, and a client that requests per-call confirmation for destructive tools. |
| `ALLOW_COMMAND_EXECUTION` | No | `false` | Explicit operator policy that registers `execute_command` over Streamable HTTP. Set to `true` only after each host has a reviewed exact executable and argument-vector policy and the MCP client requests confirmation for destructive tools. |

`DATABASE_URL` must be a PostgreSQL URL with a host and database name. URL-encode reserved characters in credentials. The bundled Compose stack sets `sslmode=disable` for its private container network; deployments that connect to a remote database should use the TLS mode required by that database, such as `verify-full` with a trusted root certificate.

The issuer URL must use HTTPS. HTTP is accepted for `PUBLIC_URL` only when its hostname is loopback, for local development. The server does not issue or store OAuth access tokens. It verifies bearer JWTs against the issuer's discovered keys and checks issuer, subject, audience, and expiry.

The control plane fails to start if `FILE_ACTION_KEY_FILE` is missing, unreadable by the process user, not a regular private file, or does not contain exactly 32 bytes. Keep the same key available while encrypted jobs or unexpired file and package action records exist. Changing it makes those records undecryptable; retain a separate protected backup and rotate only after all dependent records have expired or been removed. Compose mounts the key as `/run/secrets/file-action-key`; its `CONTROL_PLANE_USER` must be able to read the source file. See [Deploy the self-hosted control plane](../how-to/deploy-control-plane.md) for key creation and ownership.

`ALLOW_FILE_WRITES` defaults to `false`, which omits the file mutation tools from MCP. Enabling it is only the control-plane approval gate: each agent must separately store explicit `writable_paths`, and the MCP client must honor the tools' destructive annotations with per-call human confirmation.

`ALLOW_APT_WRITES` defaults to `false`, which omits `apt_update`, `apt_install`, `apt_remove`, `apt_upgrade`, and `rollback_apt_action` from MCP. Enabling it is only the HTTP control-plane gate. Every host operation must also pass the enrolled agent policy and the root-owned APT helper policy. The MCP client must honor the destructive annotations with per-call human confirmation. See [Configure APT package policy](../how-to/configure-apt-policy.md) before enabling package changes.

`ALLOW_COMMAND_EXECUTION` defaults to `false`, which omits `execute_command` from HTTP MCP. Enabling it is only the control-plane registration gate. Every request must also match an enrolled host's exact executable, argument vector, and optional working-directory policy. Sudo remains disabled per rule unless `use_sudo` is enabled and the host has matching non-interactive sudoers configuration. The agent passes arguments directly without a shell; commands have no rollback. The MCP client should request per-call human confirmation for this destructive, non-idempotent tool. See [Configure constrained command execution](../how-to/configure-command-policy.md) before enabling it.

The public service endpoints are:

| Path | Access | Purpose |
| --- | --- | --- |
| `/mcp` | Bearer token required | MCP Streamable HTTP transport. |
| `/.well-known/oauth-protected-resource/mcp` | Public | RFC 9728 metadata for the `/mcp` resource. |
| `/livez` | Public | Process liveness check. |
| `/readyz` | Public | Readiness check that requires a reachable PostgreSQL database. |
| `/agent/enroll` | One-time pairing code in the request body | Consumes a code and returns one host-scoped credential to the enrolling agent once. See [Host agent API](host-agent-api.md). |
| `/agent/poll` | Active host credential as a bearer token | Records host liveness and returns either an idle response or one leased typed job. See [Host agent API](host-agent-api.md). |
| `/agent/result` | Active host credential as a bearer token | Accepts the result or failure for the current host-scoped job lease. See [Host agent API](host-agent-api.md). |

Every authenticated control-plane user can call `get_system_info`. Over Streamable HTTP, that tool reports the Linux system running the shared control plane, not a host from that user's inventory. Grant issuer access only to users trusted with those shared system facts. `list_hosts` and `get_host_system_info` are scoped to the caller's personal tenant.

The agent endpoints do not use the operator's OIDC token. They require the high-entropy host credential created during enrollment. The host agent initiates every request over HTTPS; no inbound host port is used. The reference deployment terminates TLS at its reverse proxy before forwarding to the control plane. `/agent/enroll`, `/agent/poll`, and `/agent/result` are public application paths at that proxy, and request logs should not record authorization headers or request bodies.

For a Compose deployment, see [Deploy the self-hosted control plane](../how-to/deploy-control-plane.md).
