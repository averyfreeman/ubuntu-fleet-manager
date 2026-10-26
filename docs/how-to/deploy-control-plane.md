# Deploy the self-hosted control plane

This guide starts the Go control plane and PostgreSQL with Docker Compose. The service verifies bearer access tokens issued by an external OIDC provider; it does not provide an identity provider or an interactive sign-in page.

## Before you begin

You need Docker Compose, a PostgreSQL-compatible volume location, and an OIDC issuer that can issue signed JWT access tokens for the audience configured below. The control plane must be able to reach the issuer's OpenID Connect discovery and signing-key endpoints.

For remote MCP clients, provide a TLS reverse proxy and a public HTTPS URL. The Compose file binds the application port to loopback on the deployment host.

## Configure the deployment

Create a local environment file and edit its values:

```sh
cp .env.example .env
```

Set a long, random, URL-safe `POSTGRES_PASSWORD`. It is used for the database user and appears in the internal PostgreSQL connection URL. Keep `.env` private; it is excluded from version control.

Set `OIDC_ISSUER_URL` to the exact issuer identifier from the provider's discovery document. Set `OIDC_AUDIENCE` to the audience value that the provider includes in access tokens for Ubuntu Fleet Manager. The token must contain a subject and expiry and must verify against the issuer's published signing keys.

Create the application encryption key before starting Compose. The control plane requires exactly 32 random bytes in a regular file with mode `0400` or `0600` and no group or other permissions:

```sh
mkdir -p secrets
umask 077
head -c 32 /dev/urandom > secrets/file-action-key
chmod 0600 secrets/file-action-key
```

The image runs as UID:GID `10001:10001` by default. A file-backed Compose secret keeps the source file's host ownership, so make the key readable by `CONTROL_PLANE_USER` while keeping it private from other host users. For the default image user, set the owner before starting Compose:

```sh
sudo chown 10001:10001 secrets/file-action-key
```

If the deployment account already owns the key, set `CONTROL_PLANE_USER` in `.env` to that account's numeric UID and GID instead. With rootless Podman, container user `0:0` maps to the Podman account inside the user namespace; set `CONTROL_PLANE_USER=0:0` and keep the key owned by that account with mode `0600`.

Keep a protected backup of this key separate from the PostgreSQL volume. The application encrypts host job inputs and results and retains file reversal payloads for seven days. Replacing the key before those records expire makes them undecryptable. Compose mounts the file at `/run/secrets/file-action-key`; change `FILE_ACTION_KEY_SOURCE` in `.env` if the host-side file is elsewhere. Backups may retain encrypted database pages beyond seven days and must be managed separately.

File mutation tools are disabled by default. Keep `ALLOW_FILE_WRITES=false` unless operators have configured agent `writable_paths` and connected only MCP clients that confirm destructive calls. Setting it to `true` exposes `write_file` and `rollback_file` to authenticated operators; each write is separately bounded by the enrolled host's writable paths.

APT maintenance tools are disabled by default. Keep `ALLOW_APT_WRITES=false` until each target host has an agent package allowlist, an independently configured root-owned helper allowlist, and a sudo rule limited to the helper. Setting it to `true` exposes typed update, install, remove, upgrade, and rollback tools to authenticated operators. Every APT action requires per-call confirmation from the MCP client and is rechecked by the host policies. See [Configure APT package policy](configure-apt-policy.md).

Generic command execution is disabled by default. Keep `ALLOW_COMMAND_EXECUTION=false` unless each target host has a deliberately reviewed exact executable and argument-vector policy. Setting it to `true` exposes `execute_command` over HTTP; it does not enable a shell or grant sudo by itself. The tool has no rollback and can change host state, so connect only clients that request per-call confirmation. See [Configure constrained command execution](configure-command-policy.md).

For a local-only deployment, keep `PUBLIC_URL=http://localhost:8080`. `MCP_HOST_PORT` changes the loopback-only host port published by Compose; if you change it, set `PUBLIC_URL` to the matching local URL. For remote clients and host agents, set `PUBLIC_URL` to the external HTTPS base URL that the reverse proxy uses, such as `https://fleet.example.com`. Configure the proxy to forward `/mcp`, `/.well-known/oauth-protected-resource/mcp`, `/agent/enroll`, `/agent/poll`, `/agent/result`, `/livez`, and `/readyz` to the control-plane container without changing their paths. The agent endpoints do not use the operator's OIDC bearer token: enrollment uses a one-time pairing code, and polling and result submission use the host credential. Configure access logging to omit authorization headers and request bodies for the agent endpoints; write results contain captured prior file contents before application encryption. See [Host agent API](../reference/host-agent-api.md).

## Start and check the services

Start the stack:

```sh
docker compose up --build --detach
docker compose ps
```

The control-plane container waits for PostgreSQL's health check and applies embedded SQL migrations before it starts listening. Check readiness from the deployment host:

```sh
curl --fail http://127.0.0.1:8080/livez
curl --fail http://127.0.0.1:8080/readyz
```

`/livez` reports that the process is running. `/readyz` returns success only when PostgreSQL responds to a readiness check. The MCP endpoint is `/mcp`. Its protected resource metadata is at `/.well-known/oauth-protected-resource/mcp` and names the configured issuer.

## Connect an MCP client

Configure the client with the public `/mcp` URL. The client follows the resource metadata challenge to discover the authorization server, obtains an access token from the configured provider, then sends it as `Authorization: Bearer <token>`. The provider must issue a token whose audience matches `OIDC_AUDIENCE`.

`get_system_info` reports the Linux runtime running the control-plane process. The scratch container does not include `/etc/os-release`, so its distribution fields report `unknown`; use `get_host_system_info` to inspect a managed Ubuntu host. `list_hosts` returns only active hosts in the authenticated user's personal tenant. Create a pairing code and enroll an unprivileged host agent to populate the inventory; see [Enroll and run a host agent](enroll-host-agent.md). When `ALLOW_FILE_WRITES=true`, `ALLOW_APT_WRITES=true`, or `ALLOW_COMMAND_EXECUTION=true`, use a client that requests per-call confirmation for destructive calls; the tool annotations rely on the MCP client to present that prompt.

## Stop the stack

Stop the containers while retaining the named PostgreSQL volume:

```sh
docker compose down
```

Start again with `docker compose up --detach`. PostgreSQL schema changes are applied through versioned migrations during control-plane startup.
