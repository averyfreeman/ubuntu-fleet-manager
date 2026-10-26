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

For a local-only deployment, keep `PUBLIC_URL=http://localhost:8080`. For remote clients and host agents, set `PUBLIC_URL` to the external HTTPS base URL that the reverse proxy uses, such as `https://fleet.example.com`. Configure the proxy to forward `/mcp`, `/.well-known/oauth-protected-resource/mcp`, `/agent/enroll`, `/agent/poll`, `/agent/result`, `/livez`, and `/readyz` to the control-plane container without changing their paths. The agent endpoints do not use the operator's OIDC bearer token: enrollment uses a one-time pairing code, and polling and result submission use the host credential. Configure access logging to omit authorization headers and request bodies for the agent endpoints; see [Host agent API](../reference/host-agent-api.md).

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

`get_system_info` reports the Linux system running the control-plane process. `list_hosts` returns only active hosts in the authenticated user's personal tenant. Create a pairing code and enroll an unprivileged host agent to populate the inventory; see [Enroll and run a host agent](enroll-host-agent.md).

## Stop the stack

Stop the containers while retaining the named PostgreSQL volume:

```sh
docker compose down
```

Start again with `docker compose up --detach`. PostgreSQL schema changes are applied through versioned migrations during control-plane startup.
