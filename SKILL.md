---
name: ubuntu-fleet-manager
description: Use when modifying or operating this repository's Go MCP runtime, Python or Node connectors, Ubuntu host agent, self-hosted deployment, or product documentation.
---

# Ubuntu Fleet Manager development

Use this skill to make auditable changes to the Go MCP server and its clients.

## Start with project context

1. Read `AGENTS.md`, `GLOSSARY.md`, and the ADRs that cover the component you are changing.
2. Read the matching GitHub issue using `gh issue view`; follow `docs/agents/issue-tracker.md` when updating tickets.
3. Use the Go tool registration and typed host-operation packages as the source of truth for behavior. Python and Node packages are MCP clients, not operation implementations.

## Implement and document one behavior at a time

1. Exercise the public boundary for the behavior: MCP discovery and calls, the host-operation runner, the HTTP control plane, or the agent API.
2. Change the smallest vertical slice that delivers the issue's observable outcome. Keep policy checks in Go and preserve exact MCP result and error behavior in connector clients.
3. Update the matching tool reference, configuration reference, how-to, tutorial, or explanation whenever user-visible behavior changes.
4. Run the narrow test for the slice, then the applicable full test commands below. Fix a failing result before starting another ticket.

## Run locally

Build the Go runtime:

```sh
GOTOOLCHAIN=go1.27.3 go build -o ./build/ubuntu-fleet-manager ./cmd/ubuntu-fleet-manager
```

Run Go unit and protocol tests, vet, and build checks:

```sh
GOTOOLCHAIN=go1.27.3 go test ./...
GOTOOLCHAIN=go1.27.3 go vet ./...
GOTOOLCHAIN=go1.27.3 go build ./...
```

PostgreSQL integration tests require a disposable database URL:

```sh
UFM_TEST_DATABASE_URL='postgres://postgres:password@127.0.0.1:5432/ufm_test?sslmode=disable' \
  GOTOOLCHAIN=go1.27.3 go test ./internal/controlplane -count=1
```

Run both connector contract suites against the built runtime and test-only HTTP fixture:

```sh
GOTOOLCHAIN=go1.27.3 go build -o ./build/contract-server ./tests/contract-server
uv sync --project connectors/python --locked
npm ci --prefix connectors/node
UFM_SERVER_BINARY="$PWD/build/ubuntu-fleet-manager" \
UFM_HTTP_SERVER_BINARY="$PWD/build/contract-server" \
  uv run --project connectors/python --locked python -m unittest discover -s connectors/python/tests -v
UFM_SERVER_BINARY="$PWD/build/ubuntu-fleet-manager" \
UFM_HTTP_SERVER_BINARY="$PWD/build/contract-server" \
  npm test --prefix connectors/node
```

The legacy Python server has its own root package and test command:

```sh
uv sync --frozen
uv run python -m unittest discover -s tests -v
```

Run the full clean Compose deployment acceptance with Docker Compose and OpenSSL installed. It builds the pinned runtime image, starts an ephemeral PostgreSQL volume and test OIDC issuer, enrolls a real host agent process, and checks confirmation annotations plus file rollback:

```sh
GOTOOLCHAIN=go1.27.3 go build -o ./build/ubuntu-fleet-manager ./cmd/ubuntu-fleet-manager
GOTOOLCHAIN=go1.27.3 go build -o ./build/oidc-fixture ./tests/oidc-fixture
UFM_SERVER_BINARY="$PWD/build/ubuntu-fleet-manager" \
UFM_OIDC_FIXTURE_BINARY="$PWD/build/oidc-fixture" \
  uv run --project connectors/python --locked python tests/acceptance/compose_smoke.py
```

The control-plane suite also runs in CI with PostgreSQL, and the host-agent behavior suite runs in an Ubuntu 26.04 container. Use the same workflow when changing OS-facing behavior.

## Operate the service

- Use [Try the local MCP server](docs/tutorials/try-local-mcp-server.md) to connect a local stdio server.
- Use [Deploy the self-hosted control plane](docs/how-to/deploy-control-plane.md) and [Enroll and run a host agent](docs/how-to/enroll-host-agent.md) for remote hosts.
- Keep file writes, APT maintenance, and generic command execution disabled until their separate host and control-plane policies are configured.
- Treat MCP destructive annotations as client-side approval hints. Configure the MCP host to ask for human approval; do not claim the server can verify that a prompt appeared.
- Read [Security, approval, and reversal](docs/explanation/security-and-reversal.md) before changing policy, encryption, retention, or rollback behavior.
