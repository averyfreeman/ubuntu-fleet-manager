# Create a host pairing code

Creates a temporary code that lets one host join the authenticated operator's personal tenant.

## Availability

The `create_pairing_code` tool is available through authenticated Streamable HTTP. It is not exposed by the local stdio transport.

## Input

The tool accepts no arguments.

## Output

| Field | Type | Description |
| --- | --- | --- |
| `pairing_code` | string | One-time secret to enter on the host agent during enrollment. |
| `expires_at` | timestamp | UTC expiry time, ten minutes after creation. |

Each code contains 256 bits of random material. The control plane stores only its SHA-256 hash. It can be consumed once by `POST /agent/enroll`; invalid, expired, and previously consumed codes are rejected. The host is created in the tenant that owns the code. The caller cannot select a tenant in the enrollment request.

Treat the returned code as a secret. Share it only with the host being enrolled, and do not paste it into shell history or a support ticket. The agent accepts the code through standard input so it does not need to appear in process arguments.

## Effects and limitations

Creating a code adds temporary enrollment state to PostgreSQL. It does not enroll a host until an agent redeems the code. Unused and expired codes remain in the database in this version.

## Errors

The tool returns an MCP error if the authenticated personal tenant is unavailable or PostgreSQL cannot store the code.
