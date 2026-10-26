# Security, approval, and reversal

Ubuntu Fleet Manager separates the MCP client, Go control plane, and unprivileged host agent. Each boundary has a different credential and enforcement role.

## Identity and host scope

The Streamable HTTP control plane verifies operator bearer tokens against its configured OIDC issuer and audience. It assigns a personal tenant from the verified issuer and subject. Host inventory and queued operations are scoped to that tenant.

A managed host enrolls with a one-use pairing code and receives a host-scoped credential. The host agent makes outbound requests to poll for work and submit results. It does not expose an inbound network service. Revoking a host removes it from active inventory and invalidates its credential.

## Policy and confirmation

Mutating tools are disabled at the control plane by default. Enabling a control-plane flag only registers a tool; each operation must also pass host-agent policy and any applicable root-owned OS policy. File and command operations are bounded by configured host paths, exact command rules, or package allowlists.

MCP annotations tell a client whether a tool changes state and whether it can reach outside the host. A compatible MCP host can use these hints to ask for approval. Approval is enforced by the client UI, not proven by the server. A self-hosted client should be configured to ask for each destructive operation, and operators should keep server policy enabled only for hosts and operations they intend to expose.

`execute_command` uses an exact executable and argument vector, runs without a shell, and is not reversible. It is disabled by default and has strict output and runtime limits. See [Configure constrained command execution](../how-to/configure-command-policy.md).

## Reversal limits

File rollback restores captured file existence, contents, and permission mode only when the current file still matches the managed write. It does not preserve ACLs or extended attributes. APT rollback attempts to restore recorded package versions and installation states; repositories and dependencies may have changed, so the result can be partial. `apt_update` and generic commands have no rollback.

Every reversal is a compensating operation. It cannot undo external effects such as service actions performed by package scripts, file reads, network requests, or manual changes outside the captured state.

## Encryption and retention

The control plane encrypts sensitive job and reversal payloads with an operator-managed 32-byte key mounted at runtime. The key is not stored in PostgreSQL. Active audit and reversal records expire after seven days. The local stdio APT store uses a separate private key and also expires its active records after seven days.

The seven-day rule applies to application records. Database backups may retain older encrypted pages and are controlled by the operator's backup policy. Keep a protected key backup for the full period that retained encrypted data may need to be restored. A lost or replaced key makes those records undecryptable.

## Extension requests

The Go runtime is the single source of host-operation policy. A third-party package API or a broader use case needs an independent demand assessment before implementation. Prefer direct counts of requested users where available; record the source and date. When direct counts are unavailable, use dated public proxies such as downloads, deployments, and active issues, and label their confidence. Record accepted divergence from Canonical's documentation structure in an ADR.

See [Host action safety, approval, and reversal](../adr/0004-host-action-safety-and-reversal.md) and [Encrypted audit and seven-day retention](../adr/0005-encrypted-audit-and-seven-day-retention.md) for the accepted design decisions.
