# Host action safety, approval, and reversal

Status: Accepted

## Context

System administration can expose private data or change a host's state. A generic command string is difficult to validate, describe, audit, and reverse. Some safe operations have bounded inputs and useful compensating actions; others do not.

## Decision

Expose narrow typed tools for supported system, file, package, and host operations. File access is denied outside operator-configured host paths; the default path scope is the agent user's home directory. File writes capture existence, bytes, and mode before changing state. Rollback restores those values only when the agent is authorized to do so; do not claim that ACLs or extended attributes are preserved in v0.1.

Expose `execute_command` only as direct argv, never through a shell. Require an exact per-host executable path and exact argument-vector allowlist, with an optional exact working-directory allowlist. Reject shell and privilege-launcher executables, symlink paths, and invalid or writable executable files. Keep sudo disabled unless the operator enables a particular rule, the executable path is root-owned and protected from group/other writes, and matching non-interactive OS sudoers permission exists. Bound execution time and combined output, redact common credential patterns, and mark generic command execution non-reversible. Register the tool only behind the HTTP control-plane `ALLOW_COMMAND_EXECUTION` gate.

APT maintenance in v0.1 is limited to index refresh, install, remove, and upgrade from existing configured repositories. Repository changes, full-upgrade, autoremove, purge, and reboots are outside the default policy and require separate explicit gating. Capture the installed package state before typed APT writes. Reversal is compensating and best-effort: a prior version may no longer be available, and dependency changes may prevent an exact restore. Report partial or failed reversal clearly.

The unprivileged agent does not receive direct sudo permission for `/usr/bin/apt-get`. It invokes a root-owned `apt-helper` subcommand from the installed Go binary. The helper validates the exact operation-specific argv and a separate root-owned package policy before running `/usr/bin/apt-get`. The host-agent policy, root helper policy, and HTTP control-plane `ALLOW_APT_WRITES` gate are independent checks. Local stdio APT tools remain unregistered unless an operator supplies an explicit bounded policy and private encryption key.

ChatGPT-connected write calls require per-call human confirmation in the client. Tool annotations are advisory; the server cannot verify that a client displayed the prompt. Every request must also pass server-side identity, tenant, and host policy. Local stdio automation may run only bounded package operations when the operator explicitly enables that policy; generic command execution is not registered over local stdio and remains disabled on HTTP unless an operator enables both the control-plane gate and a host-specific exact policy.

## Alternatives considered

- Arbitrary shell access: rejected because argument parsing, shell expansion, and side effects make it unsafe to authorize or reverse reliably.
- Claim exact rollback for every write: rejected because package repositories, dependencies, and external host state can change after the original operation.
- Permit autonomous writes by default: rejected because host changes need visible operator control.

## Consequences

Tool schemas and descriptions must identify read-only, mutating, destructive, and non-reversible behavior accurately. Tests must exercise authorization, path traversal, symlink, allowlist, confirmation, interrupted execution, partial rollback, and idempotency cases. Unsupported requests must return an explicit limitation rather than falling back to an approximate command.
