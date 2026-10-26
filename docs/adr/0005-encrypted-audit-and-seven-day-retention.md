# Encrypted audit and seven-day retention

Status: Accepted

## Context

Rollback requires pre-state and operation results to remain available, but system snapshots and audit records may contain sensitive host data. The self-hosted proof of concept needs a finite retention policy and must not collect usage telemetry by default.

## Decision

Retain full audit and reversal payloads for seven days, then delete them from the active application store and expire their encryption keys when no longer referenced. Encrypt sensitive audit and pre-state payloads at the application layer with an operator-managed key supplied through a mounted secret file; do not store the key in PostgreSQL. Redact access tokens, host credentials, and secret values before logging. Do not store raw conversation prompts or collect product telemetry by default.

The seven-day limit applies to the application's active store. Operator-managed backups may retain older encrypted database pages; document that backup retention must be configured separately. Assess adoption later using direct counts where available and dated, confidence-labeled public proxies such as downloads, deployments, and active issues. Any longer-retention or paid plan requires a later product decision.

## Alternatives considered

- Keep audit and rollback data indefinitely: rejected for the proof of concept because of storage and privacy cost.
- Depend solely on disk encryption: rejected because database exports and backups can leave the encrypted host volume.
- Collect default telemetry to measure adoption: rejected because this version is fully self-hosted and telemetry has not been authorized.

## Consequences

The deployment must fail closed when the encryption key is absent or invalid. Backups need the operator-managed key to restore encrypted audit data. Retention cleanup and key lifecycle require automated tests. Documentation must distinguish the seven-day application policy from operator-controlled backups.
