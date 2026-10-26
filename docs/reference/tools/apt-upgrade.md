# Upgrade APT packages

`apt_upgrade` upgrades one or more already-installed, explicitly allowlisted packages from the host's existing APT repositories. It uses `apt-get install --only-upgrade` with `--no-remove`, so a requested package that is not installed is rejected and APT must not remove packages to resolve the upgrade.

## Availability and approval

Over authenticated Streamable HTTP, `ALLOW_APT_WRITES=true`, the enrolled agent policy, and the root-owned APT helper policy must all allow `upgrade` and every requested package. The MCP tool is marked mutating, destructive, and open-world. Use a client that asks for per-call human confirmation.

Over local stdio, the tool is omitted by default. Both `--local-apt-policy-file` and `--local-apt-key-file` must be supplied; the tool is registered only when `upgrade` is in the local policy's `allowed_operations`. The local and root-owned helper policies must allow the packages. See [Configure APT package policy](../../how-to/configure-apt-policy.md).

MCP annotations are advisory; a server cannot verify that a client presented a human confirmation prompt.

## Request

| Field | Type | Required | Constraints |
| --- | --- | --- | --- |
| `host_id` | string | HTTP only | Active host identifier in the authenticated operator's personal tenant. Omit for stdio. |
| `packages` | array of strings | Yes | One to 20 unique, already-installed Debian package names, each in both allowlists. |

Package names use lowercase Debian package-name syntax with an optional architecture qualifier. Names beginning with an option character, names containing `=`, and shell metacharacters are rejected.

## Result and limits

The result contains `action_id`, `operation`, `outcome`, `changed_packages`, `rollback_available`, `expires_at`, and an optional safe `reason`. HTTP results also include `host_id`, `hostname`, and `requested_at`; local stdio omits those fields.

The encrypted audit record captures installed package state before and after the operation, including detected dependency changes. It expires after seven days. A rollback can be partial when an old version is no longer in configured repositories or a dependency is outside the root-owned package allowlist. See Ubuntu's [`apt-get` reference](https://manpages.ubuntu.com/manpages/resolute/man8/apt-get.8.html) for `--only-upgrade` and `--no-remove`.

## Example

```json
{"host_id":"c0c326bc-cf08-4e15-98dc-cf8b5fa8d66d","packages":["curl"]}
```

Omit `host_id` for local stdio.
