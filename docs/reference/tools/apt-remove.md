# Remove APT packages

`apt_remove` removes one or more explicitly allowlisted packages with `apt-get remove`. APT leaves package configuration files behind. The tool does not expose `purge`, `autoremove`, or arbitrary APT options.

## Availability and approval

Over authenticated Streamable HTTP, `ALLOW_APT_WRITES=true`, the enrolled agent policy, and the root-owned APT helper policy must all allow `remove` and every requested package. The MCP tool is marked mutating, destructive, and open-world. Use a client that asks for per-call human confirmation.

Over local stdio, the tool is omitted by default. Both `--local-apt-policy-file` and `--local-apt-key-file` must be supplied; the tool is registered only when `remove` is in the local policy's `allowed_operations`. The local and root-owned helper policies must allow the packages. See [Configure APT package policy](../../how-to/configure-apt-policy.md).

MCP annotations are advisory; a server cannot verify that a client presented a human confirmation prompt.

## Request

| Field | Type | Required | Constraints |
| --- | --- | --- | --- |
| `host_id` | string | HTTP only | Active host identifier in the authenticated operator's personal tenant. Omit for stdio. |
| `packages` | array of strings | Yes | One to 20 unique Debian package names, each in both allowlists. |

Package names use lowercase Debian package-name syntax with an optional architecture qualifier. Names beginning with an option character, names containing `=`, and shell metacharacters are rejected. APT may remove packages needed by the requested change; those package-state changes are captured when possible and may limit rollback.

## Result and limits

The result contains `action_id`, `operation`, `outcome`, `changed_packages`, `rollback_available`, `expires_at`, and an optional safe `reason`. HTTP results also include `host_id`, `hostname`, and `requested_at`; local stdio omits those fields.

The encrypted audit record captures installed package state before and after the operation. It expires after seven days. Rollback is available only when captured state fits the bounded record and the host policy permits rollback. It will not purge configuration files; `purge` and `autoremove` are not exposed. See Ubuntu's [`apt-get` reference](https://manpages.ubuntu.com/manpages/resolute/man8/apt-get.8.html) for the difference between `remove`, `purge`, and `autoremove`.

Rollback attempts to restore only allowlisted package states that still match the state recorded after the managed operation. A later package change is preserved. Missing repository versions and dependency constraints produce a partial result. See [Roll back an APT action](rollback-apt-action.md).

## Example

Remote request:

```json
{"host_id":"c0c326bc-cf08-4e15-98dc-cf8b5fa8d66d","packages":["jq"]}
```

Local stdio request:

```json
{"packages":["jq"]}
```
