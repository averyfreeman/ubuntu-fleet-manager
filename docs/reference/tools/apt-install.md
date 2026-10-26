# Install APT packages

`apt_install` installs one or more explicitly allowlisted packages from the host's existing APT repositories. The operation may also install required dependencies. It uses `--no-remove` and `--no-install-recommends`; it does not expose arbitrary APT options or repository configuration.

## Availability and approval

Over authenticated Streamable HTTP, `ALLOW_APT_WRITES=true`, the enrolled agent policy, and the root-owned APT helper policy must all allow `install` and every requested package. The MCP tool is marked mutating, destructive, and open-world. Use a client that asks for per-call human confirmation.

Over local stdio, the tool is omitted by default. Both `--local-apt-policy-file` and `--local-apt-key-file` must be supplied; the tool is registered only when `install` is in the local policy's `allowed_operations`. The local and root-owned helper policies must allow the packages. See [Configure APT package policy](../../how-to/configure-apt-policy.md).

MCP annotations are advisory; a server cannot verify that a client presented a human confirmation prompt.

## Request

| Field | Type | Required | Constraints |
| --- | --- | --- | --- |
| `host_id` | string | HTTP only | Active host identifier in the authenticated operator's personal tenant. Omit for stdio. |
| `packages` | array of strings | Yes | One to 20 unique Debian package names. Each name must be in both operation-specific allowlists. |

Package names use lowercase Debian package-name syntax with an optional architecture qualifier. Names beginning with an option character, names containing `=`, and shell metacharacters are rejected. The agent policy can contain at most 500 package names.

The unprivileged agent invokes `/usr/local/bin/ubuntu-fleet-manager apt-helper install ...` through non-interactive `sudo`. The helper loads `/etc/ubuntu-fleet-manager/apt-policy.json`, validates the exact argument sequence and package allowlist, then invokes `/usr/bin/apt-get` with direct argv. It does not invoke a shell or use a caller-provided command string.

## Result

The result contains `action_id`, `operation`, `outcome`, `changed_packages`, `rollback_available`, `expires_at`, and an optional safe `reason`. HTTP results also include `host_id`, `hostname`, and `requested_at`; local stdio omits those fields.

The encrypted audit record captures installed package state before and after the action. It includes dependency changes detected in `dpkg` state. `rollback_available` is true only when the captured state fits the bounded record and the host policy permits rollback. The record expires after seven days.

If APT needs to remove a package while resolving dependencies, `--no-remove` makes it abort. Disabling recommended packages does not suppress required dependencies. A package's maintainer scripts run with package-manager privileges, so allow only trusted packages from trusted configured repositories. See Ubuntu's [`apt-get` reference](https://manpages.ubuntu.com/manpages/resolute/man8/apt-get.8.html) for the behavior of `--no-remove` and `--no-install-recommends`.

Rollback is compensating, not a snapshot restore. The root helper only permits packages from its root-owned allowlist. A changed dependency outside the allowlist or an unavailable old version can make rollback partial. Later changes are preserved. See [Roll back an APT action](rollback-apt-action.md).

## Example

Remote request:

```json
{"host_id":"c0c326bc-cf08-4e15-98dc-cf8b5fa8d66d","packages":["curl","jq"]}
```

Local stdio request:

```json
{"packages":["curl","jq"]}
```
