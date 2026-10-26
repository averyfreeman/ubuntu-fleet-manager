# Host agent configuration

The host agent stores its control-plane URL, host identity, bearer credential, and local file boundaries in a private JSON file. The default file path is in the agent user's configuration directory; operators can pass `--config PATH` to `agent enroll` and `agent run` to select another path. The file is created with mode `0600` and is limited to 16 KiB total.

## Configuration fields

| Field | Type | Description |
| --- | --- | --- |
| `server_url` | string | HTTPS control-plane base URL; plain HTTP is accepted only for loopback development. |
| `host_id` | string | Host identifier assigned during enrollment. |
| `credential` | string | Host-scoped bearer credential. Keep the file private; the credential is returned only during enrollment. |
| `allowed_paths` | array of strings | Existing absolute directories the agent may use for `list_directory` and `read_file`. |
| `writable_paths` | array of strings | Existing absolute directories the agent may use for reversible file writes. Missing or empty means no write access. |
| `apt_policy` | object | Explicit package-operation and package-name allowlists. Missing or disabled means all APT writes are denied. |
| `command_policy` | object | Exact executable and argument-vector allowlist for `execute_command`. Missing or disabled means all generic commands are denied. |

Example:

```json
{
  "server_url": "https://fleet.example.com",
  "host_id": "c0c326bc-cf08-4e15-98dc-cf8b5fa8d66d",
  "credential": "ufm_host_REDACTED",
  "allowed_paths": [
    "/var/lib/ubuntu-fleet-manager",
    "/srv/application-config"
  ],
  "writable_paths": [
    "/srv/application-config"
  ],
  "apt_policy": {
    "enabled": true,
    "allowed_operations": ["install", "rollback", "update"],
    "allowed_packages": ["curl"]
  },
  "command_policy": {
    "enabled": true,
    "rules": [
      {
        "executable": "/usr/bin/systemctl",
        "allowed_arguments": [["show", "--property=Version"]],
        "working_directories": ["/"]
      }
    ]
  }
}
```

If `allowed_paths` is missing or empty, reads default to the agent user's home directory. If `writable_paths` is missing or empty, all file writes are denied. Each configured entry must be an absolute existing directory. The agent resolves symlinks when loading and saving configuration and removes duplicate canonical paths. If `apt_policy` is missing or disabled, all APT writes are denied.

## Enrollment options

The enrollment command accepts repeatable `--allowed-path DIR`, `--writable-path DIR`, `--apt-operation ACTION`, and `--apt-package NAME` flags:

```text
ubuntu-fleet-manager agent enroll --server HTTPS_URL \
  (--pairing-code CODE | --pairing-code-stdin) \
  [--config PATH] [--allowed-path DIR ...] [--writable-path DIR ...] \
  [--apt-operation ACTION ...] [--apt-package NAME ...]
```

Use the default home boundary unless the host operator has a reason to expose another directory. Stop the agent before editing an existing `allowed_paths` array, keep the config file at mode `0600`, and restart the service after the change. The systemd filesystem sandbox must also permit access to each configured path.

Grant write access only to directories the operator has approved for modification. Pass `--writable-path DIR` once for each existing directory during enrollment. Alternatively, stop the agent, edit `writable_paths` in its private config file, and restart it. The systemd unit must include a matching `ReadWritePaths=` entry while retaining `ProtectSystem=strict`; the host policy and systemd sandbox are independent enforcement layers. Installing `--writable-path` does not expose MCP write tools unless the control plane also sets `ALLOW_FILE_WRITES=true`.

Pass `--apt-operation ACTION` once for each allowed operation and `--apt-package NAME` once for each allowed package. Both default to none. The agent policy does not grant sudo access; configure the root helper and host policy separately before enabling APT tools. See [Configure APT package policy](../how-to/configure-apt-policy.md) for the required root-owned policy and systemd changes.

The read boundaries apply only to `list_directory` and `read_file`; the separate write boundaries apply only to `write_file` and `rollback_file`. They do not change APT's configured package indexes or package state. See [Enroll and run a host agent](../how-to/enroll-host-agent.md) for the service setup.

`apt_policy` accepts `update`, `install`, `remove`, `upgrade`, and `rollback`. Package names are required when any install, remove, or upgrade operation is enabled. A request is limited to 20 unique packages, and the host policy can list at most 500. The agent never accepts an arbitrary APT command string. The typed operations call `/usr/local/bin/ubuntu-fleet-manager apt-helper` through non-interactive sudo; the root-owned helper checks its own stricter `/etc/ubuntu-fleet-manager/apt-policy.json` before running `/usr/bin/apt-get`.

The helper must be installed root-owned at the documented path, and the host must have the dedicated sudo rule and systemd settings described in [Configure APT package policy](../how-to/configure-apt-policy.md). These OS controls are independent of the agent's `apt_policy` and the control-plane `ALLOW_APT_WRITES` setting.

`command_policy` must be explicitly enabled and contain one or more rules. Each `executable` is a full absolute path to an existing regular executable; aliases and symlink paths are rejected. Every rule lists one or more exact `allowed_arguments` arrays. Arguments are compared literally, so every permitted argument sequence needs its own array. Shell metacharacters have no special meaning, but shells, privilege launchers, and environment wrappers are refused as executables. Rules may contain at most 64 arguments per vector, 4,096 UTF-8 bytes per argument, 100 vectors, and 100 executable rules.

`working_directories`, when present, lists the exact absolute directories allowed for a request's `working_directory`. A requested directory must exist and must not be a symlink. For a sudo-backed rule, every allowed working directory must also be root-owned and not writable by group or others. If a request omits `working_directory`, an unprivileged command inherits the agent process's current directory; a sudo-backed command runs from `/`. An empty or missing `command_policy` denies every command.

`use_sudo` defaults to `false`. When `true`, the executable and every parent directory must be root-owned and not writable by group or others. The agent invokes `/usr/bin/sudo -n -- EXECUTABLE ARGUMENTS`; configure an OS sudoers entry that matches the same executable and exact argument sequence. The agent does not inspect sudoers, and `-n` causes the operation to fail rather than prompt. The default systemd unit uses `NoNewPrivileges=yes`, which blocks privilege elevation; see [Configure constrained command execution](../how-to/configure-command-policy.md) before enabling a sudo-backed rule.

Generic commands have no rollback. The process is stopped after 30 seconds, and the combined standard output and standard error returned to MCP are limited to 64 KiB. Common credential patterns are redacted before results are stored or returned; this heuristic does not guarantee that all sensitive output is removed. See [Execute an allowlisted command](tools/execute-command.md) for the tool contract and [Configure constrained command execution](../how-to/configure-command-policy.md) for a host policy example.
