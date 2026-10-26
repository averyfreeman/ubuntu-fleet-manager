# Configure constrained command execution

This procedure enables `execute_command` for exact command vectors on enrolled hosts. Keep the control-plane gate and every host policy disabled until the executable, arguments, working directory, and any sudo access have been reviewed.

## Before you begin

- Enroll the target host and run the agent as the dedicated unprivileged `ubuntu-fleet-agent` account. See [Enroll and run a host agent](enroll-host-agent.md).
- Configure the MCP client to request confirmation for destructive tools. In ChatGPT, set the connected app or account permission to **Always ask**; workspace Agents have separate per-agent approval controls. ChatGPT's confirmation behavior depends on app permissions and action context, so the server cannot verify that a client displayed a prompt. See OpenAI's [Managing app permissions in ChatGPT](https://help.openai.com/en/articles/20001495-managing-app-permissions-in-chatgpt).
- Identify the canonical executable path on the target host. The agent rejects symlink paths, shell executables, privilege launchers, and environment wrappers.

## Add an exact host allowlist

Stop the agent before changing its private configuration file:

```sh
sudo systemctl stop ubuntu-fleet-agent.service
sudoedit /var/lib/ubuntu-fleet-manager/agent.json
```

Add a `command_policy` object next to `server_url`, `host_id`, and the other top-level settings. The example permits a read-only `systemctl` query and one separately approved service restart:

```json
"command_policy": {
  "enabled": true,
  "rules": [
    {
      "executable": "/usr/bin/systemctl",
      "allowed_arguments": [["show", "--property=Version"]],
      "working_directories": ["/"]
    },
    {
      "executable": "/usr/bin/systemctl",
      "allowed_arguments": [["restart", "my-service.service"]],
      "working_directories": ["/"],
      "use_sudo": true
    }
  ]
}
```

Each vector is an exact list of arguments. Adding a general form such as `systemctl` with arbitrary units is not supported; add one reviewed vector for each service action the host should permit. An omitted `working_directory` runs with the agent process's current directory. A supplied directory must be an exact entry in `working_directories`.

The executable and its parent directories must exist, resolve to the same canonical path, and not be writable by group or others. For a sudo-backed rule, every component must also be root-owned. A sudo rule's configured working directories must meet the same ownership and write restrictions; if the request omits its working directory, the command runs from `/`. The agent permits up to 100 executable rules, 100 argument vectors per rule, 64 arguments per vector, and 4,096 bytes per argument. Keep the policy smaller and narrower than these limits.

The configuration file contains the host credential. Keep it owned by `ubuntu-fleet-agent` with mode `0600`:

```sh
sudo chown ubuntu-fleet-agent:ubuntu-fleet-agent /var/lib/ubuntu-fleet-manager/agent.json
sudo chmod 0600 /var/lib/ubuntu-fleet-manager/agent.json
```

## Configure sudo only when required

The agent calls `/usr/bin/sudo -n -- EXECUTABLE ARGUMENTS` when a matching rule sets `use_sudo` to `true`. It does not inspect sudoers; the OS policy must permit the same full executable path and exact argument sequence without a password prompt. On Ubuntu, create and validate a dedicated sudoers file:

```sh
sudo visudo -f /etc/sudoers.d/ubuntu-fleet-agent-command
```

For the example restart rule, the entry is:

```sudoers
ubuntu-fleet-agent ALL=(root) NOPASSWD: /usr/bin/systemctl restart my-service.service
```

Validate the file before restarting the agent:

```sh
sudo chmod 0440 /etc/sudoers.d/ubuntu-fleet-agent-command
sudo visudo -cf /etc/sudoers.d/ubuntu-fleet-agent-command
```

Sudoers command entries without an argument list may permit arbitrary arguments, so specify the complete reviewed vector. Ubuntu's current [`sudoers-rs` reference](https://manpages.ubuntu.com/manpages/resolute/man5/sudoers-rs.5.html) documents exact argument matching and the absence of argument wildcards in sudo-rs.

The example agent unit has `NoNewPrivileges=yes`, which prevents sudo from elevating. If a rule uses sudo, add a service drop-in that changes only this setting:

```sh
sudo systemctl edit ubuntu-fleet-agent.service
```

```ini
[Service]
NoNewPrivileges=no
```

Keep the agent account unprivileged and retain `ProtectSystem=strict`. Systemd's filesystem and device sandbox remains in force for the elevated command and may block an otherwise allowed action. Add only the narrow systemd exceptions that the reviewed command needs.

## Enable the HTTP tool

Set the control-plane environment variable:

```dotenv
ALLOW_COMMAND_EXECUTION=true
```

Restart the control plane. It then registers `execute_command` for authenticated operators. The environment gate only controls tool registration; each target host's `command_policy` still decides whether a request runs. The operation is marked destructive, non-idempotent, and open-world, has no rollback, and is limited to 30 seconds and 64 KiB of combined output. Common credential patterns are redacted heuristically. See [Control plane configuration](../reference/control-plane-configuration.md), [Host agent configuration](../reference/host-agent-configuration.md), and [Execute an allowlisted command](../reference/tools/execute-command.md).

The local stdio server does not register `execute_command`. If the MCP client does not request human confirmation for destructive tools, leave the control-plane gate disabled.

## Restart and verify the agent

Reload systemd if you changed the service unit, then start the agent:

```sh
sudo systemctl daemon-reload
sudo systemctl start ubuntu-fleet-agent.service
sudo systemctl status ubuntu-fleet-agent.service
```

Call `execute_command` with one exact configured vector and, if required, its exact allowed working directory. Test denied vectors in a non-production host first. The control plane returns a policy error if the host denies a command; command output and runner error text are not returned for denied execution.

To disable command execution, set `command_policy.enabled` to `false` on the host, or set `ALLOW_COMMAND_EXECUTION=false` on the control plane. Keep both controls off when generic command execution is not required.
