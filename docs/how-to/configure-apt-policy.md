# Configure APT package policy

This procedure enables typed APT maintenance for an enrolled host or a local stdio server. APT writes are disabled unless the control plane or local stdio configuration opts in, the agent has a package allowlist, the root-owned helper has an independent package allowlist, and the OS sudo policy permits only the helper.

Package installation executes trusted package maintainer scripts with root privileges. Allow only packages from repositories the operator trusts. The APT tools do not modify repository sources, run `full-upgrade`, run `autoremove`, purge packages, or reboot the host.

## Before you begin

- Build the Linux `ubuntu-fleet-manager` binary and install it at `/usr/local/bin/ubuntu-fleet-manager` as root-owned mode `0755`.
- Choose a dedicated unprivileged host-agent account.
- Review the packages and operations that account may manage.
- For HTTP, configure `ALLOW_APT_WRITES=true` only after the agent and root policies are ready. For local stdio, prepare a private policy file and encryption key.

## Install the root-owned package policy

Create `/etc/ubuntu-fleet-manager/apt-policy.json` owned by root and readable only by root. This is a second allowlist enforced after the agent policy. The helper reads it only after sudo starts the same binary as root.

```sh
sudo install -d -o root -g root -m 0755 /etc/ubuntu-fleet-manager
sudo install -o root -g root -m 0600 /dev/null /etc/ubuntu-fleet-manager/apt-policy.json
sudoedit /etc/ubuntu-fleet-manager/apt-policy.json
```

Example policy:

```json
{
  "enabled": true,
  "allowed_operations": ["install", "remove", "rollback", "upgrade", "update"],
  "allowed_packages": ["curl", "jq"]
}
```

The file must be one strict JSON object, owned by root, and have mode `0400` or `0600`. Package names must be valid Debian package names. Install, remove, or upgrade requires at least one package in the allowlist. Rollback must be paired with at least one allowed mutating package operation. Update does not require package names.

The helper accepts only the fixed argv layouts used for update, install, remove, upgrade, and rollback. It then invokes `/usr/bin/apt-get` directly without a shell. The sudo rule below permits the `apt-helper` subcommand with arguments because the helper validates each operation and package against the root-owned policy. It does not grant direct access to `/usr/bin/apt-get`. See the Ubuntu [`sudoers-rs` reference](https://manpages.ubuntu.com/manpages/resolute/man5/sudoers-rs.5.html) for command and argument matching.

## Add the sudo rule

Create a sudoers file with `visudo` and replace the username with the agent account:

```sh
sudo visudo -f /etc/sudoers.d/ubuntu-fleet-manager-apt
```

Add this single command rule:

```sudoers
ubuntu-fleet-agent ALL=(root) NOPASSWD: /usr/local/bin/ubuntu-fleet-manager apt-helper
```

Validate it:

```sh
sudo visudo -cf /etc/sudoers.d/ubuntu-fleet-manager-apt
sudo -u ubuntu-fleet-agent sudo -n -l /usr/local/bin/ubuntu-fleet-manager
```

Ubuntu 26.04 uses `sudo-rs`; in that syntax, a command entry without an argument list allows arguments for that exact command. The root-owned helper rejects any subcommand or APT argument sequence outside its typed operations and root policy. Do not add a direct `/usr/bin/apt-get` rule or a broader `ALL` rule. See the Ubuntu [`sudoers-rs` reference](https://manpages.ubuntu.com/manpages/resolute/man5/sudoers-rs.5.html).

## Configure an enrolled host agent

Pass the requested operations and packages during enrollment. Repeat each flag for each value:

```sh
sudo -u ubuntu-fleet-agent /usr/local/bin/ubuntu-fleet-manager agent enroll \
  --server https://fleet.example.com \
  --pairing-code-stdin \
  --config /var/lib/ubuntu-fleet-manager/agent.json \
  --apt-operation update \
  --apt-operation install \
  --apt-operation remove \
  --apt-operation upgrade \
  --apt-operation rollback \
  --apt-package curl \
  --apt-package jq
```

The agent stores `apt_policy` in its private configuration file. Omit all `--apt-operation` and `--apt-package` flags to keep the agent package policy disabled. Keep the root policy at least as restrictive as the agent policy; both are checked before an APT write.

The default host-agent systemd unit uses `NoNewPrivileges=yes` and `ProtectSystem=strict`, which prevents the sudo helper from gaining root privileges and prevents APT from writing system package files. For a host that explicitly enables APT maintenance, install this systemd drop-in:

```sh
sudo systemctl edit ubuntu-fleet-agent.service
```

```ini
[Service]
NoNewPrivileges=no
ProtectSystem=no
```

Then reload and restart the agent:

```sh
sudo systemctl daemon-reload
sudo systemctl restart ubuntu-fleet-agent.service
```

This relaxes the service filesystem sandbox because package installation writes system files and runs package maintainer scripts as root. Keep the service account unprivileged, keep the root-owned helper and allowlist private to root, and keep the sudoers entry limited to that helper. Review every allowed package and repository as a root-level change.

## Enable APT tools over HTTP

Set this in the control-plane `.env` file:

```dotenv
ALLOW_APT_WRITES=true
```

Restart the control plane. It then registers `apt_update`, `apt_install`, `apt_remove`, `apt_upgrade`, and `rollback_apt_action`. Each tool is marked mutating, destructive, and open-world; the MCP client must present per-call human confirmation. The control plane also checks tenant and host authorization, and the agent and root helper recheck their separate policies.

The control plane encrypts the APT audit and rollback payload using `FILE_ACTION_KEY_FILE`, the same private 32-byte key used for reversible file actions. Completed job input and result data are cleared after the encrypted package action record is stored. The record expires after seven days; PostgreSQL backups may retain older encrypted pages. See [Control plane configuration](../reference/control-plane-configuration.md).

## Enable APT tools over local stdio

Create a private local policy file owned by the MCP user's account:

```sh
mkdir -p ~/.config/ubuntu-fleet-manager
chmod 0700 ~/.config/ubuntu-fleet-manager
cat > ~/.config/ubuntu-fleet-manager/apt-policy.json <<'EOF'
{
  "enabled": true,
  "allowed_operations": ["install", "rollback", "update"],
  "allowed_packages": ["curl"]
}
EOF
chmod 0600 ~/.config/ubuntu-fleet-manager/apt-policy.json
```

Create a private 32-byte AES key for the local encrypted action store:

```sh
umask 077
openssl rand -out ~/.config/ubuntu-fleet-manager/apt-action-key 32
chmod 0600 ~/.config/ubuntu-fleet-manager/apt-action-key
```

Configure the MCP client to launch the binary with both flags:

```text
ubuntu-fleet-manager --transport stdio \
  --local-apt-policy-file /home/USER/.config/ubuntu-fleet-manager/apt-policy.json \
  --local-apt-key-file /home/USER/.config/ubuntu-fleet-manager/apt-action-key
```

Without both flags, local APT tools are not registered. With both flags, stdio registers only the operations named in `allowed_operations`; package-changing tools also enforce the local package allowlist. Local actions use the same root-owned helper policy and sudo rule as an enrolled host. The encrypted action store is written under the user's configuration directory and expires after seven days.
