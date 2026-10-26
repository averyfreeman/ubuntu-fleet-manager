# Enroll and run a host agent

Use this procedure to enroll one Ubuntu host and have its unprivileged agent report liveness to a self-hosted control plane. The agent starts outbound HTTPS requests; it does not listen on a host port. APT operations require a separately configured root-owned helper and sudo policy; see [Configure APT package policy](configure-apt-policy.md).

## Before you begin

- Deploy the control plane and configure its public HTTPS URL. See [Deploy the self-hosted control plane](deploy-control-plane.md).
- Connect an MCP client to the control plane with an operator account.
- Install the `ubuntu-fleet-manager` Go binary on the host. It must be built for Linux.
- Create a dedicated unprivileged account for the agent.

Build and install the binary if Go is available on the host:

```sh
go build -o ./build/ubuntu-fleet-manager ./cmd/ubuntu-fleet-manager
sudo install -o root -g root -m 0755 ./build/ubuntu-fleet-manager /usr/local/bin/ubuntu-fleet-manager
```

Create an account and private configuration directory for the agent:

```sh
sudo useradd --system --create-home --home-dir /var/lib/ubuntu-fleet-manager --shell /usr/sbin/nologin ubuntu-fleet-agent
sudo install -d -o ubuntu-fleet-agent -g ubuntu-fleet-agent -m 0700 /var/lib/ubuntu-fleet-manager
```

## Create a pairing code

Call the authenticated MCP tool `create_pairing_code`. The result contains a one-time code that expires after ten minutes. Keep the code private and use it only on the host you intend to enroll.

## Enroll as the agent account

On the Ubuntu host, enter the code without echoing it, then pass it through standard input so it does not appear in command arguments or shell history:

```sh
printf 'Pairing code: ' >&2
read -r -s UFM_PAIRING_CODE
printf '\n' >&2
printf '%s\n' "$UFM_PAIRING_CODE" | sudo -u ubuntu-fleet-agent /usr/local/bin/ubuntu-fleet-manager agent enroll \
  --server https://fleet.example.com \
  --pairing-code-stdin \
  --config /var/lib/ubuntu-fleet-manager/agent.json
unset UFM_PAIRING_CODE
```

The agent's default read boundary is its own home directory, `/var/lib/ubuntu-fleet-manager`. To grant read-only access to other existing directories, append these flags to the enrollment command and repeat them for each directory:

```sh
  --allowed-path /srv/application-config \
  --allowed-path /var/log/application
```

Each path must be an absolute existing directory; the agent resolves configured symlinks when it saves the configuration. The paths are stored in the local agent configuration and enforced by the agent for `list_directory` and `read_file`. For an already enrolled host, stop the service, update the `allowed_paths` array in its private JSON configuration, and start it again. Ensure the systemd filesystem sandbox also permits access to any additional paths.

The agent denies file writes unless `writable_paths` is explicitly configured. To grant a write boundary at enrollment, add `--writable-path /srv/application-config` for each approved directory. This host-side boundary is separate from the control-plane `ALLOW_FILE_WRITES=true` setting. Add matching systemd `ReadWritePaths=` entries only for approved writable directories; keep the agent unprivileged and retain `ProtectSystem=strict`.

The agent denies APT writes unless `apt_policy` is explicitly configured. Add repeatable `--apt-operation update`, `--apt-operation install`, `--apt-operation remove`, `--apt-operation upgrade`, or `--apt-operation rollback` flags and `--apt-package NAME` flags during enrollment. Configure the root-owned helper allowlist and the exact sudo rule before enabling `ALLOW_APT_WRITES=true`. The systemd example below keeps `NoNewPrivileges=yes` and `ProtectSystem=strict`, so APT writes remain unavailable until the APT guide installs its systemd drop-in. That drop-in relaxes the systemd sandbox because package operations write system files and run maintainer scripts as root.

The enrollment request includes the host's hostname and OS name. On success, the control plane returns a host-scoped credential once. The agent writes it atomically to the config file with mode `0600`; the enrollment command prints the host ID and file path, never the credential. If enrollment fails, create a new code if the original was consumed or expired.

## Run the agent with systemd

Create `/etc/systemd/system/ubuntu-fleet-agent.service`:

```ini
[Unit]
Description=Ubuntu Fleet Manager host agent
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=ubuntu-fleet-agent
Group=ubuntu-fleet-agent
ExecStart=/usr/local/bin/ubuntu-fleet-manager agent run --config /var/lib/ubuntu-fleet-manager/agent.json
Restart=on-failure
RestartSec=5s
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes

[Install]
WantedBy=multi-user.target
```

For example, add this to the unit only when `/srv/application-config` is present in `writable_paths`:

```ini
ReadWritePaths=/srv/application-config
```

Enable and start the service:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now ubuntu-fleet-agent.service
sudo systemctl status ubuntu-fleet-agent.service
```

The agent sends an immediate poll and repeats every 30 seconds. The control plane records liveness and returns `idle` when no work is queued. To request a fresh host snapshot, call [`get_host_system_info`](../reference/tools/get-host-system-info.md) with the enrolled host's ID. The control plane delivers the typed job on the existing outbound poll path; the host needs no inbound port.

## Remove a host

Call `remove_host` with the host's `host_id`. The control plane revokes the host credential immediately and removes the host from active inventory. Stop the local service separately:

```sh
sudo systemctl disable --now ubuntu-fleet-agent.service
```

The removed host's next poll is rejected. To enroll it again, create and use a new pairing code.
