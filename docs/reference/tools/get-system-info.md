# Get system information

`get_system_info` returns a snapshot of operating system, kernel, memory, and root filesystem information for the Linux host running the MCP server. The Go runtime is intended first for Ubuntu; other Linux distributions may work but are not currently a supported target.

## Request

The tool accepts no arguments. Requests with additional properties are rejected.

The MCP tool is marked read-only, idempotent, and closed-world. It does not run a command or make a host change.

## Result

The response is MCP structured content with these fields:

| Field | Type | Description |
| --- | --- | --- |
| `os` | object | Distribution values read from `/etc/os-release`. |
| `hostname` | string | Hostname returned by the operating system. |
| `kernel` | object | Kernel name and release. |
| `architecture` | string | Go architecture name, such as `amd64` or `arm64`. |
| `memory` | object | Physical memory and the kernel's estimate of memory available to applications. |
| `root_filesystem` | object | Capacity and usage for the filesystem containing `/`. |
| `collected_at` | string | UTC timestamp in RFC 3339 format. |

The `os` object contains `id`, `pretty_name`, and `version_id` strings. It also contains `version_codename` when `/etc/os-release` provides one.

The `kernel` object contains `name` and `release` strings.

The `memory` object contains `total_bytes` and `available_bytes` unsigned integers. The available value is Linux's `MemAvailable` estimate, converted from KiB to bytes.

The `root_filesystem` object contains `total_bytes`, `used_bytes`, `free_bytes`, and `available_bytes` unsigned integers. Values are in bytes. `free_bytes` includes reserved filesystem blocks; `available_bytes` reports the blocks available to the process running the server.

Example:

```json
{
  "os": {
    "id": "ubuntu",
    "pretty_name": "Ubuntu 26.04 LTS",
    "version_id": "26.04",
    "version_codename": "resolute"
  },
  "hostname": "example-host",
  "kernel": {
    "name": "Linux",
    "release": "6.14.0-example"
  },
  "architecture": "amd64",
  "memory": {
    "total_bytes": 8589934592,
    "available_bytes": 4294967296
  },
  "root_filesystem": {
    "total_bytes": 107374182400,
    "used_bytes": 21474836480,
    "free_bytes": 85899345920,
    "available_bytes": 81604378624
  },
  "collected_at": "2026-10-26T12:00:00Z"
}
```

## Errors

The tool returns an MCP tool error if a required system value cannot be read or parsed. The error content describes the failed collection step. The server does not return a partial snapshot.

## Data sources

The implementation reads `/etc/os-release`, the hostname, `uname` information, `/proc/meminfo`, and `statfs` for `/`. Values are collected from the local Linux host; the tool does not make network requests.

For Ubuntu Server administration guidance, see the official [system requirements reference](https://documentation.ubuntu.com/server/reference/installation/system-requirements/) and the [Ubuntu Server documentation](https://documentation.ubuntu.com/server/).
