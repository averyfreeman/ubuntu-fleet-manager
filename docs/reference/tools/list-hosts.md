# List managed hosts

`list_hosts` returns the hosts in the authenticated operator's personal tenant. The control plane creates that tenant the first time it accepts an authenticated MCP request from the issuer and subject pair.

## Request

| Field | Type | Description |
| --- | --- | --- |
| `limit` | integer | Optional page size. The default is 50; accepted values are 1 through 200. |
| `cursor` | string | Optional opaque cursor from the previous page. |

The cursor is scoped by the authenticated tenant and the query always filters by that tenant. A cursor from another user cannot expose another tenant's hosts.

## Result

The structured result contains `hosts`, an array of host records, and `next_cursor` when another page is available. An empty inventory returns an empty `hosts` array and no cursor.

Each host record contains:

| Field | Type | Description |
| --- | --- | --- |
| `id` | string | Host identifier. |
| `hostname` | string | Host's reported hostname. |
| `os_pretty_name` | string | Human-readable operating system name. |
| `enrolled_at` | string | UTC enrollment time in RFC 3339 format. |
| `last_seen_at` | string | UTC time when the host last contacted the control plane. |

Example:

```json
{
  "hosts": [
    {
      "id": "c0c326bc-cf08-4e15-98dc-cf8b5fa8d66d",
      "hostname": "web-01",
      "os_pretty_name": "Ubuntu 26.04 LTS",
      "enrolled_at": "2026-10-26T12:00:00Z",
      "last_seen_at": "2026-10-26T12:10:00Z"
    }
  ],
  "next_cursor": "opaque-cursor-value"
}
```

Hosts enter the active inventory after an agent redeems a one-time code created by `create_pairing_code`. Removed hosts do not appear in `list_hosts`. See [Enroll and run a host agent](../../how-to/enroll-host-agent.md) to enroll a host.
