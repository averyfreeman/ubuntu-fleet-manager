# Search APT packages on a managed host

`search_packages` searches the package indexes already configured on one enrolled host. It is available over authenticated Streamable HTTP and is marked read-only, idempotent, and closed-world. It does not refresh indexes, install or remove packages, or change package state.

## Request

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `host_id` | string | Yes | Identifier returned by host enrollment and `list_hosts`. |
| `query` | string | Yes | Literal text searched in package names and short descriptions; 1 to 128 bytes. |
| `limit` | integer | No | Maximum matches to return; defaults to 50 and must be between 1 and 100. |

The agent passes the query as a direct argument to `apt-cache search` after escaping it as a POSIX regular expression. It does not invoke a shell. APT's binary package caches are directed into a private temporary directory and removed after each search, so the operation does not write persistent APT caches or change installed packages. The search uses the host's configured APT indexes; the result can be stale if those indexes have not been refreshed. See the [Ubuntu `apt-cache` reference](https://manpages.ubuntu.com/manpages/resolute/man8/apt-cache.8.html), which documents that `apt-cache` queries package metadata without manipulating system package state.

## Result

The result contains `host_id`, enrollment-time `hostname`, `requested_at`, and a `search` object:

| Field | Type | Description |
| --- | --- | --- |
| `query` | string | The normalized literal query. |
| `packages` | array | Up to the requested number of package `name` and short `description` pairs. |
| `truncated` | boolean | True when more matches were available than the requested limit. |

## Example

```json
{
  "host_id": "c0c326bc-cf08-4e15-98dc-cf8b5fa8d66d",
  "query": "curl",
  "limit": 10
}
```

Example result:

```json
{
  "host_id": "c0c326bc-cf08-4e15-98dc-cf8b5fa8d66d",
  "hostname": "web-01",
  "requested_at": "2026-10-26T12:00:00Z",
  "search": {
    "query": "curl",
    "packages": [{"name": "curl", "description": "command line tool for transferring data with URL syntax"}],
    "truncated": false
  }
}
```

## Limits and errors

- Queries with control characters, an empty value, or more than 128 bytes are rejected.
- At most 100 results are returned. A configured APT command output limit and a 10-second command deadline bound the host work.
- The tool returns an MCP error when `apt-cache` is unavailable, the configured indexes cannot be queried, or APT returns malformed or oversized output.
- The host agent must poll and return the result within the 90-second job deadline.

See [Host agent API](../host-agent-api.md) for the leased job envelope.
