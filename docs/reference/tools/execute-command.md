# Execute an allowlisted command

`execute_command` runs one pre-approved executable with one exact argument vector on an enrolled host. The agent starts the executable directly; it does not construct a shell command or expand shell syntax.

## Availability and approval

Over Streamable HTTP, the control plane registers this tool only when `ALLOW_COMMAND_EXECUTION=true`. The target agent must also have an enabled `command_policy` rule matching the exact executable, argument vector, and any requested working directory. Sudo is disabled by default and requires a separate exact OS sudoers rule. See [Host agent configuration](../host-agent-configuration.md) and [Configure constrained command execution](../../how-to/configure-command-policy.md).

The tool is marked mutating, destructive, non-idempotent, and open-world because an allowed program can change host state or contact external systems. In ChatGPT, set the connected app or account permission to **Always ask** to require confirmation before tool actions. ChatGPT's prompt behavior depends on app permissions and action context; workspace Agents have separate per-agent approval controls. Other MCP clients must also be configured to request per-call human confirmation. MCP annotations are advisory metadata; the server cannot prove that a client displayed a confirmation prompt. This operation has no rollback. See OpenAI's [Managing app permissions in ChatGPT](https://help.openai.com/en/articles/20001495-managing-app-permissions-in-chatgpt) and [Connecting custom MCP servers in ChatGPT](https://help.openai.com/en/articles/12584461-connecting-custom-mcp-servers-in-chatgpt).

The tool is currently available over the authenticated HTTP control plane. It is not registered by the local stdio server.

## Request

| Field | Type | Required | Constraints |
| --- | --- | --- | --- |
| `host_id` | string | Yes | Active host identifier in the authenticated operator's personal tenant. |
| `executable` | string | Yes | Absolute path to an existing regular executable that exactly matches a host policy rule. Symlinks, aliases, shells, privilege launchers, and environment wrappers are rejected. |
| `args` | array of strings | Yes | Exact argument vector allowed for this executable. Pass an empty array when the command takes no arguments. |
| `working_directory` | string | No | Existing absolute directory listed by this rule. It must not be a symlink. If omitted, the process inherits the agent's current directory. |

The agent accepts at most 64 arguments, with at most 4,096 UTF-8 bytes per argument. It rejects control characters, including NUL. The host policy contains up to 100 executable rules and up to 100 exact argument vectors per rule. Arguments are passed literally; shell metacharacters such as `;`, `$HOME`, and `$(...)` are not interpreted by a shell. A command can still implement its own argument-language features, so allow only vectors whose behavior the host operator has reviewed.

For a sudo-backed rule, the executable, every parent directory, and any configured working directory must be root-owned and not writable by group or others. If no working directory is passed, a sudo command runs from `/`. The agent invokes `/usr/bin/sudo -n -- EXECUTABLE ARGUMENTS`; the host's sudoers policy must permit that exact command and argument sequence without a password prompt. The agent does not inspect sudoers, and a mismatched or interactive sudo rule fails closed.

## Result

| Field | Type | Description |
| --- | --- | --- |
| `host_id` | string | Target host identifier. |
| `hostname` | string | Hostname reported during enrollment. |
| `requested_at` | timestamp | UTC time when the control plane queued the request. |
| `exit_code` | integer | Process exit status, or `-1` when the process ended from a signal. |
| `stdout` | string | Standard output after common credential-pattern redaction. |
| `stderr` | string | Standard error after common credential-pattern redaction. |
| `output_truncated` | boolean | Whether output exceeded the combined 64 KiB response limit. |

Execution is limited to 30 seconds. The combined output is capped at 64 KiB before it is retained in the job result; common password, token, bearer-credential, and private-key patterns are redacted before storage and delivery. Redaction is heuristic and is not a guarantee that every secret is removed. The control plane clears the consumed job input and result after returning the response.

## Example

```json
{
  "host_id": "c0c326bc-cf08-4e15-98dc-cf8b5fa8d66d",
  "executable": "/usr/bin/systemctl",
  "args": ["show", "--property=Version"],
  "working_directory": "/"
}
```

This request is allowed only if the agent has configured the exact executable, argument vector, and `/` working directory. See [Configure constrained command execution](../../how-to/configure-command-policy.md).
