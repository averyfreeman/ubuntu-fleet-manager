# GitHub Actions Bandit Fix and Branch Consolidation

Date: 2026-09-30

## Executive summary

The failure was on `main`, not on `docs/quality-pass-20260914`. The scheduled
run checked out `main` at `be0e0fe` and failed only its Security Scan job. The
Python 3.10–3.13 test matrix and installed-package job passed. The archived
evidence is `github-actions-logs/logs_98279672184.zip`; the corresponding
[failed Actions run](https://github.com/averyfreeman/codex-mcp-for-ubuntu/actions/runs/36294083203)
was scheduled on `main`.

Bandit 1.9.4 reported 14 findings:

| Finding | Count | Cause | Resolution |
| --- | ---: | --- | --- |
| `B108` | 11 | Shared `/tmp` audit-log default, shared-temp policy entries, and fixed-name self-test fixtures | Moved state/temp data into private per-user directories and replaced fixtures with `tempfile` resources |
| `B101` | 2 | Assertions in the runtime smoke-test helper | Replaced them with explicit runtime failures |
| `B404` | 1 | Unused `subprocess` import in `server.py` | Removed the import |

The remediation is implemented in commit `430a88c`. The new push-triggered
[Actions run](https://github.com/averyfreeman/codex-mcp-for-ubuntu/actions/runs/36812472865)
completed successfully for every job.

## What changed

- Audit logs now default to `~/.local/state/ubuntu-mcp/audit.log`. The state
  directory is `0700`; the log is created with `0600` and `O_NOFOLLOW` to avoid
  following a symlink in a shared directory.
- Secure and development policies no longer allow shared `/tmp` or `/var/tmp`.
  Documentation, legacy configuration examples, setup output, and the client
  test were updated accordingly. See [server.py](ubuntu_mcp_server/server.py),
  [SECURITY.md](SECURITY.md), and [config.example.json](config.example.json).
- Built-in security and smoke tests now use private `TemporaryDirectory`
  resources and no longer rely on fixed global filenames.
- Bandit is pinned to `1.9.4` in [ci.yml](.github/workflows/ci.yml), and CI now
  runs `python -m ubuntu_mcp_server --security-test` instead of merely claiming
  that security policy tests passed.
- The command-resolution test now derives the trusted `echo` path, so it works
  on both Ubuntu (`/usr/bin/echo`) and macOS (`/bin/echo`).

No broad `# nosec` suppression or relaxed Bandit severity threshold was used.
The latter would have hidden the 11 medium-severity findings without fixing the
shared-temp risk. Bandit documents [`B108`](https://bandit.readthedocs.io/en/latest/plugins/b108_hardcoded_tmp_directory.html)
as a temporary-file safety check, [`B101`](https://bandit.readthedocs.io/en/latest/plugins/b101_assert_used.html)
as a warning because assertions can disappear under optimized Python, and
[`B404`](https://bandit.readthedocs.io/en/latest/blacklists/blacklist_imports.html#b404-import-subprocess)
as a review warning for subprocess imports.

## Branch and PR investigation

Before consolidation, `docs/quality-pass-20260914` was one commit ahead of
`main` and zero commits behind it. Its only original commit,
`0b870406` (`docs: document Ubuntu MCP APIs`), added docstrings in four files;
it did not contain the Bandit fix. The change was documentation-only and
consistent with the repository’s public-function documentation standard in
[CONTRIBUTING.md](CONTRIBUTING.md).

GitHub’s [all-state PR query](https://api.github.com/repos/averyfreeman/codex-mcp-for-ubuntu/pulls?state=all&head=averyfreeman%3Adocs%2Fquality-pass-20260914&per_page=100)
returned no pull request; the [commit PR association query](https://api.github.com/repos/averyfreeman/codex-mcp-for-ubuntu/commits/0b8704060803a716f65c3ce6d2b27e3d755e2bfb/pulls)
and commit comments were also empty. There were no Actions runs for that
branch. Therefore there was no PR review thread or response to wait for.

Because there was no PR and the branch was a harmless, newer documentation
improvement, it was fast-forwarded into `main`. The remote and local
`docs/quality-pass-20260914` branches were then deleted. `main` is now the only
remote branch at `8b1c883` (the report commit; remediation is at `430a88c`); no
rebase was necessary because `main` was already
an ancestor.

## Validation

Local checks on the remediation branch passed:

```text
uvx --from 'bandit==1.9.4' bandit -r ubuntu_mcp_server       # no issues
uv run python -m unittest discover -s tests -v                # 7 tests: OK
uv run python -m ubuntu_mcp_server --security-test            # all checks passed
uv run python -m ubuntu_mcp_server --test                     # smoke test passed
uv build                                                       # source and wheel built
```

The existing dependency scan also reported zero known vulnerabilities locally.
Its workflow command, `safety check`, is deprecated upstream and should be
migrated to `safety scan` in a separate maintenance change; it was not the cause
of this failure.

The user’s pre-existing `.gitignore` modification adding `github-actions-logs`
was preserved and was not included in the remediation commit.
