# Issue tracker: GitHub

Repository: averyfreeman/ubuntu-fleet-manager. Specs and implementation tickets live in GitHub Issues; use the gh CLI for all tracker operations.

## Conventions

- Create and read issues with gh issue create and gh issue view.
- Publish the approved spec with the ready-for-agent label.
- Publish tickets in dependency order, also labeled ready-for-agent.
- Make tickets sub-issues of the spec when GitHub supports it.
- Represent blockers using native GitHub issue dependencies. Resolve the blocking issue database ID before creating the edge; do not use the issue number as the database ID. If native dependencies are unavailable, include a Blocked by list in each ticket.
- Leave PRs as a request surface disabled.

## Triage labels

Use the mappings in docs/agents/triage-labels.md. Create any missing configured label before publishing issues.
