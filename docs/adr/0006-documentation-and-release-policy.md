# Documentation and release policy

Status: Accepted

## Context

The project has a wide tool surface and targets system administrators and agent developers. Users need concise technical references, task instructions, and architectural explanations. The initial project is a new public MIT-licensed repository with no legacy API compatibility requirement.

## Decision

Organize user documentation as Tutorial, How-to, Reference, and Explanation, following Canonical's Diátaxis conventions. Tool schemas, options, policy limits, and result shapes belong in Reference; installation and common operations belong in Tutorials and How-tos; security and architecture rationale belong in Explanation. Request explicit authorization before any divergence from Canonical conventions and record approved divergence in an ADR. See the [Canonical documentation style guide](https://documentation.ubuntu.com/style-guide/) and [Ubuntu Server reference guidance](https://documentation.ubuntu.com/server/reference/index.html).

Start the new repository's release tags at v0.1.0. Do not copy old release tags. Breaking changes are permitted before v0.1.0; after the first release, published MCP tool names and schemas remain backward compatible. Keep the MIT license. Ship no third-party API integration in v0.1 without a separate demand assessment and approval.

## Alternatives considered

- Preserve the legacy version tags and tool schemas: rejected because this is a new project with a deliberately reworked runtime and interfaces.
- Put all guidance in one README: rejected because reference data and task instructions serve different user needs.

## Consequences

Every feature ticket updates its Reference entry and tests its schema. The final release ticket verifies navigation, examples, security boundaries, self-hosted deployment, and the v0.1.0 tag. Extension requests are evaluated case by case using user counts when available and multiple confidence-labeled proxies otherwise.
