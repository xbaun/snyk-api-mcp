# `snyk-api-mcp`

[![Release workflow](https://img.shields.io/github/actions/workflow/status/xbaun/snyk-api-mcp/release.yml?branch=main&label=release&logo=githubactions)](.github/workflows/release.yml)
[![Latest release](https://img.shields.io/github/v/release/xbaun/snyk-api-mcp?display_name=tag)](https://github.com/xbaun/snyk-api-mcp/releases)
[![Node.js](https://img.shields.io/badge/node-%3E%3D22-339933?logo=node.js&logoColor=white)](package.json)
[![License](https://img.shields.io/badge/license-ISC-blue.svg)](package.json)

Small, strict, agent-friendly MCP server for Snyk.

It gives AI coding agents a **narrow and predictable** interface for common Snyk workflows: resolve an org, discover targets and projects, list issues, fetch issue detail, inspect dependency paths, and generate ledger seed documents for remediation loops.

## Why it is useful

Most Snyk integrations are great for humans, but noisy for agents. This project keeps the surface area intentionally small:

- **Strict identifiers** — `orgId`, `projectId`, `restIssueId`, `vulnerabilityId`, and `issueKey` are not treated as interchangeable.
- **Focused workflows** — tools are split by job instead of collapsing everything into one vague query endpoint.
- **Stable response shapes** — outputs stay predictable and easy for agents to reuse.
- **REST + v1 bridge** — discovery and issue detail use modern Snyk REST APIs, while dependency-path analysis still leverages Snyk API v1 where it is stronger.
- **Downloadable agent and skill definitions** — releases include a downloadable `layout/` archive with `.github/agents`, `.github/skills`, and `.snyk/` files for downstream repos.

## What the project does

### Core workflows

| Workflow | Tools |
| --- | --- |
| Onboarding | `snyk_onboarding` |
| Org + target discovery | `snyk_resolve_org_id`, `snyk_get_targets`, `snyk_get_projects` |
| Issue intake | `snyk_get_target_ledger_seed`, `snyk_get_project_ledger_seed` |
| Issue investigation | `snyk_get_project_issues`, `snyk_list_org_issues`, `snyk_get_issue_detail` |
| Dependency analysis | `snyk_get_project_issue_paths`, `snyk_get_project_package_vulnerability_analysis`, `snyk_get_package_issue_description` |

### Identifier model

| Field | Meaning |
| --- | --- |
| `orgId` | Snyk organization UUID |
| `projectId` | Snyk project UUID |
| `restIssueId` | Snyk REST issue resource UUID |
| `vulnerabilityId` | Snyk vulnerability identifier such as `SNYK-JS-...` |
| `issueKey` | Internal bridge key used for legacy path analysis |

If you only remember one rule from this README, make it this one: **do not mix these identifiers**.

## Get started

### Prerequisites

- Node.js `>= 22`
- `pnpm`
- a Snyk API token

### Install and build

```sh
pnpm install
pnpm run build
```

### Runtime configuration

The server reads these environment variables at runtime:

| Variable | Required | Default |
| --- | --- | --- |
| `SNYK_TOKEN` | yes | — |
| `SNYK_API_BASE` | no | `https://api.eu.snyk.io` |
| `SNYK_API_VERSION` | no | `2026-03-25` |

`.env` files are **not** loaded automatically by the server. MCP clients should pass these variables explicitly.

### Quick client setup

Works with any stdio-based MCP client. A minimal VS Code / GitHub Copilot setup looks like this:

```jsonc
{
  "inputs": [
    {
      "type": "promptString",
      "id": "snyk_token",
      "description": "Snyk API Token",
      "password": true
    }
  ],
  "servers": {
    "snyk-api": {
      "command": "node",
      "args": ["/absolute/path/to/snyk-api-mcp/build/index.js"],
      "env": {
        "SNYK_TOKEN": "${input:snyk_token}",
        "SNYK_API_BASE": "https://api.eu.snyk.io",
        "SNYK_API_VERSION": "2026-03-25"
      }
    }
  }
}
```

## Typical workflow

Start with `snyk_onboarding`, then walk the identifiers forward step by step.

```mermaid
flowchart TD
    A[snyk_onboarding] --> B[snyk_resolve_org_id]
    B --> C[snyk_get_targets]
    C --> D[snyk_get_projects]
    C --> E[snyk_get_target_ledger_seed]
    D --> F[snyk_get_project_ledger_seed]
    D --> G[snyk_get_project_issues]
    G --> H[snyk_get_issue_detail]
    G --> I[snyk_get_project_issue_paths]
    G --> J[snyk_get_project_package_vulnerability_analysis]
```

### Example flow

```text
1. snyk_resolve_org_id(orgSlug)
2. snyk_get_targets(orgId)
3. snyk_get_projects(orgId, targetId)
4. snyk_get_project_issues(orgId, projectId, issueType='package_vulnerability', severity='critical', status='open')
5. snyk_get_issue_detail(...) or snyk_get_project_issue_paths(...)
```

Use ledger seed tools when you want to initialize remediation sessions instead of manually iterating issues.

## Download agent and skill definitions

Each GitHub release attaches `snyk-api-mcp-layout.tar.gz`.

Use it to copy the repository `layout/` contents into another repository, including:

- `.github/agents`
- `.github/skills`
- `.snyk/`

Example:

```sh
curl -fsSL https://github.com/xbaun/snyk-api-mcp/releases/latest/download/snyk-api-mcp-layout.tar.gz \
  | tar -xzf - -C .
```

This is the fastest way to add the bundled agent and skill definitions to a downstream repo.

## Development

### Common commands

```sh
pnpm run dev
pnpm run build
pnpm run lint
pnpm run build:layout-archive
pnpm run gen:snyk-rest
pnpm run gen:snyk-api-v1
```

### Project shape

```text
src/
  index.ts                MCP bootstrap
  tools/                  MCP tool definitions
  snyk/client.ts          Snyk API access
  utils/                  focused helpers
layout/                   bundled agent and skill definitions for downstream repos
docs/                     small reference docs
```

## Help and documentation

If you are using the server:

- start with `snyk_onboarding`
- use [identifier mapping notes](docs/snyk-issue-identifier-mapping.md) when a Snyk UI issue ID does not match the MCP contract
- inspect [AGENTS.md](AGENTS.md) for the design philosophy behind the public tool surface
- follow [CODING.md](CODING.md) for local consistency rules
- open an issue at <https://github.com/xbaun/snyk-api-mcp/issues>

## Maintainers and contributing

This project is maintained by [`@xbaun`](https://github.com/xbaun) and contributors.

Contributions are welcome via issues and pull requests. Before opening a PR:

- keep the MCP contract strict and explicit
- prefer extending existing patterns over adding abstractions
- run `pnpm run build` and `pnpm run lint`
- align with the repository guidance in [AGENTS.md](AGENTS.md) and [CODING.md](CODING.md)

## License

ISC.