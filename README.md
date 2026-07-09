# Snyk API MCP Server

An [MCP](https://modelcontextprotocol.io/) server for AI coding agents that combines:

- **Snyk REST API** for discovery, listing, and issue detail flows
- **Snyk API v1** for dependency-path analysis where the legacy endpoint is still the better source

If you are integrating this into a client, start with `snyk_onboarding`.

## What this server exposes

| Tool | Purpose |
|------|---------|
| `snyk_onboarding` | Overview of the toolset, identifier rules, and recommended workflow |
| `snyk_resolve_org_id` | Resolve an exact Snyk org slug to an org UUID |
| `snyk_get_targets` | List targets for an org, optionally filtered by display name |
| `snyk_get_projects` | List projects for an org or target |
| `snyk_get_target_ledger_seed` | Build the canonical target-scoped remediation seed with `issues[]` and `advisories[]` |
| `snyk_get_project_ledger_seed` | Build the canonical project-scoped remediation seed with `issues[]` and `advisories[]` |
| `snyk_get_project_issues` | List project issues with optional type, severity, and status filters |
| `snyk_list_org_issues` | List issues across an org with explicit API filters |
| `snyk_get_issue_detail` | Fetch a single REST issue resource by `restIssueId` |
| `snyk_get_package_issue_description` | List direct package vulnerabilities for an exact PURL |
| `snyk_get_project_issue_paths` | Resolve dependency paths for one project issue |
| `snyk_get_project_package_vulnerability_analysis` | Compose a package_vulnerability-focused project analysis from REST issue data, V1 paths, and package vulnerability data |

## Identifier model

The MCP contract is intentionally strict about issue identifiers.

| Field | Format | Meaning |
|------|--------|---------|
| `orgId` | UUID | Snyk organization ID |
| `projectId` | UUID | Snyk project ID |
| `restIssueId` | UUID | Snyk REST issue resource ID |
| `vulnerabilityId` | `SNYK-...` string | Snyk vulnerability identifier |
| `issueKey` | opaque string | Internal bridge identifier used to map REST issues to V1 path endpoints |

Do **not** treat `restIssueId`, `vulnerabilityId`, and `issueKey` as interchangeable.

## Typical workflow

```text
snyk_resolve_org_id
  → snyk_get_targets
  → snyk_get_target_ledger_seed
or
  → snyk_get_projects
  → snyk_get_project_ledger_seed
or
  → snyk_get_projects
  → snyk_get_project_issues
  → snyk_get_issue_detail / snyk_get_project_issue_paths / snyk_get_project_package_vulnerability_analysis
```

In practice:

1. Resolve the org UUID from the exact org slug.
2. Choose whether you want a target-scoped remediation seed or a single-project remediation seed.
3. Discover the target and/or the relevant project UUID.
4. Use a ledger seed tool for session initialization, or list project issues to obtain a `restIssueId`.
5. Use that `restIssueId` for detail lookups or dependency-path analysis.

## Prerequisites

- Node.js >= 22
- `pnpm`
- A Snyk API token

## Install and build

```sh
cd snyk-api-mcp
pnpm install
pnpm run build
```

## Runtime configuration

The MCP server reads these environment variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SNYK_TOKEN` | yes | — | Snyk API token |
| `SNYK_API_BASE` | no | `https://api.eu.snyk.io` | Snyk API base URL |
| `SNYK_API_VERSION` | no | `2026-03-25` | Default REST API version |

### Important note about `.env`

`.env` files are **not** loaded automatically by the MCP server at runtime.

- For MCP clients such as VS Code, Claude Desktop, or OpenCode, pass env vars explicitly in the client configuration.
- A local `.env` file is only useful for **internal debugging**, for example when you manually launch Node with an env-file flag or export vars in your shell first.

## Client setup

### VS Code / GitHub Copilot

Add this to `.vscode/mcp.json`:

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

### Claude Desktop

Add this to `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS or `%APPDATA%\\Claude\\claude_desktop_config.json` on Windows:

```json
{
  "mcpServers": {
    "snyk-api": {
      "command": "node",
      "args": ["/absolute/path/to/snyk-api-mcp/build/index.js"],
      "env": {
        "SNYK_TOKEN": "<your-snyk-token>",
        "SNYK_API_BASE": "https://api.eu.snyk.io",
        "SNYK_API_VERSION": "2026-03-25"
      }
    }
  }
}
```

### OpenCode

Add this to your OpenCode config:

```json
{
  "mcp": {
    "snyk-api": {
      "type": "stdio",
      "command": "node",
      "args": ["/absolute/path/to/snyk-api-mcp/build/index.js"],
      "env": {
        "SNYK_TOKEN": "${SNYK_TOKEN}",
        "SNYK_API_BASE": "https://api.eu.snyk.io",
        "SNYK_API_VERSION": "2026-03-25"
      }
    }
  }
}
```

## Usage examples

### Resolve an org and list critical project issues

```text
Agent: snyk_resolve_org_id(orgSlug: "my-snyk-org")
→ { orgId: "d85409c5-..." }

Agent: snyk_get_targets(orgId: "d85409c5-...", displayName: "my-org/my-repo")
→ { targets: [{ id: "16dd3840-..." }] }

Agent: snyk_get_target_ledger_seed(
  orgId: "d85409c5-...",
  targetId: "16dd3840-..."
)
→ target-scoped issues-ledger seed with issues[] and advisories[]

Agent: snyk_get_projects(orgId: "d85409c5-...", targetId: "16dd3840-...")
→ { projects: [{ id: "1454..." }] }

Agent: snyk_get_project_issues(
  orgId: "d85409c5-...",
  projectId: "1454...",
  issueType: "package_vulnerability",
  severity: "critical",
  status: "open"
)
→ issues with restIssueId, issueKey, severity, risk, and status

### Build a project-scoped remediation seed

```text
Agent: snyk_get_projects(orgId: "d85409c5-...", targetId: "16dd3840-...")
→ { projects: [{ id: "1454...", type: "pnpm" }] }

Agent: snyk_get_project_ledger_seed(
  orgId: "d85409c5-...",
  projectId: "1454..."
)
→ project-scoped issues-ledger seed with issues[] and advisories[]
```
```

### Fetch full detail for one issue

```text
Agent: snyk_get_issue_detail(
  orgId: "d85409c5-...",
  restIssueId: "a0f3809c-2c52-4d8f-8894-2f0c4a834f83"
)
→ full REST issue resource summary and raw response payload
```

### Look up direct package vulnerabilities for a PURL

```text
Agent: snyk_get_package_issue_description(
  orgId: "d85409c5-...",
  purl: "pkg:npm/axios@1.7.0"
)
→ packageVulnerabilities with vulnerabilityId values
```

### Get dependency paths for one project issue

```text
Agent: snyk_get_project_issue_paths(
  orgId: "d85409c5-...",
  projectId: "1454...",
  restIssueId: "a0f3809c-2c52-4d8f-8894-2f0c4a834f83"
)
→ issueKey bridge + V1 dependency paths
```

### Compose a package vulnerability analysis

```text
Agent: snyk_get_project_package_vulnerability_analysis(
  orgId: "d85409c5-...",
  projectId: "1454...",
  restIssueId: "a0f3809c-2c52-4d8f-8894-2f0c4a834f83",
  purl: "pkg:npm/esbuild@0.24.2"
)
→ REST issue metadata + package vulnerability context + dependency-path remediation hints
```

## Development

```sh
pnpm run dev
pnpm run build
pnpm run lint
```

### Type generation

```sh
pnpm run gen:snyk-rest
pnpm run gen:snyk-api-v1
```

Backward-compatible aliases for the old misspelled script names still exist:

```sh
pnpm run gen:synk-rest
pnpm run gen:synk-api-v1
```

## Release

- Releases are handled by `semantic-release`
- Release branch: `main`
- Package registry: `https://npm.pkg.github.com`
- Published package name: `@<github-owner>/snyk-api-mcp`

When the package is published, the published artifact gets the semantic-release version. In a development checkout, the server falls back to the latest release tag from `main` when `package.json` still carries the placeholder development version.

## Architecture

```text
snyk-api-mcp/
├── src/
│   ├── index.ts
│   ├── config.ts
│   ├── version.ts
│   ├── snyk/
│   │   ├── client.ts
│   │   └── types/
│   └── tools/
│       ├── onboarding.ts
│       ├── orgs.ts
│       ├── issues.ts
│       └── analysis.ts
├── build/
├── README.md
├── package.json
└── tsconfig.json
```

- **Runtime:** Node.js ESM
- **Validation:** Zod
- **HTTP client:** `openapi-fetch`
- **APIs:** Snyk REST + selective Snyk API v1 bridging

## License

ISC