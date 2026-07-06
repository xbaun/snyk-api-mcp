# Snyk API MCP Server

A generic [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that exposes the [Snyk REST API](https://docs.snyk.io/snyk-api) as tools for AI coding agents (VS Code Copilot, Claude Desktop, OpenCode, etc.).

## Available Tools

| Tool | Description |
|------|-------------|
| `snyk_onboarding` | 🆕 **Start here** — overview of all tools, workflow, and best practices |
| `snyk_resolve_org_id` | Resolve an org slug/name to its UUID |
| `snyk_get_targets` | List targets (repos) for an org, filterable by display name |
| `snyk_get_projects` | List projects for a target or entire org |
| `snyk_get_project_issues` | List issues for a specific project (filter by type, severity, status) |
| `snyk_list_org_issues` | List all issues across an org with client-side title search |
| `snyk_get_issue_detail` | Get full details of a single issue |
| `snyk_get_package_issue_description` | Get all issues for a package (PURL) |
| `snyk_get_project_issue_paths` | Get vulnerability data flow paths (Snyk v1 API) |
| `snyk_get_project_issue_analysis` | Compose a UI-like OSS issue analysis from REST + v1 paths + package metadata |

### Typical Workflow

```
snyk_resolve_org_id    → find org UUID from slug
snyk_get_targets       → find target (repo) by display name
snyk_get_projects      → list all projects for that target
snyk_get_project_issues → get issues per project (filter by severity/status)
```

Most tool inputs that end in `Id` expect Snyk UUIDs discovered from earlier calls. In particular:

- `orgId` = Snyk organization UUID
- `projectId` = Snyk project UUID

## Quick Start

### Prerequisites

- Node.js ≥ 22
- A Snyk API token (generate/revoke at [Snyk Account Settings → API Token](https://docs.snyk.io/developer-tools/snyk-api/authentication-for-api/revoke-and-regenerate-a-snyk-api-token))

### Install & Build

```sh
cd snyk-api-mcp
pnpm install
pnpm run build
```

### Configuration

The server reads these environment variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SNYK_TOKEN` | ✅ | — | Your Snyk API token |
| `SNYK_API_BASE` | ❌ | `https://api.eu.snyk.io` | Snyk API base URL |
| `SNYK_API_VERSION` | ❌ | `2026-03-25` | REST API version |

---

## Client Setup

### VS Code / GitHub Copilot

Add to `.vscode/mcp.json`:

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
      "args": ["/absolute/path/to/tools/snyk-api-mcp/build/index.js"],
      "env": {
        "SNYK_TOKEN": "${input:snyk_token}",
        "SNYK_API_BASE": "https://api.eu.snyk.io",
        "SNYK_API_VERSION": "2026-03-25"
      }
    }
  }
}
```

> `"password": true` ensures the token is never stored in plaintext. The token is prompted once per session.
>
> Restart VS Code or run `Developer: Reload Window` after editing `mcp.json`.

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "snyk-api": {
      "command": "node",
      "args": ["/absolute/path/to/tools/snyk-api-mcp/build/index.js"],
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

Add to your OpenCode configuration (`opencode.json` or project-level config):

```json
{
  "mcp": {
    "snyk-api": {
      "type": "stdio",
      "command": "node",
      "args": ["/absolute/path/to/tools/snyk-api-mcp/build/index.js"],
      "env": {
        "SNYK_TOKEN": "${SNYK_TOKEN}",
        "SNYK_API_BASE": "https://api.eu.snyk.io",
        "SNYK_API_VERSION": "2026-03-25"
      }
    }
  }
}
```

> Store the token in your shell profile (`export SNYK_TOKEN=...`) or use a `.env` file.

---

## Usage Examples

### 1. Find all critical issues for a specific repository

```
Agent: snyk_resolve_org_id(orgSlug: "my-snyk-org")
→ orgId: "d85409c5-..."

Agent: snyk_get_targets(orgId: "...", displayName: "my-org/my-repo")
→ targetId: "16dd3840-..."

Agent: snyk_get_projects(orgId: "...", targetId: "...")
→ 13 projects with IDs

Agent: snyk_get_project_issues(orgId: "...", projectId: "1454...", severity: "critical", status: "open")
→ List of open critical issues
```

### 2. Search for a specific vulnerability across the org

```
Agent: snyk_list_org_issues(orgId: "...", issueType: "package", titleSearch: "Prototype Pollution")
→ All matching issues
```

### 3. Get details for a single issue

```
Agent: snyk_get_issue_detail(orgId: "...", issueId: "a0f3809c-...")
→ Full issue details including coordinates, risk score, resolution
```

### 4. Check issues for a specific package

```
Agent: snyk_get_package_issue_description(orgId: "...", purl: "pkg:npm/axios@1.7.0")
→ All known vulnerabilities for that package version
```

### 5. Reproduce the Snyk UI analysis for one OSS issue in one project

```
Agent: snyk_get_project_issue_analysis(
  orgId: "...",
  projectId: "...",
  issueId: "SNYK-JS-ESBUILD-17750822"
)
→ REST issue metadata + introduced-through paths + package fix version + project remediation hint in one response
```

Semantics note:

- `package.fixedIn` = the relevant fix version for the vulnerable package itself (when derivable from Snyk metadata)
- `issueContext.remediation` = the best next project-level action inferred from the dependency path, e.g. upgrade a direct parent or re-lock transitives

---

## Development

```sh
# Watch mode (auto-rebuild on changes)
pnpm run dev

# One-shot build
pnpm run build
```

## Release to GitHub Packages

This repository can publish the MCP server to the GitHub npm registry instead of `npmjs.com`.

- Publish trigger: GitHub Release with a semver tag such as `v0.2.1`
- Target registry: `https://npm.pkg.github.com`
- Published package name: `@<github-owner>/snyk-api-mcp`

The workflow automatically:

1. installs dependencies with `pnpm`
2. builds the TypeScript project
3. rewrites the package name to the current GitHub owner scope
4. publishes the package to GitHub Packages using `GITHUB_TOKEN`

### Installing the published package

Consumers need access to GitHub Packages and an `.npmrc` entry for the owner scope, for example:

```ini
@YOUR_GITHUB_OWNER:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
```

Then install the package via:

```sh
pnpm add @YOUR_GITHUB_OWNER/snyk-api-mcp
```

### Adding a New Tool

1. Add a `server.registerTool(...)` call in `src/index.ts`
2. Define the `inputSchema` using Zod
3. Implement the async handler using the `snykGet()` helper
4. Run `npm run build` to verify compilation
5. Restart the MCP server in your client

---

## Architecture

```
snyk-api-mcp/
├── src/
│   └── index.ts          # All tools and server setup
├── build/                # Compiled JS output
├── package.json
└── tsconfig.json
```

- **Runtime:** Node.js, ESM (`"type": "module"`)
- **MCP SDK:** `@modelcontextprotocol/sdk` v1.x
- **Validation:** Zod v4
- **Build:** TypeScript compiler (`tsc`)

## License

ISC