# snyk-orchestration handoff format

## Purpose

This is the only allowed structure for dispatch from `snyk-orchestration` to a resolver.

## Rules

- The handoff is plain text, but strictly structured.
- Field names must stay exactly as written below.
- The resolver receives exactly one advisory per invocation.
- `issues-ledger.json` is the status source.
- `issues-ledger-seed.json` is the static context source.

## Field semantics

- `SESSION` = the concrete `.synk/{sessionId}` work area for this run
- `ADVISORY` = the canonical work unit in the ledger (`advisoryKey`)
- `ISSUE_TYPE` = the only valid dispatch key (`package_vulnerability` or `code`)
- `REPRESENTATIVE ISSUE INSTANCES` = concrete seed issue instances from the same work unit, used as the starting point for analysis calls
- `AFFECTED WORKSPACE PACKAGES` = repo-relative workspace areas relevant for health checks or scoping; this is a hint, not a second dispatch mechanism
- `PRE-KNOWN FACTS` = optional known facts from the seed or earlier loop state; they may be incomplete

### `PRE-KNOWN FACTS` for `package_vulnerability`

- `Package Name` = package name directly from seed data for a `package_vulnerability`; this is normally the primary input for `dep.py inspect|trace|verify`
- `Package` = a later loop or resolver fact such as confirmed `vulnerablePackage`; it may start as `unknown`
- `Versions` = already known problematic versions; may start as `unknown`
- `Target` = already known desired target version or resolution; may start as `unknown`

Additional rules:

- If `Package Name` exists and is not `unknown`, the resolver should prefer it over `purl` for `dep.py` input.
- `Package` does not replace `Package Name` as the seed-near identity.
- If `Package Name` is missing or `unknown`, `purl` is the canonical fallback identity.
- Omit the `PRE-KNOWN FACTS` block entirely for `code` advisories unless a later protocol revision defines code-specific fact fields.

### Representative issue instances

- For `package_vulnerability`, `purl` is the exact project-facing package reference and the canonical fallback when `packageName` is not usable.
- For `package_vulnerability`, `packageName` remains the preferred compact input for `dep.py`; do not rewrite it from `purl` when it already exists in seed context.
- For `code`, `filePath`, `startLine`, and `endLine` are the direct entry point for code analysis.
- `workspacePackage` is a scope hint, not the primary finding identity; if no reliable value exists, keep it exactly as `unknown`.

## Template

```text
SESSION: {sessionId}
ADVISORY: {advisoryKey}
ISSUE_TYPE: {issueType}
TITLE: {title}
SEVERITY: {severity}
ISSUE_COUNT: {issueCount}

REPRESENTATIVE ISSUE INSTANCES:
  For issueType = package_vulnerability:
  - projectId={projectId}, restIssueId={restIssueId}, issueKey={issueKey}, purl={purl}, packageName={packageName}, workspacePackage={workspacePackage | "unknown"}

  For issueType = code:
  - projectId={projectId}, restIssueId={restIssueId}, issueKey={issueKey}, filePath={filePath}, startLine={startLine}, endLine={endLine}, workspacePackage={workspacePackage | "unknown"}

AFFECTED WORKSPACE PACKAGES:
  - {workspacePackage1}
  - {workspacePackage2}

For issueType = package_vulnerability only:
  PRE-KNOWN FACTS:
    Package Name: {packageName | "unknown"}
    Package: {vulnerablePackage | "unknown"}
    Versions: {vulnerableVersions | "unknown"}
    Target: {targetVersion | "unknown"}

CONTEXT FILES:
  - .synk/{sessionId}/issues-ledger-seed.json
  - .snyk/GOTCHAS.md                  # read-only for resolvers; curated only by snyk-orchestration
  - .synk/{sessionId}/GOTCHAS.md      # read + append for resolvers according to gotchas-policy
  - .github/skills/snyk-orchestration/references/gotchas-policy.md
  - AGENTS.md

  For issueType = package_vulnerability only:
    - .github/skills/snyk-dep-analysis/SKILL.md
    - .github/skills/snyk-dep-analysis/references/harness.md
    - .github/skills/snyk-dep-analysis/scripts/dep.py
    - .github/skills/snyk-dep-overrides/SKILL.md
    - .github/skills/snyk-dep-overrides/references/snyk-dep-overrides.harness.md
    - .github/skills/snyk-dep-overrides/schemas/snyk-dep-overrides.schema.json
    - .github/skills/snyk-dep-overrides/examples/snyk-dep-overrides.{{manager}}.example.json
    - .github/skills/snyk-dep-overrides/scripts/overrides.py
    - snyk-dep-overrides.pnpm.json
    - pnpm-workspace.yaml

IMPORTANT:
  - Apply Gate [A] before making changes.
  - Use one representative issue instance with complete required fields for the first analysis call.
  - For `package_vulnerability`, prefer `packageName`; fall back to `purl` only when `packageName` is missing or `unknown`.
  - If `temp-override` is under consideration, consult `overrides.py analyze` before choosing the strategy.
  - `workspacePackage` is only a scope hint; do not use it as package identity or resolver selection input.
  - Do not do extra issue discovery before the resolver starts.
  - For `blocked`, return `remediationProposal` and `rationale`.
  - Accept override materialization only after successful validation.
  - Write session learnings to `.synk/{sessionId}/GOTCHAS.md` only under `gotchas-policy.md`.
```

## Required rules

### For `package_vulnerability`

- Include at least one representative issue instance with:
  - `projectId`
  - `restIssueId`
  - `issueKey`
  - `purl`
  - `packageName`
- Keep `packageName` and `purl` unchanged from seed or ledger context.
- `workspacePackage` may be `unknown`, but must not be invented.
- `AFFECTED WORKSPACE PACKAGES` may be empty.
- Include the dep-analysis and dep-overrides context files only for this issue type.

### For `code`

- Include at least one representative issue instance with:
  - `projectId`
  - `restIssueId`
  - `issueKey`
  - `filePath`
  - `startLine`
  - `endLine`
- Omit `PRE-KNOWN FACTS`.
- Do not include dep-analysis or dep-overrides context files.

## Forbidden

- alternate headings
- JSON or YAML handoff variants
- free-form prose before the template
- extra context files that are not justified by the workflow
