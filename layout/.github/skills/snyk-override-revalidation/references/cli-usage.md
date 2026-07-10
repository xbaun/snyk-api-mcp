# snyk-override-revalidation CLI usage

## Read the tools first

- `python3 .github/skills/snyk-dep-overrides/scripts/overrides.py --help`
- `python3 .github/skills/snyk-dep-overrides/scripts/overrides.py <subcommand> --help`
- `python3 .github/skills/snyk-dep-analysis/scripts/dep.py --help`
- `python3 .github/skills/snyk-dep-analysis/scripts/dep.py <subcommand> --help`

## Typical inspection flow

- `python3 .github/skills/snyk-dep-overrides/scripts/overrides.py list --materialization snyk-dep-overrides.pnpm.json --status active`
- `python3 .github/skills/snyk-dep-overrides/scripts/overrides.py analyze --materialization snyk-dep-overrides.pnpm.json --package <packageName>`
- `python3 .github/skills/snyk-dep-analysis/scripts/dep.py inspect --repo-root . --package-name <packageName> --workspace-package <workspacePackage | unknown>`
- `python3 .github/skills/snyk-dep-analysis/scripts/dep.py trace --repo-root . --package-name <packageName> --workspace-package <workspacePackage | unknown>`
- `python3 .github/skills/snyk-dep-analysis/scripts/dep.py verify --repo-root . --package-name <packageName> --workspace-package <workspacePackage | unknown> --vulnerable-version <version>`

## Typical mutation flow

- `python3 .github/skills/snyk-dep-overrides/scripts/overrides.py remove --materialization snyk-dep-overrides.pnpm.json --key <caseKey>`
- `python3 .github/skills/snyk-dep-overrides/scripts/overrides.py upsert --materialization snyk-dep-overrides.pnpm.json ...`
- `python3 .github/skills/snyk-dep-overrides/scripts/overrides.py materialize --materialization snyk-dep-overrides.pnpm.json --workspace pnpm-workspace.yaml`
- `python3 .github/skills/snyk-dep-overrides/scripts/overrides.py validate --materialization snyk-dep-overrides.pnpm.json --workspace pnpm-workspace.yaml`

## Interpretation rules

- Use `analyze` before any removal or narrowing decision.
- Use `verify` as the strongest default proof that a vulnerable version is no longer active.
- If evidence is incomplete, keep the override and report the blocker instead of removing it optimistically.
