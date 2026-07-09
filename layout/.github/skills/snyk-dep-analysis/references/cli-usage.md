# snyk-dep-analysis CLI usage

## Purpose

This reference owns the operational command patterns for `scripts/dep.py`.

Use it when an agent needs the concrete query flow for dependency fact gathering, path analysis, or verification.

## Read help first

Before using the script:

- `python3 .github/skills/snyk-dep-analysis/scripts/dep.py --help`
- `python3 .github/skills/snyk-dep-analysis/scripts/dep.py <subcommand> --help`

## Canonical query sequence

Use this sequence unless a narrower repo-specific reason clearly requires something else.

### Gate `[R2]` fact set

- `python3 .github/skills/snyk-dep-analysis/scripts/dep.py inspect --repo-root . --package-name <packageName> --workspace-package <workspacePackage | unknown>`
- If `packageName` is missing or unusable, use:
  - `python3 .github/skills/snyk-dep-analysis/scripts/dep.py inspect --repo-root . --purl <purl> --workspace-package <workspacePackage | unknown>`

### Gates `[R3]`–`[R4]` classification and controllable levers

- `python3 .github/skills/snyk-dep-analysis/scripts/dep.py trace --repo-root . --package-name <packageName> --workspace-package <workspacePackage | unknown>`
- If `packageName` is missing or unusable, use:
  - `python3 .github/skills/snyk-dep-analysis/scripts/dep.py trace --repo-root . --purl <purl> --workspace-package <workspacePackage | unknown>`

### Gate `[R7]` verification

- `python3 .github/skills/snyk-dep-analysis/scripts/dep.py verify --repo-root . --package-name <packageName> --workspace-package <workspacePackage | unknown> --vulnerable-version <version>`
- Repeat `--vulnerable-version` for every known problematic version when more than one version is in scope.

## Argument rules

- Omit `--manager` by default.
- Pass `--manager` only when auto-detection is ambiguous or repo context requires it explicitly.
- Prefer `packageName` from the handoff.
- Use `purl` only when `packageName` is missing or `unknown`.
- Treat `workspacePackage` only as a scope hint.
- Pass `unknown` unchanged when that is the known scope value.

## Interpretation rules

- `inspect.packagePresent == false` does not prove remediation on its own if the handoff or project context still indicates a live issue.
- `trace.controllableParents[]` is the primary source for `update-parent` candidates.
- `verify.dependencyCheck == pass` is the default proof required before claiming `resolved`.
- If a manager is recognized but unsupported, fail clearly; do not silently switch managers.

## Usage constraints

- Prefer `dep.py` whenever it already covers the needed fact.
- Do not manually read large lockfiles when `dep.py` can supply the same evidence.
- Keep manager-specific complexity inside adapters, not in resolver prompt logic.
