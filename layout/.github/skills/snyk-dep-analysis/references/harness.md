# snyk-dep-analysis harness

## Purpose

This harness defines the only allowed read interface for compact dependency facts in resolver workflows.

It covers fact gathering and verification only. The final resolver handback remains a separate JSON object sent to `ledger.py update --from-handback -` by `snyk-orchestration`.

## Adapter model

- `dep.py` has a small registry of manager adapters.
- Each adapter owns:
  - detection (`detect_score`)
  - fact gathering (`inspect`)
  - path and lever analysis (`trace`)
  - verification (`verify`)
- Resolvers talk to `dep.py`, not to manager-specific raw artifacts.

## Auto-selection

1. If `--manager` is provided, use that adapter only.
2. Otherwise, `dep.py` picks the adapter with the highest `detect_score`.
3. Detection stays intentionally simple and file-based.
4. In this repo, `pnpm` usually wins via `pnpm-workspace.yaml` or `pnpm-lock.yaml`.
5. Recognized but unsupported managers must fail clearly, not fall through silently.

## Subcommands

### `inspect`

Provides the compact fact set for Gate `[R2]`.

Required semantics:

- `manager` — selected adapter
- `packageName` — canonical package name from `--package-name` or `--purl`
- `workspacePackage` — the supplied scope hint or `unknown`
- `manifestPaths[]` — relevant `package.json` files in scope
- `directDeclarations[]` — direct declarations of the package in relevant manifests
- `observedVersions[]` — concretely observed active versions
- `reachableImporters[]` — observed importers or workspace entry points
- `packagePresent` — whether the package appears in the active resolution at all

### `trace`

Provides dependency paths and controllable levers for Gates `[R3]`–`[R5]`.

Required semantics:

- `controllableParents[]` — direct levers in relevant manifests
- `evidencePaths[]` — compact observed paths from importer to affected package
- `candidateLevers[]` — possible strategy directions only, not a final decision

### `verify`

Provides the normative verification fact for Gate `[R7]`.

Required semantics:

- `dependencyCheck` — `pass | fail`
- `observedVersions[]` — currently observed versions
- `reachableVulnerableVersions[]` — still-active problematic versions
- `remainingPaths[]` — paths through which problematic versions remain reachable
- `summary` — brief human-readable summary

## Input rules

- `--repo-root` is the canonical repo root.
- `--package-name` and `--purl` are alternative identity inputs; at least one is required.
- `--workspace-package` is a scope hint and may be `unknown`.
- `verify` requires at least one explicit `--vulnerable-version`.

## Quality rules

- Keep JSON output small and deduplicated.
- Limit path output; this is not a full graph dump.
- Back direct declarations with manifest evidence, not guesses.
- Base verification claims on the active dependency graph of the selected adapter.
- If an adapter cannot produce trustworthy data, it must fail clearly.

## Forbidden

- manual resolver interpretation of large lockfiles when `dep.py` can provide the fact
- reinterpretation of these fields inside the resolver
- silent switching to another manager after an adapter failure
