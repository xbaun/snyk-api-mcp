# snyk-dep-overrides harness

## Purpose

This harness defines when and how a manager-specific override materialization may be maintained.

It covers override decision support and materialization only. The final resolver handback remains a separate JSON object passed to `ledger.py update --from-handback -` by `snyk-ledger-remediation`.

## Decision rules

1. An override is allowed only when a regular dependency change cannot fix the finding within the YAGNI+KISS boundary.
2. Every override case needs traceable evidence:
   - `selector`
   - `target`
   - `package`
   - `snykIds[]`
   - `evidenceTree[]`
   - `watch[]`
   - `obsoleteWhen[]`
3. `status=active` means the override is currently intended and effective.
4. `status=obsolete` means the case is historical and no longer needed.
5. Removal is allowed only when the `obsoleteWhen[]` conditions are satisfied.

## Field semantics

These terms are normative.

### `selector`

- Which resolution match is being overridden.
- This is the manager-specific expression for the problematic or unwanted resolution.
- Example for pnpm: `esbuild@<0.28.0`
- `selector` describes the problem match, not the target version.

### `target`

- What the selector is redirected to.
- This is the desired non-vulnerable target resolution or range.
- Example: `^0.28.1`

### `package`

- Canonical name of the affected package.
- Used for readability, Snyk traceability, and later recognition.

### `snykIds[]`

- Concrete Snyk references that justify the override.
- Use real Snyk IDs such as `SNYK-JS-ESBUILD-17750822`.

### `evidenceTree[]`

- Why the override is needed and through which dependency path the package enters the repo.
- Each entry represents one observed introduction chain.

#### `evidenceTree[].importer`

- Where the chain is viewed from.
- Typically workspace root, catalog, or a concrete package.

#### `evidenceTree[].directDependency`

- The first controllable lever in the chain.
- Usually the direct dependency that introduces the affected package.

#### `evidenceTree[].chain[]`

- Full observed chain from the controllable lever to the affected package.
- Order is upstream → downstream.

### `watch[]`

- Upstream levers that should be monitored so the override can later be removed or adjusted.
- `watch[]` answers: which declarations must change before this override can become obsolete?

#### `watch[].package`

- Package to monitor.

#### `watch[].declaredIn`

- Where that package is declared.

#### `watch[].declaredVersion`

- Declared version or range observed when the case was created.

#### `watch[].relevance`

- Why this upstream package matters.

### `obsoleteWhen[]`

- Explicit, testable conditions under which the override should no longer be needed.
- Each condition must be written as a concrete verification rule, not as vague intent.

Good examples:

- `All watched packages resolve esbuild >=0.28.1 natively`
- `Removing selector does not reintroduce the vulnerable package version`

### `status`

- `active` = currently intended and effective
- `draft` = prepared, but not yet an active materialization
- `obsolete` = historical, no longer needed
- `removed` = no longer an operational source

### `reason`

- `security` = security remediation
- `compatibility` = compatibility reason
- `performance` = performance reason
- `other` = legitimate exception outside the other classes

### `introducedBy`

- Identifies the run, session, or remediation that introduced the case.
- It should stay stable enough to trace the origin.

### `scope`

- Optional human-readable scope such as `workspace-root`, `dev-tooling`, or `apps/web`.
- For readability only, not matching.

### `contextSummary`

- Short human-readable explanation of why this repo currently needs the override.

## Quality rules

- `selector` and `target` must form a clear problem → solution pair.
- `evidenceTree[]` must be observed or reproducible, never guessed.
- `watch[]` should name real future removal levers, not just restate the vulnerable package.
- `obsoleteWhen[]` must be testable.
- `snykIds[]` should contain real Snyk references, not free labels.
- If the meaning of a field cannot be justified, do not write the case.

## Case reading shorthand

```text
selector      = what match is being overridden?
target        = what does that match resolve to instead?
package       = what package is affected?
snykIds       = which Snyk findings justify the case?
evidenceTree  = how does the package enter the repo?
watch         = which upstream levers should be monitored later?
obsoleteWhen  = when may the override be removed?
```

## Maintenance rules

- Use `scripts/overrides.py analyze` before strategy selection.
- Use `scripts/overrides.py read` when a concrete `key` is already known.
- Use `scripts/overrides.py list` for operational status overviews.
- Use `scripts/overrides.py upsert` to write new or changed cases.
- Use `scripts/overrides.py materialize` to sync active pnpm cases into `pnpm-workspace.yaml`.
- Use `scripts/overrides.py validate` to compare JSON materialization with the live pnpm configuration.
- Use `scripts/overrides.py remove` only when `obsoleteWhen[]` conditions are demonstrably satisfied.
- For non-canonical materialization names or example files, pass `--manager <manager>` explicitly to `analyze`, `read`, `list`, and `remove`.
- Read cases via `read` or `list`, not by manually interpreting raw JSON.
- Persist only valid materializations.

### `analyze` output semantics

`analyze` returns a deterministic query result:

- `query` — exact applied filters (`manager`, `package`, `snykId`, `status`, `checkSelector`)
- `matches[]` — full case objects satisfying all filters
- `summary.totalMatches` — number of matches
- `summary.statusCounts` — status distribution for the matches (`active`, `draft`, `obsolete`, `removed`)
- `summary.totalCases` — total number of cases in the materialization
- `summary.conflictingSelectors[]` — active or draft cases relevant to the checked selector; each entry has `conflictType`:
  - `exact-selector` = the same selector already exists
  - `same-package` = the same package already has a different selector case

Resolver rules:

- Before strategy selection, call `analyze --package <name>`.
- If an `active` case already exists for the same package, check whether the advisory is already covered with `--snyk-id`.
- Before a new `upsert`, use `--check-selector` to detect conflicts.
- `exact-selector` means the same selector already exists and should normally be reused or updated, not duplicated.
- `same-package` is a review signal, not automatic proof of a semver conflict.

## Deterministic creation and maintenance

- Do not invent materialization filenames.
- Do not create materialization files by hand.
- In this repo the operational file is `snyk-dep-overrides.pnpm.json` in the repo root.
- If it is missing, let `scripts/overrides.py upsert` create it.
- For pnpm, `pnpm-workspace.yaml` is the live target and must be kept in sync through `scripts/overrides.py materialize`, not manual editing.
- The agent should determine the case correctly; the script owns JSON creation, pnpm sync, and validation.
- The example under `examples/` is for understanding only, not as a write template.

## Expected output

A manager-specific file such as `snyk-dep-overrides.pnpm.json` that satisfies the schema contract and remains readable for agents.
