# snyk-dep-overrides CLI usage

## Purpose

This reference owns the operational command patterns for `scripts/overrides.py`.

Use it when an agent needs the concrete CLI flow for inspect, write, sync, validate, or cleanup work.

## Read help first

Before using the script:

- `python3 .github/skills/snyk-dep-overrides/scripts/overrides.py --help`
- `python3 .github/skills/snyk-dep-overrides/scripts/overrides.py <subcommand> --help`

## `analyze` — resolver pre-flight queries

`analyze` is the first entrypoint before strategy selection. Use it to answer:

- does a case for this package already exist? → `--package <name>`
- does an existing case already cover this Snyk ID? → `--snyk-id <id>`
- does this selector already exist, exactly or for the same package? → `--check-selector <selector>`
- what is the filtered state by status? → `--status active|draft|obsolete|removed`

All flags are combinable.

### `analyze` output

- `query` — exact applied filters, including optional `manager`
- `matches[]` — full case objects that satisfy all filters
- `summary.totalMatches` — number of matches
- `summary.statusCounts` — status distribution for the matches
- `summary.totalCases` — total case count in the materialization
- `summary.conflictingSelectors[]` — relevant active or draft selector conflicts when `--check-selector` is used

Conflict types:

- `exact-selector` = the same selector already exists
- `same-package` = the same package already has a different selector case

## Canonical command catalog

### Check existing state before strategy selection

- `python3 .github/skills/snyk-dep-overrides/scripts/overrides.py analyze --materialization snyk-dep-overrides.pnpm.json --package <name>`
- `python3 .github/skills/snyk-dep-overrides/scripts/overrides.py analyze --materialization snyk-dep-overrides.pnpm.json --package <name> --snyk-id <id>`
- `python3 .github/skills/snyk-dep-overrides/scripts/overrides.py analyze --materialization snyk-dep-overrides.pnpm.json --package <name> --check-selector <selector> --status active`

### Read a known case

- `python3 .github/skills/snyk-dep-overrides/scripts/overrides.py read --materialization snyk-dep-overrides.pnpm.json --key <caseKey>`

### Get an operational overview

- `python3 .github/skills/snyk-dep-overrides/scripts/overrides.py list --materialization snyk-dep-overrides.pnpm.json --status active`

### Write or update a case

- `python3 .github/skills/snyk-dep-overrides/scripts/overrides.py upsert --materialization snyk-dep-overrides.pnpm.json ...`

### Synchronize active pnpm cases

- `python3 .github/skills/snyk-dep-overrides/scripts/overrides.py materialize --materialization snyk-dep-overrides.pnpm.json --workspace pnpm-workspace.yaml`

### Validate JSON + live manager config

- `python3 .github/skills/snyk-dep-overrides/scripts/overrides.py validate --materialization snyk-dep-overrides.pnpm.json --workspace pnpm-workspace.yaml`

### Remove a case deterministically

- `python3 .github/skills/snyk-dep-overrides/scripts/overrides.py remove --materialization snyk-dep-overrides.pnpm.json --key <caseKey>`

## Non-canonical materialization names

If the materialization filename does not follow `snyk-dep-overrides.<manager>.json`, pass `--manager <manager>` explicitly to:

- `analyze`
- `read`
- `list`
- `remove`

Examples:

- `python3 .github/skills/snyk-dep-overrides/scripts/overrides.py analyze --materialization .github/skills/snyk-dep-overrides/examples/snyk-dep-overrides.{{manager}}.example.json --manager pnpm --package example-package`
- `python3 .github/skills/snyk-dep-overrides/scripts/overrides.py read --materialization .github/skills/snyk-dep-overrides/examples/snyk-dep-overrides.{{manager}}.example.json --manager pnpm --key example-security-override`

## Interpretation rules

- Use `analyze` as the decision surface; do not infer broader repo state from `summary.conflictingSelectors[]` alone.
- `exact-selector` usually means reuse or update, not duplication.
- `same-package` is a review signal, not automatic proof of a semver conflict.
- Use `read` only after `analyze` or another deterministic source has produced a concrete `key`.
- Use `list` for overview, not as a substitute for `analyze` when deciding coverage.
- Do not invent alternate filenames or locations.
- Use the example file only as a shape reference, never as an editable template.
