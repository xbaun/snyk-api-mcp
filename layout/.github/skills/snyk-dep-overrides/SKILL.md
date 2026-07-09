---
name: snyk-dep-overrides
description: Own schemas, reference examples, and deterministic scripts for manager-specific Snyk dependency override materializations.
user-invocable: false
---

# snyk-dep-overrides

## Purpose

Own the traceable, manager-specific override materialization path for dependency overrides and resolutions.

## This skill owns

- the override materialization schema
- the canonical harness for override semantics
- manager-agnostic example structure
- deterministic JSON mutation through `scripts/overrides.py`

## Canonical files

- `schemas/snyk-dep-overrides.schema.json`
- `references/snyk-dep-overrides.harness.md`
- `references/cli-usage.md`
- `examples/snyk-dep-overrides.{{manager}}.example.json`
- `scripts/overrides.py` — `upsert`, `read`, `list`, `remove`, `materialize`, `validate`, `analyze`

## Script-first rules

- Use AJV only for schema validation.
- Use `python3 .github/skills/snyk-dep-overrides/scripts/overrides.py <subcommand>` for every operational change.
- Read `overrides.py --help` first.
- Before using a new subcommand, read `overrides.py <subcommand> --help`.
- For the full command catalog, pre-flight query patterns, and non-canonical filename handling, read `references/cli-usage.md`.

## Deterministic execution rules

- Resolvers decide whether an override is needed.
- This skill defines how override materialization is written and validated.
- Materializations are manager-specific; skill semantics remain manager-agnostic.
- New or changed cases must be validated before they are treated as complete.
- The field semantics live in the harness, not in ad-hoc resolver prose.
- The example file is reference material only, not a writing template.

## Hard constraints

- Do not create override files manually.
- Do not edit override JSON directly.
- The only allowed write path is `scripts/overrides.py upsert`.
- Do not invent materialization paths; use repo or handoff context.
- In this repo, the materialization file is `snyk-dep-overrides.pnpm.json`.
- In this repo, the live pnpm target is `pnpm-workspace.yaml`.
- If the materialization file is missing, let `overrides.py upsert` create it.
- After every active pnpm override `upsert`, run `overrides.py materialize`.
- Before claiming success for `temp-override`, require `overrides.py validate` to pass.

## Minimal agent sequence

1. Before strategy selection, inspect existing state with `scripts/overrides.py analyze`.
2. Use the harness to decide whether an override is allowed.
3. Use the repo-defined materialization path.
4. Create or update the case only through `scripts/overrides.py upsert`.
5. Synchronize active pnpm cases with `scripts/overrides.py materialize --workspace pnpm-workspace.yaml`.
6. Validate JSON and live pnpm configuration with `scripts/overrides.py validate --workspace pnpm-workspace.yaml`.
7. Read existing cases only through `read` or `list`.
8. Remove cases only through `remove`, and only when `obsoleteWhen[]` conditions are met.

## `analyze` is the pre-flight entrypoint

Use `analyze` first to answer:

- does a case for this package already exist?
- does an existing case already cover this Snyk ID?
- would a new selector conflict with an existing case?
- what is the current filtered state by status?

The meaning of `matches[]`, `summary.*`, and selector conflict rules is canonical in `references/snyk-dep-overrides.harness.md`.
The concrete `analyze`, `read`, `list`, `upsert`, `materialize`, `validate`, and `remove` command patterns are canonical in `references/cli-usage.md`.

## Does not own

- dependency strategy selection itself
- project or ledger selection
- unrelated repo mutations outside override materialization
