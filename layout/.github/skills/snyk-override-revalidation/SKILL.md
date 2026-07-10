---
name: snyk-override-revalidation
description: Revalidate existing dependency overrides and remove or narrow them when the dependency graph no longer requires them.
---

# snyk-override-revalidation

## Purpose

Inspect and maintain the repo's dependency override materialization:

- inspect current override cases
- verify whether the vulnerable transitive version is still reachable
- decide whether each override is still necessary
- remove or narrow stale overrides safely
- validate the materialized override file after changes

## Use this skill when

Use it when an override already exists and you want to verify whether it still reflects the active dependency graph.

Typical triggers:

- revalidate Snyk dependency overrides
- check whether existing pnpm overrides are still needed
- remove stale temporary security overrides
- audit override drift after dependency upgrades

## Inputs

- `snyk-dep-overrides.pnpm.json`
- `pnpm-workspace.yaml`
- current manifests and lockfiles
- optional advisory metadata when available

## Read first

Use these canonical files:

- `../snyk-dep-overrides/SKILL.md`
- `../snyk-dep-overrides/references/cli-usage.md`
- `../snyk-dep-overrides/references/snyk-dep-overrides.harness.md`
- `../snyk-dep-overrides/scripts/overrides.py`
- `../snyk-dep-analysis/SKILL.md`
- `../snyk-dep-analysis/references/cli-usage.md`
- `../snyk-dep-analysis/references/harness.md`
- `../snyk-dep-analysis/scripts/dep.py`
- `references/workflow.md`
- `references/cli-usage.md`
- `AGENTS.md`

## Non-negotiable invariants

- This skill does not require or mutate `.synk/{sessionId}/issues-ledger.json`.
- Never handcraft override JSON.
- Always inspect existing state before removing or changing an override.
- Do not claim an override is removable unless dependency evidence shows the vulnerable version is no longer active.
- After every change, validate the materialized override state deterministically.

## Minimal sequence

1. Inspect current override state with `overrides.py analyze` or `list`.
2. For each candidate case, gather dependency evidence with `dep.py inspect|trace|verify`.
3. Decide whether the override remains necessary.
4. If stale, remove or narrow it through `overrides.py`.
5. Re-materialize when needed.
6. Validate with `overrides.py validate`.
7. Report which overrides were kept, narrowed, or removed and why.

## Does not own

- new session creation
- advisory dispatch from the ledger
- resolver handoff/handback protocol
- fresh remediation of unrelated open advisories

## Output expectation

Return a concise, structured result that states:

- which override cases were reviewed
- which were kept, narrowed, or removed
- what dependency evidence justified the decision
- what validation commands passed
