# Snyk skill topology

This repository now distinguishes two separate top-level workflows for downstream agent layouts.

## Why the split matters

There are actually two different jobs:

1. **Ledger-based remediation**
   - work from `.synk/{sessionId}/issues-ledger.json`
   - fix or document advisory work items
   - use temporary dependency overrides when needed
   - update the ledger deterministically
2. **Override revalidation**
   - work from the current override materialization and dependency graph
   - re-check whether existing dependency overrides are still needed
   - remove overrides when updated upstream packages or transitive graph changes made them unnecessary
   - keep the override file honest over time

These jobs have different:

- inputs
- stopping conditions
- success criteria
- operator expectations

So they should not share one vague top-level name.

## Recommended top-level names

### `snyk-ledger-remediation`

Why this name fits:

- says exactly what drives the workflow: the ledger
- says exactly what the workflow is doing: remediation
- does not imply long-term ownership of all dependency hygiene tasks
- stays compatible with the current resolver model (`snyk-resolve-dep`, `snyk-resolve-code`)

Scope:

- select one advisory from the ledger
- dispatch the correct resolver
- validate handback
- update the ledger
- run cascade checks
- curate GOTCHAS for the remediation session

### `snyk-override-revalidation`

Recommended top-level skill for override cleanup and re-checks.

Why this name fits:

- names the main artifact explicitly: overrides
- names the real action explicitly: revalidation
- makes the independence from the ledger obvious
- avoids implying that the skill should also remediate arbitrary fresh advisories

Scope:

- inspect current override state
- verify whether the vulnerable transitive version is still reachable
- decide whether an override remains necessary
- remove or narrow stale overrides safely
- validate the materialized override file after changes

## Naming guidance

Prefer names that describe the operator entry point, not internal implementation style.

Good top-level names in this layout tend to follow this pattern:

- `snyk-session-init`
- `snyk-ledger-remediation`
- `snyk-override-revalidation`

This is clearer than names based on broad internal mechanics alone.

## Current layout

The current repository layout uses:

- `layout/.github/skills/snyk-ledger-remediation/SKILL.md`
- `layout/.github/skills/snyk-override-revalidation/SKILL.md`
