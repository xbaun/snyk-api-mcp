# snyk-override-revalidation workflow

## Purpose

This workflow is normative for override hygiene work on the repo's dependency override materialization.

## Normative sequence

1. Enumerate existing override cases from `snyk-dep-overrides.pnpm.json`.
2. Select one concrete override case or one concrete vulnerable package to review.
3. Inspect current override coverage with `overrides.py analyze`.
4. Gather active dependency evidence with `dep.py inspect`, `dep.py trace`, and `dep.py verify` as needed.
5. Decide one of:
   - `keep`
   - `narrow`
   - `remove`
6. Apply the change only through `overrides.py`.
7. Re-materialize active state when the manager requires it.
8. Run `overrides.py validate`.
9. Report the decision and evidence.

## Hard invariants

- Never depend on `.synk/{sessionId}/issues-ledger.json`.
- Never remove an override on heuristics alone.
- Never edit `snyk-dep-overrides.pnpm.json` by hand.
- Never report success without post-change validation.
- Prefer keeping an override over removing it when dependency evidence is incomplete.

## Decision model

```text
existing override case
└─ still covers reachable vulnerable version?
   ├─ yes → keep
   └─ no
      └─ can selector/range be narrowed safely?
         ├─ yes → narrow
         └─ remove
```
