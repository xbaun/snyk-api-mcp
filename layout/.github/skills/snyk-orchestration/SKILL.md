---
name: snyk-orchestration
description: Orchestrate deterministic advisory processing from `issues-ledger.json`, including selection, dispatch, validation, and ledger updates.
---

# snyk-orchestration

## Purpose

Process an existing `.synk/{sessionId}/issues-ledger.json` deterministically.

This skill owns:

- advisory selection
- resolver dispatch by `issueType`
- handoff construction
- handback validation
- ledger updates through `ledger.py`
- cascade checks
- GOTCHAS curation and promotion

## Use this skill when

Use it for an existing remediation session that must continue strictly from the ledger state, not from free-form planning.

Typical triggers:

- orchestrate Snyk remediation session
- continue issues-ledger loop
- process next advisory from issues-ledger
- validate resolver handback
- update issues-ledger deterministically

## Non-negotiable invariants

- Use `ledger.py` for every ledger decision and mutation.
- Never edit `issues-ledger.json` directly.
- Start Gate `[O1]` with `ledger.py select --format json`.
- Persist `in-progress` before launching a resolver.
- Dispatch only by `issueType`.
- Use only the documented handoff and handback formats.
- Treat `blocked` and `partially-resolved` as skipped in later selection.
- Run cascade checks only for `package_vulnerability` with `status=resolved`.

## Script-first operation

- Read `python3 .github/skills/snyk-orchestration/scripts/ledger.py --help` first.
- Before using a subcommand, read `python3 .github/skills/snyk-orchestration/scripts/ledger.py <subcommand> --help`.
- If a `ledger.py` command exists for the task, do not reconstruct the logic from raw JSON.
- If ledger JSON validation is needed, use `pnpm dlx ajv-cli validate --spec=draft2020 -s .github/skills/snyk-orchestration/schemas/issues-ledger.schema.json -d .synk/{sessionId}/issues-ledger.json`.
- For the full command catalog for `select`, `analyze`, `set-status`, `update`, `record-failure`, and `cascade-check`, read `references/cli-usage.md`.

## Canonical references

Read these in order:

1. `references/workflow.md`
2. `references/gates.md`
3. `references/cli-usage.md`
4. `references/handoff-format.md`
5. `references/handback-format.md`
6. `references/gotchas-policy.md`

If a decision is not defined there, do not invent one.

## Gate set

- `Gate [O1] — Selection`
- `Gate [O2] — Dispatch`
- `Gate [O3] — Handoff Build`
- `Gate [O4] — Handback Validation`
- `Gate [O5] — Override Validation`
- `Gate [O6] — Code Health Validation`
- `Gate [O7] — Ledger Update`
- `Gate [O8] — Cascade Check`
- `Gate [O9] — GOTCHAS Curation`

`references/gates.md` is the canonical gate definition.

## Resolver routing

- `issueType = package_vulnerability` → `snyk-resolve-dep`
- `issueType = code` → `snyk-resolve-code`

Any other `issueType` is a contract error.

## Minimal loop

1. Select with `ledger.py select --format json`.
2. If starting new work, persist `in-progress` with `ledger.py set-status`.
3. Build the handoff exactly as documented.
4. Run the matching resolver exactly once.
5. Validate the handback exactly as documented.
6. Record parse or format failures with `ledger.py record-failure`.
7. Persist the validated result with `ledger.py update --from-handback -`.
8. If applicable, run `ledger.py cascade-check`.
9. Curate session GOTCHAS and promote durable rules.
10. Return to Gate `[O1]` until selection returns `done`.

## Does not own

- session creation
- seed aggregation
- override semantics
- dependency fact gathering
- resolver-specific remediation logic

This skill is intentionally runbook-first: procedure before interpretation.
