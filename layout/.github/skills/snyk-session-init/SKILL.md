---
name: snyk-session-init
description: Initialize a deterministic `.synk/{sessionId}` remediation session from one target-scoped or project-scoped Snyk seed call.
---

# snyk-session-init

## Purpose

Initialize a new `.synk/{sessionId}/` remediation session from one seed call and one deterministic local ledger materialization step.

## This skill owns

- taking `orgId` and exactly one of `targetId` or `projectId`
- making exactly one MCP seed call
- persisting the seed unchanged as `issues-ledger-seed.json`
- running `ledger.py init`
- creating `.snyk/GOTCHAS.md` if missing
- creating `.synk/{sessionId}/GOTCHAS.md` with the required session structure

## Fixed contract

- `status = open`
- `issueTypes = [package_vulnerability, code]`
- exactly one of `targetId` or `projectId`
- `targetId` → `snyk_get_target_ledger_seed(orgId, targetId)`
- `projectId` → `snyk_get_project_ledger_seed(orgId, projectId)`
- `ledger.py init` materializes the ledger from `advisories[]`; `issues[]` remain the canonical detail and validation context
- canonical seed issue fields are `issueKey`, `projectId`, and `issueType`
- no extra MCP calls between seed retrieval and ledger creation
- no local seed re-aggregation
- no handoff creation

## Canonical files

- `schemas/issues-ledger-seed.schema.json`
- `schemas/project-issues-ledger-seed.schema.json`
- `references/cli-usage.md`
- `../snyk-ledger-remediation/scripts/ledger.py`
- `../snyk-ledger-remediation/references/gotchas-policy.md`

## Script-first rules

- Validate seed JSON with `pnpm dlx ajv-cli ... --spec=draft2020` when needed.
- Read `python3 .github/skills/snyk-ledger-remediation/scripts/ledger.py --help` first.
- Before initialization, read `python3 .github/skills/snyk-ledger-remediation/scripts/ledger.py init --help`.
- Materialize only through `python3 .github/skills/snyk-ledger-remediation/scripts/ledger.py init --from .synk/{sessionId}/issues-ledger-seed.json --output .synk/{sessionId}/issues-ledger.json --session-id <sessionId>`.
- For the full validation and `ledger.py init` command patterns, read `references/cli-usage.md`.

## Sequence

1. Resolve `orgId`.
2. Choose exactly one path:
   - `snyk_get_targets` → `snyk_get_target_ledger_seed(orgId, targetId)`
   - `snyk_get_projects` → `snyk_get_project_ledger_seed(orgId, projectId)`
3. Write `.synk/{sessionId}/issues-ledger-seed.json` unchanged.
4. Run `ledger.py init`.
5. Create `.snyk/GOTCHAS.md` if missing.
6. Create `.synk/{sessionId}/GOTCHAS.md` from the session template.

## Guardrails

- Validate the seed; do not reshape it.
- Persist the MCP response unchanged, including `$schema`.
- Never rebuild `advisories[]` locally from `issues[]`.
- Never reinterpret scope heuristically: `targetId` stays target-scoped, `projectId` stays project-scoped.
- `issues-ledger-seed.json` is the only input artifact for `ledger.py init`.
- `snyk-session-init` owns only GOTCHAS file creation, not later curation.
- GOTCHAS structure must follow `../snyk-ledger-remediation/references/gotchas-policy.md`.
