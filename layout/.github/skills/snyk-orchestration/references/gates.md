# snyk-orchestration gates

## Gate [O1] — Selection

### Goal

Select exactly one advisory deterministically, or stop cleanly.

### Input

- `.synk/{sessionId}/issues-ledger.json`
- repo status from `git status --porcelain`

### Steps

1. Run `python3 .github/skills/snyk-orchestration/scripts/ledger.py select --ledger .synk/{sessionId}/issues-ledger.json --repo-root . --format json`.
2. Interpret only the returned `decision` field.
3. Allowed decisions:
   - `resume` → resume the one advisory already in progress
   - `dirty-stop` → do not continue automatically; require explicit user choice such as `reset` or `resume-with-risk`
   - `start` → `selectedAdvisory` is the first `not-started` advisory by deterministic sort:
     1. `issueType` (`package_vulnerability` before `code`)
     2. severity (`critical`, `high`, `medium`, `low`)
     3. `riskScoreMax` desc
     4. `affectedProjectCount` desc
     5. `issueCount` desc
     6. `createdAt` asc
     7. `advisoryKey` asc
   - `done` → stop the run
4. If `decision == "start"`, persist `in-progress` with `ledger.py set-status --ledger .synk/{sessionId}/issues-ledger.json --key <advisoryKey> --status in-progress`.

### Runtime metadata

- `set-status --status in-progress` sets `lastAttemptAt`.
- Resume-relevant failures must also be persisted with `ledger.py record-failure`.

### Pass

- exactly one advisory is selected and persisted as `in-progress`

### Stop or fail

- invalid or unreadable ledger
- more than one `in-progress` advisory
- dirty repo without explicit user decision

### Forbidden

- reconstructing `resume`, `start`, or `done` by scanning raw ledger JSON
- using any sort order other than `ledger.py select`

---

## Gate [O2] — Dispatch

### Goal

Choose the resolver from `issueType` only.

### Steps

- `issueType == "package_vulnerability"` → `snyk-resolve-dep`
- `issueType == "code"` → `snyk-resolve-code`
- any other value → hard contract error

### Pass

- exactly one resolver is selected

### Forbidden

- heuristics based on title, severity, package name, or file path
- fallback resolvers

---

## Gate [O3] — Handoff Build

### Goal

Build one deterministic resolver briefing from ledger + seed.

### Input

- `.synk/{sessionId}/issues-ledger.json`
- `.synk/{sessionId}/issues-ledger-seed.json`
- the selected advisory

### Steps

1. Find all `issues[]` in `issues-ledger-seed.json` with the same `advisoryKey`.
2. Copy advisory metadata from `issues-ledger.json`.
3. Build the handoff exactly as defined in `references/handoff-format.md`.
4. Include at least one representative issue instance with all required fields for the `issueType`.
5. For `package_vulnerability`:
   - keep `packageName` unchanged as the primary compact identity
   - keep `purl` unchanged as the exact fallback identity
   - treat `workspacePackage` only as a scope hint; use `unknown` when no reliable value exists
   - do not invent alternate package names or run extra package discovery before the resolver starts
6. Include only issue-type-relevant static context files, not extra discovery steps.
7. Include GOTCHAS files with their roles:
   - `.snyk/GOTCHAS.md` = permanent read-only resolver context
   - `.synk/{sessionId}/GOTCHAS.md` = session file that resolvers may append to when policy requires it

### Pass

- the handoff contains all required fields and at least one representative issue instance

### Forbidden

- local re-aggregation
- extra MCP calls before the resolver starts
- implicit defaults outside the documented format
- dep-analysis or override context in a `code` handoff when the resolver does not need it
- heuristic rewriting of `packageName`, `purl`, or `workspacePackage`

---

## Gate [O4] — Handback Validation

### Goal

Validate resolver output strictly before anything touches the ledger.

### Steps

1. Parse the handback as exactly one JSON object.
2. Check `issueType` against the handoff.
3. Check `status` against the allowed set:
   - dep: `resolved | partially-resolved | blocked`
   - code: `resolved | blocked`
4. Check required fields against `references/handback-format.md`.
5. Check consistency:
   - `blocked` requires `outcome.remediationProposal` and `outcome.rationale`
   - dep `resolved` or `partially-resolved` requires `verification.dependencyCheck`
   - claimed verification fields must reflect real executed results
6. If parsing or format validation fails:
   - persist the error with `ledger.py record-failure --kind handback-parse|handback-format`
   - return a precise error message
   - treat the advisory as `blocked`

### Pass

- the handback is complete, internally consistent, and valid for its `issueType`

### Forbidden

- silently repairing domain content
- guessing missing fields

---

## Gate [O5] — Override Validation

### Goal

Accept override-based remediation only when materialization and repo state agree.

### Trigger

Run only when the dep handback reports non-empty `implementation.overridesApplied`.

### Steps

1. Confirm that `snyk-dep-overrides.pnpm.json` exists.
2. Require evidence that the resolver checked existing state with `overrides.py analyze` before adding a new temp override.
3. Require `overrides.py materialize --workspace pnpm-workspace.yaml` when `temp-override` was used.
4. Validate deterministically with `overrides.py validate --materialization snyk-dep-overrides.pnpm.json --workspace pnpm-workspace.yaml`.
5. Confirm that the override reported in the handback matches the validated materialized state.
6. On failure, treat the advisory as `blocked`.

### Pass

- override materialization is valid and matches the real repo changes

---

## Gate [O6] — Code Health Validation

### Goal

Check minimum consistency of claimed verification results before ledger update.

### Steps

- For dep handbacks:
  - `verification.dependencyCheck` must be `pass` when `status == "resolved"`
- For both resolvers:
  - if `lint` or `typecheck` is reported as `pass`, it must not be known as failed in the same run
  - `tests` and `build` are optional, but when present they must carry real states

### Pass

- verification data is consistent with the claimed outcome

---

## Gate [O7] — Ledger Update

### Goal

Persist the validated handback into `issues-ledger.json` deterministically.

### Steps

1. Run `ledger.py update --ledger ... --key ... --from-handback -` and pass the validated handback through stdin.
2. Use `--from-handback <path>` only when the handback already exists as a real operational file.
3. Re-check ledger JSON integrity.
4. Never write ledger fields directly.

### Pass

- the ledger is updated and remains valid JSON

---

## Gate [O8] — Cascade Check

### Goal

After a successful dependency remediation, identify other candidate advisories for the same vulnerability and optionally close them.

### Trigger

Run only when:

- `issueType == "package_vulnerability"`
- `status == "resolved"`

### Steps

1. Run `ledger.py cascade-check --dry-run`.
2. Validate candidates against real lockfile or dependency evidence.
3. Only if the vulnerable version is truly gone, run `ledger.py cascade-check --apply`.
4. There is no cascade check for `code` advisories.

### Pass

- only real cascades are marked

### Forbidden

- string matching without lockfile or dependency-graph evidence
- cascade apply for `blocked` or `partially-resolved`

---

## Gate [O9] — GOTCHAS Curation

### Goal

Enforce GOTCHAS ownership, write duty, and promotion deterministically.

### Input

- `.synk/{sessionId}/GOTCHAS.md`
- `.snyk/GOTCHAS.md`
- the validated advisory result

### Steps

1. Check whether the resolver should have written a session GOTCHA under policy.
2. If a loop, resume, failure, or cascade issue occurred, write an orchestration session GOTCHA.
3. Review new session entries for promotion value.
4. Promote only durable, repo-specific, reusable rules to `.snyk/GOTCHAS.md`.
5. Deduplicate or update existing permanent rules instead of blindly appending duplicates.

### Pass

- session learnings are documented
- permanent rules are updated when warranted

### Forbidden

- direct resolver writes to `.snyk/GOTCHAS.md`
- promotion of one-off notes with no reuse value
