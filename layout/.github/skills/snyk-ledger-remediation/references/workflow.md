# snyk-ledger-remediation workflow

## Purpose

This workflow is normative. `snyk-ledger-remediation` must follow it exactly.

## Normative sequence

1. **Gate [O1] — Selection**
   - Run `ledger.py select --ledger ... --repo-root . --format json`.
   - Derive `resume`, `dirty-stop`, `start`, or `done` only from that result.
   - Optional operator view: `ledger.py analyze --ledger ... --format json`.
   - If starting new work, persist `in-progress` with `ledger.py set-status --key <advisoryKey> --status in-progress`.

2. **Gate [O2] — Dispatch**
   - Select the resolver from `issueType` only.

3. **Gate [O3] — Handoff Build**
   - Build the handoff exactly as defined in `handoff-format.md`.
   - Filter seed issues by `advisoryKey`.

4. **Resolver Run**
   - Run `snyk-resolve-dep` or `snyk-resolve-code` exactly once.

5. **Gate [O4] — Handback Validation**
   - Validate the handback exactly against `handback-format.md`.
   - On parse or format failure, persist the error with `ledger.py record-failure`.

6. **Gate [O5] — Override Validation**
   - Run only if overrides were reported.

7. **Gate [O6] — Code Health Validation**
   - Check minimum consistency of claimed verification results.

8. **Gate [O7] — Ledger Update**
   - Persist the validated handback with `ledger.py update --from-handback -`.
   - Confirm JSON integrity afterward.

9. **Gate [O8] — Cascade Check**
   - Run only for `package_vulnerability` with `status=resolved`.

10. **Gate [O9] — GOTCHAS Curation**
   - Review session GOTCHAS.
   - Promote durable rules to `.snyk/GOTCHAS.md` when justified.

11. **Loop**
   - Return to Gate `[O1]` until selection returns `done`.

## Hard invariants

- Never edit `issues-ledger.json` directly.
- Never reconstruct Gate `[O1]` by scanning raw ledger JSON.
- Never dispatch from anything other than `issueType`.
- Never start a resolver without persisted `in-progress`.
- Never guess or silently repair handback content.
- Never apply a cascade close without real lockfile or dependency evidence.
- Never let resolvers write directly to `.snyk/GOTCHAS.md`.

## Minimal decision tree

```text
run ledger.py select
└─ in-progress exists?
   ├─ yes → dirty?
   │  ├─ yes → stop and require explicit user decision
   │  └─ no → resume that advisory
   └─ no → choose first not-started advisory by deterministic sort
      ├─ none → done
      └─ set-status(in-progress)
         └─ issueType?
            ├─ package_vulnerability → dep resolver
            └─ code → code resolver
```

## Advisory end states

Each advisory run ends in exactly one of these states:

- `resolved`
- `blocked`
- `partially-resolved`

There is no fourth semantic end state.

## GOTCHAS ownership in the loop

- `snyk-session-init` creates the files.
- Resolvers append advisory-specific learnings only to `.synk/{sessionId}/GOTCHAS.md`.
- `snyk-ledger-remediation` may also append coordination notes there.
- Only `snyk-ledger-remediation` promotes durable rules to `.snyk/GOTCHAS.md`.
- Resume and failure state must also be persisted in the ledger.
