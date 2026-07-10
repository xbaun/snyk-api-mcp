# snyk-ledger-remediation CLI usage

## Purpose

This reference owns the operational command patterns for `scripts/ledger.py` and ledger JSON validation.

Use it when an agent needs the concrete CLI flow for selection, update, failure persistence, cascade checks, or integrity checks.

## Read help first

Before using the script:

- `python3 .github/skills/snyk-ledger-remediation/scripts/ledger.py --help`
- `python3 .github/skills/snyk-ledger-remediation/scripts/ledger.py <subcommand> --help`

## Ledger schema validation

If ledger JSON validation is needed, use:

- `pnpm dlx --package=ajv-cli --package=ajv-formats ajv validate -c ajv-formats --spec=draft2020 -s .github/skills/snyk-ledger-remediation/schemas/issues-ledger.schema.json -d .synk/{sessionId}/issues-ledger.json`

AJV validates the persisted JSON contract. `ledger.py` remains the canonical owner of selection, update, and failure logic.

## Canonical command catalog

### Gate `[O1]` selection

- `python3 .github/skills/snyk-ledger-remediation/scripts/ledger.py select --ledger .synk/{sessionId}/issues-ledger.json --repo-root . --format json`

Optional operator overview:

- `python3 .github/skills/snyk-ledger-remediation/scripts/ledger.py analyze --ledger .synk/{sessionId}/issues-ledger.json --format json`

### Persist `in-progress` before resolver launch

- `python3 .github/skills/snyk-ledger-remediation/scripts/ledger.py set-status --ledger .synk/{sessionId}/issues-ledger.json --key <advisoryKey> --status in-progress`

### Persist validated handback

- `python3 .github/skills/snyk-ledger-remediation/scripts/ledger.py update --ledger .synk/{sessionId}/issues-ledger.json --key <advisoryKey> --from-handback -`

Use stdin-first handback transfer by default. Use `--from-handback <path>` only when a real operational file already exists.

If inline handback construction is used for operational tooling, include at minimum:

- `--issue-type <package_vulnerability|code>`
- `--status <...>`
- all required fields for that issue type and status according to `handback-format.md`

If inline handback construction is used for operational tooling, `temp-override` handbacks must carry both:

- `--overrides <JSON>` for `implementation.overridesApplied`
- `--override-preflight <JSON>` for `implementation.overridePreflight`

Example pre-flight payload:

- `--override-preflight '{"materializationPresent":true,"queryPackage":"esbuild","matchingCaseKeys":["esbuild-active"],"selectorConflict":"exact-selector","disposition":"reuse-existing-case"}'`

### Persist parse or format failure

- `python3 .github/skills/snyk-ledger-remediation/scripts/ledger.py record-failure --ledger .synk/{sessionId}/issues-ledger.json --key <advisoryKey> --kind <handback-parse|handback-format|resume|other> --error <message>`

### Cascade checks after successful dependency remediation

- `python3 .github/skills/snyk-ledger-remediation/scripts/ledger.py cascade-check --ledger .synk/{sessionId}/issues-ledger.json --package <packageName> --version <targetVersion> --dry-run`
- `python3 .github/skills/snyk-ledger-remediation/scripts/ledger.py cascade-check --ledger .synk/{sessionId}/issues-ledger.json --package <packageName> --version <targetVersion> --apply`

## Usage rules

- Start Gate `[O1]` with `ledger.py select --format json`.
- Interpret resume, dirty-stop, start, and done from the script output, not from manual JSON scanning.
- Never launch a resolver before persisted `in-progress`.
- Use `ledger.py update` for ledger mutation; never write ledger fields directly.
- Use `record-failure` for persisted resume, parse, or format failures.
- Apply cascade changes only after real dependency evidence confirms the vulnerable version is gone.
