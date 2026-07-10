# snyk-session-init CLI usage

## Purpose

This reference owns the operational command patterns for seed validation and `ledger.py init`.

Use it when an agent needs the concrete CLI flow for turning a seed document into a new session ledger.

## Read help first

Before initialization:

- `python3 .github/skills/snyk-ledger-remediation/scripts/ledger.py --help`
- `python3 .github/skills/snyk-ledger-remediation/scripts/ledger.py init --help`

## Seed schema validation

Target-scoped seed:

- `pnpm dlx --package=ajv-cli --package=ajv-formats ajv validate -c ajv-formats --spec=draft2020 -s .github/skills/snyk-session-init/schemas/issues-ledger-seed.schema.json -d .synk/{sessionId}/issues-ledger-seed.json`

Project-scoped seed:

- `pnpm dlx --package=ajv-cli --package=ajv-formats ajv validate -c ajv-formats --spec=draft2020 -s .github/skills/snyk-session-init/schemas/project-issues-ledger-seed.schema.json -d .synk/{sessionId}/issues-ledger-seed.json`

AJV validates the seed contract. `ledger.py init` remains the canonical owner of advisory materialization into `issues-ledger.json`.

## Canonical materialization command

- `python3 .github/skills/snyk-ledger-remediation/scripts/ledger.py init --from .synk/{sessionId}/issues-ledger-seed.json --output .synk/{sessionId}/issues-ledger.json --session-id <sessionId>`

## Usage rules

- Make exactly one seed MCP call before local materialization.
- Persist the seed unchanged, including `$schema`.
- Use `.synk/{sessionId}/issues-ledger-seed.json` as the only input to `ledger.py init`.
- Do not rebuild `advisories[]` locally from `issues[]`.
- Treat seed validation and ledger materialization as separate steps.
