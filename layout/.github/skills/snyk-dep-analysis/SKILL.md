---
name: snyk-dep-analysis
description: Deterministic dependency fact gathering and verification for resolver agents via manager adapters with auto-selection.
user-invocable: false
---

# snyk-dep-analysis

## Purpose

Provide the deterministic read path for dependency facts so resolvers do not have to parse large lockfiles or graph artifacts manually.

## This skill owns

- manager selection through a small adapter registry
- deterministic detection of supported managers
- compact JSON fact sets for dependency resolvers
- normalized direct declarations, transitive paths, and verification facts
- replacing raw lockfile reading with stable analysis commands

## Supported managers

- `pnpm` — fully supported
- `npm` — supported through deterministic `package-lock.json` analysis
- `yarn` — supported for Yarn Classic `yarn.lock` v1

## Canonical files

- `references/harness.md` — output semantics, auto-selection rules, and command intent
- `references/cli-usage.md` — canonical query sequences and argument patterns
- `scripts/dep.py` — `inspect`, `trace`, `verify`

## Script-first rules

- Use only `python3 .github/skills/snyk-dep-analysis/scripts/dep.py <subcommand>`.
- Read `dep.py --help` before first use.
- Read `dep.py <subcommand> --help` before using a new subcommand.
- For the full `inspect` / `trace` / `verify` sequence, fallback rules, and interpretation rules, read `references/cli-usage.md`.

## Canonical commands

- Fact set:
  - `python3 .github/skills/snyk-dep-analysis/scripts/dep.py inspect --repo-root . --package-name <name> --workspace-package <workspace | unknown>`
- Dependency trace:
  - `python3 .github/skills/snyk-dep-analysis/scripts/dep.py trace --repo-root . --package-name <name> --workspace-package <workspace | unknown>`
- Verification:
  - `python3 .github/skills/snyk-dep-analysis/scripts/dep.py verify --repo-root . --package-name <name> --workspace-package <workspace | unknown> --vulnerable-version <version>`

`references/cli-usage.md` is the canonical place for the full query flow, including `purl` fallback and repeated `--vulnerable-version` usage.

## Rules

- Prefer `dep.py` whenever `inspect`, `trace`, or `verify` covers the needed fact.
- Do not read large lockfiles manually when `dep.py` can provide the same fact set.
- Keep manager-specific complexity inside adapters, not in prompt logic.
- Keep JSON output small, stable, and resolver-oriented.
- Extend support through new adapters, not resolver-side branching.

## Does not own

- override materialization
- ledger updates
- remediation strategy choice
- speculative support for package managers without a real need
