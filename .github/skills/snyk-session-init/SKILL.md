---
name: snyk-session-init
description: Initialize a deterministic `.synk/{sessionId}` remediation session from one target-scoped or project-scoped Snyk seed call.
---

# snyk-session-init

## Zweck

Erzeugt eine neue `.synk/{sessionId}/` Session auf Basis eines einzigen semantischen MCP-Calls und eines deterministischen lokalen Ledger-Materialisierungsschritts.

## Verantwortung

- `orgId` und genau **eines** von `targetId` oder `projectId` entgegennehmen
- genau **einen** MCP-Call verwenden: `snyk_get_target_ledger_seed` oder `snyk_get_project_ledger_seed`
- das Seed-Dokument unverändert als `issues-ledger-seed.json` persistieren
- `ledger.py init` aus `.github/skills/snyk-orchestration/scripts/ledger.py` aufrufen
- `.snyk/GOTCHAS.md` erzeugen, falls die permanente Datei noch fehlt
- `.synk/{sessionId}/GOTCHAS.md` mit klarer Ownership- und Sections-Struktur erzeugen

## Fester Contract

- `status = open`
- `issueTypes = [package_vulnerability, code]`
- genau eines von `targetId` oder `projectId`
- `targetId` → `snyk_get_target_ledger_seed(orgId, targetId)`
- `projectId` → `snyk_get_project_ledger_seed(orgId, projectId)`
- `ledger.py init` materialisiert das Ledger aus `advisories[]`; `issues[]` bleiben kanonischer Detail- und Validierungskontext
- kanonische Seed-Issue-Felder heißen `issueKey`, `projectId`, `issueType` — keine Legacy-Aliase wie `key`, `scanItemId`, `type`
- keine weiteren MCP-Calls zwischen Seed und Ledger
- keine lokale Re-Aggregation des Seeds
- keine Handoff-Erzeugung

## Dateien

- `schemas/issues-ledger-seed.schema.json` — kanonischer Seed-Contract
- `schemas/project-issues-ledger-seed.schema.json` — kanonischer Project-Seed-Contract
- nutzt `../snyk-orchestration/scripts/ledger.py` für `init`
- nutzt `../snyk-orchestration/references/gotchas-policy.md` als normative GOTCHAS-Policy

## Tools

- Seed-Schema-Validierung erfolgt normativ über `pnpm dlx ajv-cli`.
- Beide Seed-Schemas verwenden Draft 2020-12; AJV CLI braucht daher immer `--spec=draft2020`.
- Kanonische Schema-Checks:
	- target-scoped: `pnpm dlx ajv-cli validate --spec=draft2020 -s .github/skills/snyk-session-init/schemas/issues-ledger-seed.schema.json -d .synk/{sessionId}/issues-ledger-seed.json`
	- project-scoped: `pnpm dlx ajv-cli validate --spec=draft2020 -s .github/skills/snyk-session-init/schemas/project-issues-ledger-seed.schema.json -d .synk/{sessionId}/issues-ledger-seed.json`
- Die operative Ledger-Materialisierung erfolgt nicht per Hand und nicht per AJV, sondern ausschließlich über `python3 .github/skills/snyk-orchestration/scripts/ledger.py init`.
- Vor Ausführung zuerst Hilfe lesen:
	- `python3 .github/skills/snyk-orchestration/scripts/ledger.py --help`
	- `python3 .github/skills/snyk-orchestration/scripts/ledger.py init --help`
- Kanonisches Materialisierungs-Muster:
	- `python3 .github/skills/snyk-orchestration/scripts/ledger.py init --from .synk/{sessionId}/issues-ledger-seed.json --output .synk/{sessionId}/issues-ledger.json --session-id <sessionId>`
- AJV validiert den Seed-Contract; die Advisory-Materialisierung aus `advisories[]` und die Konsistenz des Ledgers werden normativ durch `ledger.py init` durchgesetzt.

## Ablauf

1. `snyk_resolve_org_id`
2. entweder:
	- `snyk_get_targets` → `snyk_get_target_ledger_seed(orgId, targetId)`
	- `snyk_get_projects` → `snyk_get_project_ledger_seed(orgId, projectId)`
3. `.synk/{sessionId}/issues-ledger-seed.json` schreiben
4. `python3 .github/skills/snyk-orchestration/scripts/ledger.py init --from ... --output ... --session-id ...`
5. `.snyk/GOTCHAS.md` anlegen, falls sie fehlt
6. `.synk/{sessionId}/GOTCHAS.md` mit Session-Template anlegen

## Guardrails

- Seed-Dokument nur validieren, nicht umformen
- den MCP-Response unverändert persistieren, inklusive `$schema`
- `advisories[]` nie lokal aus `issues[]` nachbauen; wenn `ledger.py init` scheitert, ist das ein Contract- oder Datenfehler, kein Anlass für Feld-Mapping
- den Scope nie heuristisch umdeuten: `targetId` bleibt target-scoped, `projectId` bleibt project-scoped
- Session-Id ist ein UTC-ISO-Timestamp ohne Doppelpunkte im Zeitteil
- `issues-ledger-seed.json` ist das einzige Input-Artefakt für `ledger.py init`
- `snyk-session-init` besitzt nur die **Initialisierung** der GOTCHAS-Dateien, nicht deren spätere Kuratierung
- die Struktur der GOTCHAS-Dateien folgt verbindlich `../snyk-orchestration/references/gotchas-policy.md`
