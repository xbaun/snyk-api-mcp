---
name: snyk-orchestration
description: Orchestrate deterministic advisory processing from `issues-ledger.json`, including selection, dispatch, validation, and ledger updates.
---

# snyk-orchestration

## Zweck

Arbeitet `issues-ledger.json` deterministisch ab, routet pro `issueType` an den passenden Resolver und schreibt ausschließlich über `ledger.py` in das Ledger zurück.

## Wann dieser Skill verwendet wird

Nutze diesen Skill, wenn eine bestehende `.synk/{sessionId}/`-Session sequenziell abgearbeitet werden soll und der Agent **ohne freie Interpretation** aus dem vorhandenen Ledger den nächsten Schritt ableiten muss.

Trigger-Begriffe:

- orchestrate Snyk remediation session
- continue issues-ledger loop
- process next advisory from issues-ledger
- validate resolver handback
- update issues-ledger deterministically

## Einstieg über `ledger.py`

Bevor du irgendwelche Ledger-Entscheidungen triffst, orientiere dich **am Script selbst**:

1. Das Script liegt unter `./.github/skills/snyk-orchestration/scripts/ledger.py`.
2. Lies zuerst die Top-Level-Hilfe des Scripts.
3. Lies danach die Hilfe **des konkreten Subcommands**, das du gleich benutzen willst.
4. Rate keine Flags und rekonstruiere keine Ledger-Logik aus Roh-JSON, wenn das Script bereits ein passendes Command hat.

Praktische Leitlinie pro Loop:

- Gate [O1] beginnt mit `ledger.py select --format json`
- vor Resolver-Start folgt `ledger.py set-status --key <advisoryKey> --status in-progress`
- nach validiertem Handback folgt `ledger.py update`
- bei Resume-/Parse-/Format-Problemen folgt `ledger.py record-failure`
- nach erfolgreicher Dependency-Resolution folgt ggf. `ledger.py cascade-check`

Wenn unklar ist, welches Flag oder welches Command zu verwenden ist, ist die richtige nächste Aktion **nicht** das Ledger manuell zu lesen, sondern die CLI-Hilfe von `ledger.py` bzw. `ledger.py <command> --help` zu lesen.

## Tools

- JSON-Schema-Validierung für das Ledger erfolgt normativ über `pnpm dlx ajv-cli`.
- Da `schemas/issues-ledger.schema.json` Draft 2020-12 verwendet, muss AJV CLI immer mit `--spec=draft2020` aufgerufen werden.
- Kanonisches Schema-Check-Muster:
	- `pnpm dlx ajv-cli validate --spec=draft2020 -s .github/skills/snyk-orchestration/schemas/issues-ledger.schema.json -d .synk/{sessionId}/issues-ledger.json`
- Die operative Bedienung des Ledgers erfolgt ausschließlich über `python3 .github/skills/snyk-orchestration/scripts/ledger.py <subcommand>`.
- Vor jeder Benutzung zuerst CLI-Hilfe lesen:
	- `python3 .github/skills/snyk-orchestration/scripts/ledger.py --help`
	- `python3 .github/skills/snyk-orchestration/scripts/ledger.py <subcommand> --help`
- Normative Kommando-Muster im Loop:
	- Auswahl: `python3 .github/skills/snyk-orchestration/scripts/ledger.py select --ledger .synk/{sessionId}/issues-ledger.json --repo-root . --format json`
	- Status-Überblick: `python3 .github/skills/snyk-orchestration/scripts/ledger.py analyze --ledger .synk/{sessionId}/issues-ledger.json --format json`
	- Status setzen: `python3 .github/skills/snyk-orchestration/scripts/ledger.py set-status --ledger .synk/{sessionId}/issues-ledger.json --key <advisoryKey> --status in-progress`
	- Handback schreiben: `python3 .github/skills/snyk-orchestration/scripts/ledger.py update ...`
	- Fehler persistieren: `python3 .github/skills/snyk-orchestration/scripts/ledger.py record-failure ...`
	- Kaskaden prüfen: `python3 .github/skills/snyk-orchestration/scripts/ledger.py cascade-check ...`
- AJV validiert den persistierten JSON-Contract; die fachliche Kontrollfluss- und Update-Logik bleibt normativ Aufgabe von `ledger.py`.

## Normativer Workflow

Dieser Skill ist **workflow-first**. Der Agent soll nicht frei planen, sondern die dokumentierten Gates und Referenzformate in dieser Reihenfolge ausführen:

1. `references/workflow.md`
2. `references/gates.md`
3. `references/handoff-format.md`
4. `references/handback-format.md`
5. `references/gotchas-policy.md`

Wenn eine Entscheidung nicht explizit in diesen Referenzen beschrieben ist, wird sie **nicht heuristisch erfunden**.

## Operative Verantwortung

- Selection des nächsten Advisorys **über `ledger.py select`**
- `set-status --key <advisoryKey> --status in-progress` vor Sub-Agent-Start
- Dispatch + Handoff nach `issueType`
- Handback validieren
- Failure-Zustände via `ledger.py record-failure` persistieren
- `ledger.py update` aufrufen
- package-vulnerability-Kaskaden über `ledger.py cascade-check` markieren
- Session-GOTCHAS kuratieren und dauerhafte Learnings nach `.snyk/GOTCHAS.md` promoten

## Harte Ablaufregeln

- starte **nie** einen Resolver ohne vorher persistiertes `in-progress`
- leite den Resolver **ausschließlich** aus `issueType` ab
- verwende Handoff und Handback **nur** in den dokumentierten Formaten
- schreibe **nie** direkt in `issues-ledger.json`; nutze nur `ledger.py`
- rekonstruiere Gate-[O1]-Entscheidungen **nie** durch manuelles Lesen oder zeilenweises Scannen von `issues-ledger.json`; nutze `ledger.py select --format json`
- überspringe `blocked` und `partially-resolved` bei der nächsten Selektion
- behandle Handback-Formatfehler nach persistiertem Fehlerzustand als `blocked`
- persistiere Resume-/Failure-Zustände im Ledger
- führe Cascade-Checks nur für `package_vulnerability` mit `status=resolved` aus

## Explizite Gates

Der Skill arbeitet über diese Gates:

- `Gate [O1] — Selection`
- `Gate [O2] — Dispatch`
- `Gate [O3] — Handoff Build`
- `Gate [O4] — Handback Validation`
- `Gate [O5] — Override Validation`
- `Gate [O6] — Code Health Validation`
- `Gate [O7] — Ledger Update`
- `Gate [O8] — Cascade Check`
- `Gate [O9] — GOTCHAS Curation`

Die vollständige Gate-Definition steht in `references/gates.md`.

## Resolver-Übergaben

- `issueType = package_vulnerability` → `snyk-resolve-dep`
- `issueType = code` → `snyk-resolve-code`

Andere `issueType`-Werte sind Contract-Verletzungen und kein gültiger Laufzeitfall.

## Verbindliche Referenzen

- `references/workflow.md` — normative Ablaufreihenfolge
- `references/gates.md` — exakte Gate-Definitionen
- `references/handoff-format.md` — Pflichtformat für Dispatch an Resolver
- `references/handback-format.md` — Pflichtformat für Resolver-Rückgaben
- `references/gotchas-policy.md` — Ownership, Schreibpflichten und Promotionsregeln für GOTCHAS

## Wichtige Regeln

- `ledger.py` ist die operative Single Source of Truth für CLI-Bedienung; lies bei Unklarheit immer zuerst `ledger.py --help` und dann `ledger.py <command> --help`
- Gate [O1] wird normativ über `python3 .github/skills/snyk-orchestration/scripts/ledger.py select --ledger .synk/{sessionId}/issues-ledger.json --repo-root . --format json` vorbereitet
- Sortierung: `issueType` (`package_vulnerability` zuerst) → severity desc → `riskScoreMax` desc → `affectedProjectCount` desc → `issueCount` desc → `createdAt` asc → `advisoryKey` asc
- `partially-resolved` wird wie `blocked` übersprungen
- Kein direkter LLM-Edit oder manuelles Control-Flow-Parsing von `issues-ledger.json`
- Ledger wird nach jedem Statuswechsel gespeichert
- Handoff/Handback ist strikt strukturiert
- Für `package_vulnerability` muss das Handoff `packageName` als primären kompakten Identitätswert und `purl` als exakten Fallback unverändert aus Seed-/Ledger-Kontext weitergeben
- `workspacePackage` bleibt im Handoff ein Scope-Hint und wird bei fehlender belastbarer Information als `unknown` weitergereicht statt frei erfunden

## Dateien

- `schemas/issues-ledger.schema.json` — persistenter Ledger-Contract
- `scripts/ledger.py` — deterministische JSON-Manipulation (`init`, `next`, `select`, `analyze`, `cascade-check`, `update`, `set-status`, `record-failure`)
- `references/workflow.md` — normativer End-to-End-Loop
- `references/gates.md` — operative Gate-Definitionen
- `references/handoff-format.md` — Handoff-Template
- `references/handback-format.md` — Handback-Template
- `references/gotchas-policy.md` — GOTCHAS-Ownership und Schreibregeln

## Qualitäts-Gates

1. Override-Materialisierung via `overrides.py validate` gegen `pnpm-workspace.yaml` prüfen
2. Lockfile-Diff prüfen, wenn Dependency-Resolution behauptet wird
3. JSON-Integrität des Ledgers nach jedem Update sicherstellen
4. Failure-Metadaten im Ledger konsistent halten
5. GOTCHAS-Einträge nach validierten Advisories prüfen und ggf. promoten

## Nicht-Ziele

- keine Session-Erzeugung
- keine Seed-Aggregation
- keine Override-Semantik im Orchestrator selbst
- keine versteckte Heuristik für Resolver-Auswahl außerhalb von `issueType`

## Entscheidende Anweisung an den Agenten

Wenn du diesen Skill lädst, arbeite ihn wie ein Runbook ab:

1. lese `references/workflow.md`
2. führe Gates gemäß `references/gates.md` aus und beginne Gate [O1] immer mit `ledger.py select --format json`
3. erzeuge Resolver-Handoffs exakt nach `references/handoff-format.md`
4. akzeptiere Resolver-Handbacks nur nach `references/handback-format.md`
5. kuratiere `.synk/{sessionId}/GOTCHAS.md` und promote dauerhafte Learnings gemäß `references/gotchas-policy.md`

Dieser Skill beschreibt absichtlich **Prozedur vor Interpretation**.
