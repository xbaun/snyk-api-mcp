---
name: snyk-dep-analysis
description: Deterministic dependency fact gathering and verification for resolver agents via manager adapters with auto-selection.
user-invocable: false
---

# snyk-dep-analysis

## Zweck

Liefert den **deterministischen Lesepfad** für Dependency-Fakten, damit Resolver keine großen Lockfiles oder Graph-Artefakte manuell lesen müssen.

## Verantwortung

- Paketmanager über einen kleinen Adapter-Registry-Mechanismus auswählen
- unterstützte Manager deterministisch erkennen
- kompakte JSON-Faktensätze für Dependency-Resolver liefern
- direkte Deklarationen, transitive Pfade und Verifikationsfakten vereinheitlichen
- manuelle Lockfile-Leserei durch normierte Analysekommandos ersetzen

## Unterstützte Manager

- `pnpm` — aktuell vollständig unterstützt
- `npm` — unterstützt über deterministische `package-lock.json`-Analyse
- `yarn` — unterstützt für Yarn Classic `yarn.lock` v1

## Struktur

- `references/harness.md` — Feldsemantik, Auto-Selection-Regeln und Kommandoeinsatz
- `scripts/dep.py` — `inspect`, `trace`, `verify`

## Tools

- Operative Nutzung erfolgt ausschließlich über `python3 .github/skills/snyk-dep-analysis/scripts/dep.py <subcommand>`.
- Vor jeder Verwendung zuerst Hilfe lesen:
  - `python3 .github/skills/snyk-dep-analysis/scripts/dep.py --help`
  - `python3 .github/skills/snyk-dep-analysis/scripts/dep.py <subcommand> --help`
- Für Agent-Läufe bleiben Shell-Kommandos weiterhin mit `rtk` prefixed.

## Kanonische Kommandos

- Fact Set aufbauen:
  - `python3 .github/skills/snyk-dep-analysis/scripts/dep.py inspect --repo-root . --package-name <name> --workspace-package <workspace | unknown>`
- Dependency-Trace erzeugen:
  - `python3 .github/skills/snyk-dep-analysis/scripts/dep.py trace --repo-root . --package-name <name> --workspace-package <workspace | unknown>`
- Remediation verifizieren:
  - `python3 .github/skills/snyk-dep-analysis/scripts/dep.py verify --repo-root . --package-name <name> --workspace-package <workspace | unknown> --vulnerable-version <version>`

## Regeln

- Resolver sollen `dep.py` bevorzugen, sobald ein benötigter Fakt durch `inspect`, `trace` oder `verify` abgedeckt wird.
- Große Lockfiles oder rohe Dependency-Graphen werden **nicht manuell** gelesen, wenn `dep.py` den Faktensatz liefern kann.
- Das Script darf intern manager-spezifische Dateien oder CLI-Ausgaben auswerten; diese Komplexität gehört in den Adapter, nicht in den Prompt-Kontext.
- Die JSON-Ausgabe bleibt klein, stabil und auf Resolver-Entscheidungen ausgerichtet.
- Manager-Unterstützung wird **über neue Adapter** erweitert, nicht durch freie `if/else`-Explosion im Resolver.

## Nicht-Ziele

- keine Override-Materialisierung
- keine Ledger-Updates
- keine automatische Remediation-Strategieentscheidung
- keine spekulative Vollunterstützung weiterer Package-Manager ohne echten Bedarf
