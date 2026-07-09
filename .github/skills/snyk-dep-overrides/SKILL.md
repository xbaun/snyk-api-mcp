---
name: snyk-dep-overrides
description: Own schemas, reference examples, and deterministic scripts for manager-specific Snyk dependency override materializations.
user-invocable: false
---

# snyk-dep-overrides

## Zweck

Besitzt die gesamte Override-Traceability-Logik für manager-spezifische Dependency-Overrides bzw. Resolutions.

## Verantwortung

- Schema für Override-Materialisierungen definieren
- Harness/Referenz für Agenten bereitstellen
- manager-agnostische Example-Struktur pflegen
- deterministische JSON-Manipulation via `scripts/overrides.py`

## Struktur

- `schemas/snyk-dep-overrides.schema.json` — kanonischer Materialisierungs-Contract
- `references/snyk-dep-overrides.harness.md` — Entscheidungsregeln, Feldsemantik und Pflege-Regeln
- `examples/snyk-dep-overrides.{{manager}}.example.json` — Referenzbeispiel für einen vollständigen Case
- `scripts/overrides.py` — `upsert`, `read`, `list`, `remove`, `materialize`, `validate`, `analyze`

## Tools

- JSON-Schema-Validierung mit AJV CLI erfolgt normativ über `pnpm dlx ajv-cli`.
- Da das Schema `https://json-schema.org/draft/2020-12/schema` verwendet, muss AJV CLI immer mit `--spec=draft2020` aufgerufen werden.
- Kanonisches Schema-Check-Muster für Materialisierungen oder Examples:
	- `pnpm dlx ajv-cli validate --spec=draft2020 -s .github/skills/snyk-dep-overrides/schemas/snyk-dep-overrides.schema.json -d <json-datei>`
- Für operative Änderungen am Override-Bestand ist **nicht** AJV der primäre Schreibpfad, sondern ausschließlich `python3 .github/skills/snyk-dep-overrides/scripts/overrides.py <subcommand>`.
- Vor der Nutzung eines Subcommands zuerst Hilfe lesen:
	- `python3 .github/skills/snyk-dep-overrides/scripts/overrides.py --help`
	- `python3 .github/skills/snyk-dep-overrides/scripts/overrides.py <subcommand> --help`
- Für dieses Repo gilt die feste Kommando-Reihenfolge:
	1. `overrides.py analyze --materialization snyk-dep-overrides.pnpm.json --package <name> [--snyk-id <id>] [--check-selector <selector>]`
	2. `overrides.py upsert --materialization snyk-dep-overrides.pnpm.json ...`
	3. `overrides.py materialize --materialization snyk-dep-overrides.pnpm.json --workspace pnpm-workspace.yaml`
	4. `overrides.py validate --materialization snyk-dep-overrides.pnpm.json --workspace pnpm-workspace.yaml`
- AJV prüft nur den JSON-Schema-Contract; die inhaltliche pnpm-Synchronität gegen `pnpm-workspace.yaml` wird normativ über `overrides.py validate` geprüft.

## Kanonischer Command-Katalog

- Bestand vor einer Strategieentscheidung prüfen:
	- `overrides.py analyze --materialization snyk-dep-overrides.pnpm.json --package <name>`
	- `overrides.py analyze --materialization snyk-dep-overrides.pnpm.json --package <name> --snyk-id <id>`
	- `overrides.py analyze --materialization snyk-dep-overrides.pnpm.json --package <name> --check-selector <selector> --status active`
- Konkreten bekannten Case lesen:
	- `overrides.py read --materialization snyk-dep-overrides.pnpm.json --key <caseKey>`
- Operativen Überblick nach Status holen:
	- `overrides.py list --materialization snyk-dep-overrides.pnpm.json --status active`
- Case deterministisch entfernen:
	- `overrides.py remove --materialization snyk-dep-overrides.pnpm.json --key <caseKey>`
- Für nicht kanonisch benannte Materialisierungen oder Example-Dateien zusätzlich explizit:
	- `--manager <manager>` bei `analyze`, `read`, `list` und `remove`

## Regeln

- Resolver entscheiden **dass** ein Override nötig ist
- dieser Skill definiert **wie** die Materialisierung aufgebaut und validiert wird
- Materialisierungen sind manager-spezifisch, aber Skill/Schema bleiben manager-agnostisch
- neue oder geänderte Cases müssen immer validiert werden, bevor sie persistiert werden
- die inhaltliche Bedeutung der Override-Felder wird im Harness dieses Skills normativ definiert
- das Example ist nur Anschauungs- und Referenzmaterial; die operative Pflege erfolgt ausschließlich über `overrides.py`

## Deterministische Ausführung

- Der Agent legt Override-Dateien **nicht manuell** an.
- Der Agent editiert Override-JSON **nie direkt**.
- Die einzige zulässige Schreiboperation ist `scripts/overrides.py upsert`.
- Der Speicherort wird **nicht frei erfunden**, sondern kommt aus dem Repo-/Handoff-Kontext.
- Für dieses Repo ist die operative Materialisierung `snyk-dep-overrides.pnpm.json` im Repo-Root.
- Für dieses Repo ist die echte pnpm-Zielkonfiguration `pnpm-workspace.yaml`.
- Wenn diese Datei noch nicht existiert, muss der Agent sie **durch `overrides.py upsert` erzeugen lassen**, nicht durch manuelles JSON-Schreiben.
- Der Manager ist für dieses Repo `pnpm`.
- `overrides.py` kann den Manager deterministisch aus einem Dateinamen wie `snyk-dep-overrides.<manager>.json` ableiten; bei `snyk-dep-overrides.pnpm.json` also `pnpm`.
- Nach jedem `upsert` für einen aktiven pnpm-Override muss der Agent `overrides.py materialize` verwenden, damit `pnpm-workspace.yaml` synchronisiert wird.
- Vor Abschluss eines Advisorys mit `temp-override` muss `overrides.py validate` erfolgreich sein.

## Operativer Ablauf für Agenten

1. **Vor jeder Strategieentscheidung**: Prüfe existierende Overrides mit `scripts/overrides.py analyze`.
2. Entscheide anhand des Harness, ob ein Override überhaupt zulässig ist.
3. Verwende als Materialisierungspfad den im Repo vorgesehenen Pfad; hier: `snyk-dep-overrides.pnpm.json`.
4. Erzeuge oder aktualisiere den Case ausschließlich über `scripts/overrides.py upsert`.
5. Synchronisiere aktive pnpm-Cases deterministisch mit `scripts/overrides.py materialize --workspace pnpm-workspace.yaml`.
6. Validiere JSON + echte pnpm-Konfiguration mit `scripts/overrides.py validate --workspace pnpm-workspace.yaml`.
7. Lies bei Bedarf bestehende Cases ausschließlich über `read` oder `list`.
8. Entferne Cases ausschließlich über `remove` und nur wenn die `obsoleteWhen[]`-Bedingungen erfüllt sind.
9. Nutze das Example nur als Lesebeispiel, nicht als Schreibvorlage.

## `analyze` — Resolver Pre-Flight Queries

Der `analyze`-Subcommand ist die **erste Anlaufstelle** für Resolver, bevor sie eine Strategieentscheidung treffen. Er beantwortet:

- **Gibt es schon einen Override für dieses Paket?** → `--package <name>`
- **Deckt ein existierender Override diese Snyk-ID ab?** → `--snyk-id <id>`
- **Gibt es für diesen Selector bereits einen exakten oder paketgleichen Case?** → `--check-selector <selector>`
- **Filterung nach Status** → `--status active|draft|obsolete|removed`

Alle Flags sind kombinierbar. Die Ausgabe enthält:
- `query` — die angewandten Filter, inklusive optionalem `manager`
- `matches[]` — die vollständigen Case-Objekte, gefiltert durch alle gesetzten Query-Flags
- `summary.totalMatches` — Anzahl der Treffer
- `summary.statusCounts` — Verteilung nach Status
- `summary.totalCases` — Gesamtzahl aller Cases
- `summary.conflictingSelectors[]` — aktive/draft Cases mit `conflictType = exact-selector | same-package` (nur wenn `--check-selector` gesetzt)

Kanonische Aufrufe:

```bash
# Vor jedem Advisory: existiert schon ein Case für dieses Paket?
python3 .github/skills/snyk-dep-overrides/scripts/overrides.py analyze \
  --materialization snyk-dep-overrides.pnpm.json --package <name>

# Prüfe, ob eine Snyk-ID bereits abgedeckt ist
python3 .github/skills/snyk-dep-overrides/scripts/overrides.py analyze \
  --materialization snyk-dep-overrides.pnpm.json --snyk-id SNYK-JS-ESBUILD-...

# Vor einem neuen Override: Kollisionen prüfen
python3 .github/skills/snyk-dep-overrides/scripts/overrides.py analyze \
  --materialization snyk-dep-overrides.pnpm.json \
  --package esbuild --check-selector "esbuild@<0.28.0" --status active

# Für Example- oder abweichend benannte Dateien Manager explizit setzen
python3 .github/skills/snyk-dep-overrides/scripts/overrides.py analyze \
	--materialization .github/skills/snyk-dep-overrides/examples/snyk-dep-overrides.{{manager}}.example.json \
	--manager pnpm --package example-package

# Einen konkreten Case aus einer nicht kanonisch benannten Datei lesen
python3 .github/skills/snyk-dep-overrides/scripts/overrides.py read \
	--materialization .github/skills/snyk-dep-overrides/examples/snyk-dep-overrides.{{manager}}.example.json \
	--manager pnpm --key example-security-override
```

## Nicht-Ziele

- keine Dependency-Strategie im Skill selbst
- keine Projekt- oder Ledger-Selektion
- keine implizite Anpassung anderer Repo-Dateien außerhalb der Materialisierung
