# snyk-dep-analysis harness

## Ziel

Dieses Harness definiert die **einzige zulässige Leseschnittstelle** für kompakte Dependency-Fakten im Resolver-Kontext.

Im Gesamtfluss liefert dieses Harness nur Faktensammlung und Verifikation. Das finale Resolver-Handback bleibt ein separates JSON-Objekt, das `snyk-orchestration` primär direkt per stdin an `ledger.py update --from-handback -` weiterreicht; dieses Harness setzt dafür kein temp Handback-File voraus.

## Adapter-Modell

- `dep.py` besitzt eine kleine Registry aus Manager-Adaptern.
- Jeder Adapter kapselt:
  - Erkennung (`detect_score`)
  - Faktensammlung (`inspect`)
  - Pfad-/Hebelanalyse (`trace`)
  - Verifikation (`verify`)
- Der Resolver spricht **nur** mit `dep.py`, nicht direkt mit manager-spezifischen Rohartefakten.

## Auto-Selection

1. Wenn `--manager` angegeben ist, wird genau dieser Adapter verwendet.
2. Wenn kein `--manager` angegeben ist, wählt `dep.py` den Adapter mit dem höchsten `detect_score`.
3. Die Erkennung bleibt absichtlich simpel und dateibasiert.
4. Für dieses Repo gewinnt `pnpm` typischerweise über `pnpm-workspace.yaml` oder `pnpm-lock.yaml`.
5. Erkannte, aber noch nicht implementierte Manager müssen **klar fehlschlagen**, statt implizit auf andere Manager zu fallen.

## Subcommands

### `inspect`

Liefert den kompakten Faktensatz für Gate `[R2]`.

Pflichtsemantik:

- `manager` — der ausgewählte Adapter
- `packageName` — kanonischer Paketname aus `--package-name` oder `--purl`
- `workspacePackage` — der verwendete Workspace-Hint oder `unknown`
- `manifestPaths[]` — relevante `package.json`-Dateien im Analysekorridor
- `directDeclarations[]` — direkte Deklarationen des Pakets in relevanten Manifesten
- `observedVersions[]` — konkret beobachtete aktive Paketversionen
- `reachableImporters[]` — beobachtete Importer / Workspace-Einstiegspunkte
- `packagePresent` — ob das Paket in der aktiven Auflösung überhaupt vorkommt

### `trace`

Liefert Dependency-Pfade und kontrollierbare Hebel für Gates `[R3]`–`[R5]`.

Pflichtsemantik:

- `controllableParents[]` — direkte Hebel in relevanten Manifests
- `evidencePaths[]` — kompakte beobachtete Pfade vom Importer bis zum betroffenen Paket
- `candidateLevers[]` — nur mögliche Strategierichtungen, keine finale Entscheidung

### `verify`

Liefert den normativen Verifikationsfakt für Gate `[R7]`.

Pflichtsemantik:

- `dependencyCheck` — `pass | fail`
- `observedVersions[]` — aktuell beobachtete Versionen
- `reachableVulnerableVersions[]` — noch aktive problematische Versionen
- `remainingPaths[]` — Pfade, über die problematische Versionen weiterhin erreichbar sind
- `summary` — knappe menschenlesbare Kurzfassung

## Eingangsregeln

- `--repo-root` ist der kanonische Repo-Ausgangspunkt.
- `--package-name` und `--purl` sind alternative Wege zur Paketidentität; mindestens eines davon muss vorhanden sein.
- `--workspace-package` ist ein Scope-Hint und darf `unknown` sein.
- `verify` braucht mindestens eine explizite `--vulnerable-version`.

## Qualitätsregeln

- JSON-Ausgabe bleibt klein und dedupliziert.
- Pfade werden begrenzt; das Script ist kein kompletter Graph-Dump.
- Direkte Deklarationen werden aus Manifesten belegt, nicht geraten.
- Verifikationsaussagen basieren auf dem aktiven Dependency-Graph des gewählten Adapters.
- Wenn ein Adapter die Information nicht belastbar liefern kann, muss er klar fehlschlagen.

## Nicht erlaubt

- manuelle Resolver-Interpretation großer Lockfiles, wenn `dep.py` die Information liefern kann
- freie Umdeutung der Felder im Resolver
- stilles Umschalten auf einen anderen Manager bei Adapterfehlern
