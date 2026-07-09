# snyk-dep-overrides harness

## Ziel

Dieses Harness beschreibt, wann und wie eine manager-spezifische Override-Materialisierung gepflegt werden darf.

## Entscheidungsregeln

1. Ein Override ist nur zulässig, wenn eine reguläre Dependency-Änderung den Befund nicht innerhalb der YAGNI+KISS-Grenze behebt.
2. Jeder Override-Case braucht nachvollziehbare Traceability:
   - `selector`
   - `target`
   - `package`
   - `snykIds[]`
   - `evidenceTree[]`
   - `watch[]`
   - `obsoleteWhen[]`
3. `status=active` bedeutet: aktuell wirksam und beabsichtigt.
4. `status=obsolete` bedeutet: historisch dokumentiert, aber nicht mehr nötig.
5. Entfernen ist nur zulässig, wenn die `obsoleteWhen[]`-Kriterien erfüllt sind.

## Feldsemantik

Diese Begriffe sind normativ. Ein Agent darf sie nicht frei uminterpretieren.

### `selector`

- Beschreibt **welches Auflösungs-Match überschrieben wird**.
- Das ist der manager-spezifische Ausdruck für die problematische oder unerwünschte Paketauflösung.
- Beispiel bei pnpm: `esbuild@<0.28.0`
- `selector` beschreibt das Match des Problems, **nicht** die gewünschte Zielversion.

### `target`

- Beschreibt **worauf der Selector umgebogen wird**.
- Das ist die gewünschte nicht-vulnerable Zielauflösung oder Ziel-Range.
- Beispiel: `^0.28.1`

### `package`

- Der kanonische Name des fachlich betroffenen Pakets.
- Dient der Lesbarkeit, Snyk-Traceability und späteren Wiedererkennung.
- Beispiel: `esbuild`

### `snykIds[]`

- Liste der konkreten Snyk-Referenzen, die diesen Override motivieren.
- Inhalt: echte Snyk IDs wie `SNYK-JS-ESBUILD-17750822`.
- Zweck: nachvollziehbar machen, **welche Findings/Advisories** dieser Case adressiert.

### `evidenceTree[]`

- Belegt, **warum** der Override nötig wurde und **über welchen Dependency-Pfad** das Paket ins Projekt gelangt.
- Jeder Eintrag steht für eine konkrete beobachtete Einführungskette.

#### `evidenceTree[].importer`

- Die Stelle, von der aus die Kette betrachtet wird.
- Typischerweise Workspace-Root, Catalog oder ein konkretes Package.

#### `evidenceTree[].directDependency`

- Der erste kontrollierbare Hebel in der Kette.
- Also die direkt deklarierte Abhängigkeit, über die das problematische Paket hereinkommt.

#### `evidenceTree[].chain[]`

- Vollständige beobachtete Kette vom kontrollierbaren Hebel bis zum betroffenen Paket.
- Reihenfolge ist upstream → downstream.
- Beispiel: `["vite@7.3.1", "esbuild@0.27.3"]`

### `watch[]`

- Liste von Upstream-Hebeln, die künftig beobachtet werden müssen, damit der Override später entfernt oder angepasst werden kann.
- `watch[]` beantwortet die Frage: **Welche Deklarationen müssen sich ändern, damit der Override obsolet werden könnte?**

#### `watch[].package`

- Das zu beobachtende Paket.

#### `watch[].declaredIn`

- Wo dieses Paket deklariert ist.
- Beispiele: `catalog`, `apps/web/package.json`

#### `watch[].declaredVersion`

- Die zum Zeitpunkt der Case-Erstellung beobachtete deklarierte Version oder Range.

#### `watch[].relevance`

- Kurze Begründung, warum genau dieses Paket überwacht werden soll.

### `obsoleteWhen[]`

- Explizite, überprüfbare Bedingungen, unter denen der Override-Case nicht mehr nötig sein soll.
- Jede Bedingung muss als konkrete Prüfregel formuliert sein, nicht als vage Absicht.
- Gute Beispiele:
   - `All watched packages resolve esbuild >=0.28.1 natively`
   - `Removing selector does not reintroduce the vulnerable package version`

### `status`

- `active` = Override ist aktuell wirksam und beabsichtigt
- `draft` = Case ist vorbereitet, aber noch nicht als aktive Materialisierung zu behandeln
- `obsolete` = historisch dokumentiert, aber nicht mehr nötig
- `removed` = Case ist nicht mehr operative Quelle

### `reason`

- `security` = primär Sicherheitsremediation
- `compatibility` = primär Kompatibilitätsgrund
- `performance` = primär Performance-Grund
- `other` = legitimer Sonderfall außerhalb der anderen Klassen

### `introducedBy`

- Kennzeichnet, welcher Lauf / welche Session / welche Remediation den Case eingeführt hat.
- Soll stabil genug sein, um zur verursachenden Änderung zurückverfolgt zu werden.

### `scope`

- Optionale menschliche Einordnung, in welchem Bereich der Override gilt.
- Beispiele: `workspace-root`, `dev-tooling`, `apps/web`
- Dient der Lesbarkeit, nicht dem Matching.

### `contextSummary`

- Kurze menschenlesbare Erklärung, warum der Override-Case existiert.
- Soll beantworten: **Warum braucht dieses Repo diesen Override aktuell?**

## Inhaltliche Qualitätsregeln

- `selector` und `target` müssen zusammen ein klares Problem→Lösungs-Paar bilden.
- `evidenceTree[]` darf nicht geraten sein; jeder Eintrag braucht beobachtete oder reproduzierbare Evidence.
- `watch[]` soll echte spätere Entfernungshebel benennen, nicht nur das bereits vulnerable Paket wiederholen.
- `obsoleteWhen[]` muss prüfbar sein.
- `snykIds[]` soll echte Snyk-Referenzen enthalten, nicht freie Labels.
- Wenn ein Agent die Bedeutung eines Feldes nicht sicher belegen kann, darf er den Case nicht schreiben.

## Beispielhafte Lesart eines vollständigen Cases

```text
selector      = welches Match wird überschrieben?
target        = worauf wird dieses Match umgebogen?
package       = welches Paket ist fachlich betroffen?
snykIds       = welche Snyk-Findings motivieren den Case?
evidenceTree  = wie kommt das Paket hinein?
watch         = welche Upstream-Hebel müssen später beobachtet werden?
obsoleteWhen  = wann darf der Override wieder weg?
```

## Pflege

- Verwende `scripts/overrides.py analyze`, um vor einer Strategieentscheidung existierende Overrides zu prüfen.
- Verwende `scripts/overrides.py read`, wenn ein konkreter `key` bereits deterministisch bekannt ist.
- Verwende `scripts/overrides.py list`, wenn ein operativer Überblick nach `status` benötigt wird.
- Verwende `scripts/overrides.py upsert`, um neue oder geänderte Cases zu schreiben.
- Verwende `scripts/overrides.py materialize`, um aktive pnpm-Cases nach `pnpm-workspace.yaml` zu synchronisieren.
- Verwende `scripts/overrides.py validate`, um JSON-Materialisierung und echte pnpm-Konfiguration gegeneinander zu prüfen.
- Verwende `scripts/overrides.py remove` nur dann, wenn die `obsoleteWhen[]`-Bedingungen nachvollziehbar erfüllt sind.
- Für nicht kanonisch benannte Materialisierungen oder Example-Dateien gib bei `analyze`, `read`, `list` und `remove` explizit `--manager <manager>` an.
- Lies Cases mit `read` oder `list`, statt das JSON manuell zu interpretieren.
- Persistiere nur valide Materialisierungen.

### `analyze` Output-Semantik

Der `analyze`-Subcommand liefert eine deterministische Query-Antwort:

- `query` — die exakten angewandten Filter (`manager`, `package`, `snykId`, `status`, `checkSelector`)
- `matches[]` — vollständige Case-Objekte, die alle gesetzten Filter erfüllen
- `summary.totalMatches` — Anzahl der Treffer
- `summary.statusCounts` — Verteilung der Treffer nach Status (`active`, `draft`, `obsolete`, `removed`)
- `summary.totalCases` — Gesamtzahl aller Cases in der Materialisierung (zum Vergleich)
- `summary.conflictingSelectors[]` — aktive oder draft Cases, die zum geprüften Selector passen; jeder Eintrag trägt `conflictType`:
   - `exact-selector` = derselbe Selector existiert bereits
   - `same-package` = derselbe Paketname hat bereits einen anderen Selector-Case

**Regeln für Resolver:**

- Vor jeder Strategieentscheidung MUSS der Resolver `analyze --package <name>` aufrufen.
- Wenn ein Case mit `status=active` für dasselbe Paket existiert, MUSS der Resolver prüfen, ob das Advisory bereits abgedeckt ist (`--snyk-id`).
- Vor einem neuen `upsert` MUSS der Resolver `--check-selector` verwenden, um Konflikte zu erkennen.
- `exact-selector` bedeutet: derselbe Selector ist bereits im Bestand und muss vor einem neuen `upsert` begründet wiederverwendet oder aktualisiert werden.
- `same-package` bedeutet: für dasselbe Paket existiert bereits ein anderer Selector-Case; das ist ein Review-Signal und darf nicht blind als eindeutige semver-Kollision interpretiert werden.

## Deterministische Anlage und Pflege

- Ein Agent darf die Materialisierungsdatei nicht frei benennen.
- Ein Agent darf die Materialisierungsdatei nicht per Hand anlegen.
- Der operative Dateipfad kommt aus dem Repo-Kontext; in diesem Repo ist das `snyk-dep-overrides.pnpm.json` im Repo-Root.
- Falls die Datei fehlt, wird sie durch `scripts/overrides.py upsert` erzeugt.
- Für pnpm ist `pnpm-workspace.yaml` die echte Zielkonfiguration; sie wird nicht manuell gepflegt, sondern über `scripts/overrides.py materialize` synchronisiert.
- Der Agent muss also nur den fachlichen Case korrekt bestimmen; die JSON-Anlage, pnpm-Materialisierung und Validierung übernimmt das Script deterministisch.
- Das Example unter `examples/` dient nur zum Verständnis eines vollständigen Cases, nicht als operative Schreibvorlage.

## Erwartete Ausgabe

Eine manager-spezifische Datei wie `snyk-dep-overrides.pnpm.json`, die den Schema-Contract erfüllt und für Agenten lesbar bleibt.
