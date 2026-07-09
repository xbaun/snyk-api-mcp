# snyk-orchestration gates

## Gate [O1] — Selection

### Ziel

Deterministisch genau **ein** Advisory auswählen oder den Run sauber beenden.

### Input

- `.synk/{sessionId}/issues-ledger.json`
- Repo-Status via `git status --porcelain`

### Ablauf

1. Rufe `python3 .github/skills/snyk-orchestration/scripts/ledger.py select --ledger .synk/{sessionId}/issues-ledger.json --repo-root . --format json` auf.
2. Interpretiere ausschließlich das Feld `decision` aus der Antwort.
3. Erlaubte Entscheidungen:
   - `resume` → genau dieses bereits laufende Advisory wieder aufnehmen
   - `dirty-stop` → **nicht automatisch weiterlaufen**; nur nach expliziter User-Entscheidung `reset` oder `resume-with-risk`
   - `start` → `selectedAdvisory` ist das erste `not-started` Advisory gemäß deterministischer Sortierung:
     1. `issueType` (`package_vulnerability` vor `code`)
     2. severity (`critical`, `high`, `medium`, `low`)
     3. `riskScoreMax` desc
     4. `affectedProjectCount` desc
     5. `issueCount` desc
     6. `createdAt` asc
     7. `advisoryKey` asc
   - `done` → Run beenden
4. Wenn `decision == "start"`, setze das selektierte Advisory via `ledger.py set-status --ledger .synk/{sessionId}/issues-ledger.json --key <advisoryKey> --status in-progress` auf `in-progress`.

### Persistente Laufzeitmetadaten

- `set-status --key <advisoryKey> --status in-progress` setzt `lastAttemptAt`.
- Resume-relevante Fehler werden zusätzlich über `ledger.py record-failure` persistiert.

### Pass-Kriterium

- genau ein Advisory ist selektiert und im Ledger als `in-progress` gespeichert

### Fail-/Stop-Kriterien

- Ledger-Datei ungültig oder nicht lesbar
- mehr als ein `in-progress` Advisory vorhanden
- Repo ist dirty und keine explizite User-Entscheidung liegt vor

### Verboten

- keine zeilenweise oder heuristische Ledger-Analyse zur Rekonstruktion von `resume`, `start` oder `done`
- kein alternatives Sortieren außerhalb von `ledger.py select`

---

## Gate [O2] — Dispatch

### Ziel

Den passenden Resolver **nur anhand von `issueType`** bestimmen.

### Ablauf

- `issueType == "package_vulnerability"` → `snyk-resolve-dep`
- `issueType == "code"` → `snyk-resolve-code`
- jeder andere Wert = Seed-/Ledger-Contract-Verletzung → harter Fehler

### Pass-Kriterium

- Resolver ist eindeutig bestimmt

### Verboten

- keine Heuristik über Titel, Severity, Package-Namen oder Pfade
- kein Fallback-Resolver

---

## Gate [O3] — Handoff Build

### Ziel

Ein vollständig deterministisches Handoff-Briefing aus Ledger + Seed erzeugen.

### Input

- `.synk/{sessionId}/issues-ledger.json`
- `.synk/{sessionId}/issues-ledger-seed.json`
- selektiertes Advisory

### Ablauf

1. Finde in `issues-ledger-seed.json` alle `issues[]` mit passendem `advisoryKey`.
2. Übernimm Advisory-Metadaten aus `issues-ledger.json`.
3. Baue das Handoff strikt nach `references/handoff-format.md`.
4. Nutze für den ersten Analyse-Call repräsentative Issue-Instanzen mit allen Pflichtfeldern des jeweiligen `issueType`.
5. Für `package_vulnerability` gilt beim Handoff-Build zusätzlich:
   - übernimm `packageName` unverändert aus Seed-/Ledger-Kontext als primären kompakten Identitätswert
   - übernimm `purl` unverändert als exakten Fallback-Identitätswert
   - übernimm `workspacePackage` nur als Scope-Hint; wenn kein belastbarer Wert vorliegt, verwende `unknown`
   - erfinde keine alternativen Paketnamen und baue keine zusätzliche lokale Paket-Discovery vor dem Resolver-Start
6. Füge nur statische Kontextdateien ein; keine zusätzlichen Discovery-Schritte.
7. Füge die GOTCHAS-Dateien mit ihrer jeweiligen Rolle ein:
   - `.snyk/GOTCHAS.md` = permanente, read-only Resolver-Kontextquelle
   - `.synk/{sessionId}/GOTCHAS.md` = Session-Datei, die vom Resolver bei Bedarf ergänzt werden muss

### Pass-Kriterium

- Handoff enthält alle Pflichtfelder und mindestens eine repräsentative Issue-Instanz

### Verboten

- keine zusätzliche lokale Re-Aggregation
- keine zusätzlichen MCP-Calls vor dem Resolver-Start
- keine impliziten Defaults außerhalb des dokumentierten Formats
- keine heuristische Umschreibung von `packageName`, `purl` oder `workspacePackage` im Handoff

---

## Gate [O4] — Handback Validation

### Ziel

Die Rückgabe des Resolvers streng prüfen, bevor etwas ins Ledger geschrieben wird.

### Ablauf

1. Parse Handback als genau ein JSON-Objekt.
2. Prüfe `issueType` gegen das Handoff.
3. Prüfe `status` gegen erlaubte Werte:
   - Dep: `resolved | partially-resolved | blocked`
   - Code: `resolved | blocked`
4. Prüfe Pflichtfelder nach `references/handback-format.md`.
5. Prüfe Konsistenz:
   - `blocked` benötigt `outcome.remediationProposal` und `outcome.rationale`
   - Dep `resolved`/`partially-resolved` benötigt `verification.dependencyCheck`
   - wenn `verification` Felder behauptet werden, müssen sie echte Resultate sein
6. Wenn Parsing/Format fehlschlägt:
   - persistiere den Fehler via `ledger.py record-failure --kind handback-parse|handback-format`
   - liefere eine präzise Fehlermeldung
   - behandle das Advisory anschließend als `blocked`

### Pass-Kriterium

- Handback ist vollständig, konsistent und dem `issueType` entsprechend gültig

### Verboten

- kein stilles Reparieren fachlicher Inhalte
- kein Erraten fehlender Felder

---

## Gate [O5] — Override Validation

### Ziel

Overrides nur akzeptieren, wenn Materialisierung und tatsächliche Repo-Änderung zusammenpassen.

### Trigger

Nur wenn Dep-Handback `implementation.overridesApplied` enthält und nicht leer ist.

### Ablauf

1. Prüfe, dass `snyk-dep-overrides.pnpm.json` existiert.
2. Verlange, dass der Resolver vor einem neuen temp-override den bestehenden Bestand deterministisch via `overrides.py analyze` gegen Paket / Snyk-ID / Selector geprüft hat.
3. Verlange, dass der Resolver `overrides.py materialize --workspace pnpm-workspace.yaml` ausgeführt hat, wenn `temp-override` verwendet wurde.
4. Validiere deterministisch per `overrides.py validate --materialization snyk-dep-overrides.pnpm.json --workspace pnpm-workspace.yaml`.
5. Prüfe, dass die im Handback genannte Override-Maßnahme mit dem validierten Materialisierungszustand zusammenpasst.
6. Bei Fehlschlag → Advisory `blocked`.

### Pass-Kriterium

- Override-Materialisierung ist valide und korrespondiert mit realen Repo-Änderungen

---

## Gate [O6] — Code Health Validation

### Ziel

Behauptete Verifikationsergebnisse vor Ledger-Update auf Mindestkonsistenz prüfen.

### Ablauf

- Für Dep-Handbacks:
  - `verification.dependencyCheck` muss `pass` sein, wenn `status == "resolved"`
- Für beide Resolver:
  - wenn `lint` oder `typecheck` als `pass` gemeldet werden, dürfen sie nicht gleichzeitig im Workflow als fehlgeschlagen bekannt sein
  - `tests` und `build` sind optional, aber wenn gesetzt, müssen sie echte Zustände tragen

### Pass-Kriterium

- Verifikationsdaten sind konsistent zum beanspruchten Ergebnis

---

## Gate [O7] — Ledger Update

### Ziel

Das validierte Handback deterministisch in `issues-ledger.json` persistieren.

### Ablauf

1. Rufe `ledger.py update --ledger ... --key ... --from-handback ...` auf.
2. Prüfe danach JSON-Integrität des Ledgers.
3. Schreibe keine Ledger-Felder direkt per LLM.

### Pass-Kriterium

- Ledger ist aktualisiert und weiterhin gültiges JSON

---

## Gate [O8] — Cascade Check

### Ziel

Nach erfolgreicher Dep-Resolution weitere Advisory-Kandidaten derselben Schwachstelle erkennen und optional automatisch schließen.

### Trigger

Nur wenn:
- `issueType == "package_vulnerability"`
- `status == "resolved"`

### Ablauf

1. Rufe `ledger.py cascade-check --dry-run` auf.
2. Prüfe Kandidaten gegen Lockfile-/Dependency-Evidenz.
3. Nur wenn die vulnerable Version tatsächlich verschwunden ist: `ledger.py cascade-check --apply`
4. Für `code`-Advisories gibt es **keinen** Cascade-Check.

### Pass-Kriterium

- nur echte Kaskaden werden markiert

### Verboten

- kein String-Vergleich ohne Lockfile-/Graph-Evidenz
- kein Cascade-Apply bei `blocked` oder `partially-resolved`

---

## Gate [O9] — GOTCHAS Curation

### Ziel

Ownership, Schreibpflicht und Promotion der GOTCHAS-Dateien deterministisch durchsetzen.

### Input

- `.synk/{sessionId}/GOTCHAS.md`
- `.snyk/GOTCHAS.md`
- validiertes Advisory-Ergebnis

### Ablauf

1. Prüfe, ob Resolver gemäß Policy einen Session-GOTCHA-Eintrag hätte schreiben müssen.
2. Wenn ein Loop-/Resume-/Failure-/Cascade-Thema aufgetreten ist, schreibe selbst einen Session-GOTCHA-Eintrag.
3. Prüfe neue Session-Einträge auf Promotionswürdigkeit.
4. Promote nur dauerhafte, repo-spezifische, wiederverwendbare Regeln nach `.snyk/GOTCHAS.md`.
5. Dedupliziere oder aktualisiere bestehende permanente Regeln statt sie blind zu duplizieren.

### Pass-Kriterium

- Session-Learnings sind dokumentiert
- dauerhafte Regeln sind bei Bedarf in `.snyk/GOTCHAS.md` reflektiert

### Verboten

- Resolver dürfen `.snyk/GOTCHAS.md` nicht direkt schreiben
- keine Promotion von einmaligen Einzelfall-Notizen ohne Wiederverwendungswert
