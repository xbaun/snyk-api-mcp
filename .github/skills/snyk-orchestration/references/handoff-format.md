# snyk-orchestration handoff format

## Zweck

Dieses Format ist die **einzige zulässige Struktur** für den Dispatch von `snyk-orchestration` an einen Resolver.

## Regeln

- Das Handoff ist reiner Text, aber **strikt strukturiert**.
- Die Feldnamen bleiben exakt wie unten angegeben.
- Der Resolver erhält genau ein Advisory pro Invocation.
- `issues-ledger.json` ist Statusquelle.
- `issues-ledger-seed.json` ist statische Kontextquelle.

## Feldsemantik

- `SESSION` = die konkrete `.synk/{sessionId}`-Arbeitsumgebung dieses Laufs
- `ADVISORY` = die kanonische Arbeitseinheit im Ledger (`advisoryKey`)
- `ISSUE_TYPE` = der einzige zulässige Dispatch-Schlüssel (`package_vulnerability` oder `code`)
- `REPRESENTATIVE ISSUE INSTANCES` = konkrete Seed-Issue-Instanzen derselben Arbeitseinheit, die als Startpunkt für Analyse-Calls dienen
- `AFFECTED WORKSPACE PACKAGES` = repo-relative Workspace-Bereiche, die für Health-Checks oder Scope-Begrenzung relevant sind; diese Liste ist ein Hint, kein zweiter Dispatch-Mechanismus
- `PRE-KNOWN FACTS` = bereits bekannte, aber nicht zwingend vollständige Hinweise aus Seed oder früherem Loop-Kontext

### Semantik der `PRE-KNOWN FACTS`

- `Package Name` = Name des Pakets direkt aus Seed-Daten einer `package_vulnerability`; das ist typischerweise der **primäre** Startwert für `dep.py inspect|trace|verify`
- `Package` = bereits im Loop ermittelter oder bestätigter `vulnerablePackage`-Wert; kann anfangs `unknown` sein
- `Versions` = bereits bekannte problematische Versionen des betroffenen Pakets; kann anfangs `unknown` sein
- `Target` = bereits bekannte gewünschte Zielversion oder Zielauflösung; kann anfangs `unknown` sein

Zusatzregeln:

- Wenn `Package Name` vorhanden und nicht `unknown` ist, soll der Resolver diesen Wert vor `purl` als Eingabe für `dep.py` verwenden.
- `Package` ist ein späterer Loop-/Resolver-Fakt und ersetzt `Package Name` nicht als Seed-nahe Identität.
- Wenn `Package Name` fehlt oder `unknown` ist, ist `purl` der kanonische Fallback zur Paketidentität.

### Semantik der repräsentativen Instanzen

- bei `package_vulnerability` ist `purl` die exakte Paket-Referenz für projektbezogene Analyse und der kanonische Fallback, wenn `packageName` nicht nutzbar ist
- bei `package_vulnerability` bleibt `packageName` der bevorzugte kompakte Einstiegspunkt für `dep.py`; er wird nicht aus `purl` frei umformuliert, wenn er bereits im Seed vorhanden ist
- bei `code` sind `filePath`, `startLine` und `endLine` der direkte Einstiegspunkt für die Codeanalyse
- `workspacePackage` ist ein Scope-Hinweis für Prüfungen und Folgearbeiten, nicht der Primär-Identifier des Findings; wenn kein belastbarer Wert vorliegt, bleibt er exakt `unknown`

## Template

```text
SESSION: {sessionId}
ADVISORY: {advisoryKey}
ISSUE_TYPE: {issueType}
TITLE: {title}
SEVERITY: {severity}
ISSUE_COUNT: {issueCount}

REPRESENTATIVE ISSUE INSTANCES:
  Für issueType = package_vulnerability:
  - projectId={projectId}, restIssueId={restIssueId}, issueKey={issueKey}, purl={purl}, packageName={packageName}, workspacePackage={workspacePackage | "unknown"}

  Für issueType = code:
  - projectId={projectId}, restIssueId={restIssueId}, issueKey={issueKey}, filePath={filePath}, startLine={startLine}, endLine={endLine}, workspacePackage={workspacePackage | "unknown"}

AFFECTED WORKSPACE PACKAGES:
  - {workspacePackage1}
  - {workspacePackage2}

PRE-KNOWN FACTS:
  Package Name: {packageName | "unknown"}
  Package: {vulnerablePackage | "unknown"}
  Versions: {vulnerableVersions | "unknown"}
  Target: {targetVersion | "unknown"}

CONTEXT FILES:
  - .synk/{sessionId}/issues-ledger-seed.json
  - .snyk/GOTCHAS.md                  # read-only for resolvers; curated only by snyk-orchestration
  - .synk/{sessionId}/GOTCHAS.md      # read + append for resolvers according to gotchas-policy
  - .github/skills/snyk-orchestration/references/gotchas-policy.md
  - .github/skills/snyk-dep-analysis/SKILL.md
  - .github/skills/snyk-dep-analysis/references/harness.md
  - .github/skills/snyk-dep-analysis/scripts/dep.py
  - .github/skills/snyk-dep-overrides/SKILL.md
  - .github/skills/snyk-dep-overrides/references/snyk-dep-overrides.harness.md
  - .github/skills/snyk-dep-overrides/schemas/snyk-dep-overrides.schema.json
  - .github/skills/snyk-dep-overrides/examples/snyk-dep-overrides.{{manager}}.example.json
  - .github/skills/snyk-dep-overrides/scripts/overrides.py
  - snyk-dep-overrides.pnpm.json
  - pnpm-workspace.yaml
  - AGENTS.md

IMPORTANT:
  - Prüfe Gate [A] vor jeder Veränderung.
  - Nutze für den ersten Analyse-Call eine repräsentative Issue-Instanz mit vollständigen Pflichtfeldern.
  - Für `package_vulnerability` gilt: zuerst `packageName` verwenden, nur bei `unknown` oder fehlendem Wert auf `purl` ausweichen.
  - Wenn ein `temp-override` in Betracht kommt, konsultiere vor der Strategieentscheidung zuerst `overrides.py analyze` für Paket-, Advisory- und Selector-Kontext.
  - `workspacePackage` ist nur ein Scope-Hint; nicht als Paketidentität oder Resolver-Auswahl missbrauchen.
  - Keine vorgelagerte zusätzliche Issue-Discovery.
  - Bei blocked: remediationProposal + rationale liefern.
  - Override-Materialisierung nur mit bestandener Validierung.
  - Schreibe Session-Learnings nach `.synk/{sessionId}/GOTCHAS.md` nur gemäß `gotchas-policy.md`.
```

## Pflichtregeln

### Für `package_vulnerability`

- mindestens eine repräsentative Issue-Instanz mit:
  - `projectId`
  - `restIssueId`
  - `issueKey`
  - `purl`
  - `packageName`
- `packageName` und `purl` werden unverändert aus Seed-/Ledger-Kontext übernommen; sie werden im Handoff nicht heuristisch umgeschrieben oder ersetzt
- `workspacePackage` darf `unknown` sein, wird aber nicht frei erfunden
- `AFFECTED WORKSPACE PACKAGES` darf leer sein

### Für `code`

- mindestens eine repräsentative Issue-Instanz mit:
  - `projectId`
  - `restIssueId`
  - `issueKey`
  - `filePath`
  - `startLine`
  - `endLine`

## Verboten

- keine alternativen Überschriften
- keine JSON- oder YAML-Handoff-Variante
- keine Freitext-Einleitung vor dem Template
- keine zusätzlichen Kontextdateien, die nicht aus dem Workflow ableitbar sind
