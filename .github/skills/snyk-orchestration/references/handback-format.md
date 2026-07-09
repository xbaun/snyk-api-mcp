# snyk-orchestration handback format

## Zweck

Dieses Dokument definiert die **einzige zulässige Rückgabeform** von `snyk-resolve-dep` und `snyk-resolve-code` an `snyk-orchestration`.

## Ownership

Dieses Dokument ist die **Single Source of Truth** für das Handback-Protokoll.

- `snyk-orchestration` validiert dagegen.
- `snyk-resolve-dep` und `snyk-resolve-code` dürfen diese Struktur **nicht eigenständig neu definieren**.
- Agent-Dateien sollen auf dieses Dokument verweisen, statt JSON-Shapes oder Feldlisten redundant zu duplizieren.

## Global Rules

- Ausgabe ist **genau ein JSON-Objekt**.
- Keine Markdown-Fences.
- Kein Prosa-Vor- oder Nachspann.
- Keine `null`-Werte; unbekannte Felder bleiben absent.
- `issueType` muss exakt zum Handoff passen.

## Semantik-Grundregeln

- `resolved` bedeutet: die konkrete Arbeitseinheit wurde innerhalb des erlaubten Scopes erfolgreich remediated.
- `blocked` bedeutet: keine sichere oder zulässige automatische Remediation innerhalb des erlaubten Scopes.
- `partially-resolved` bedeutet: es wurde nur ein Teil der Arbeitseinheit verbessert; dieser Zustand ist nur für `package_vulnerability` zulässig.
- `implementation` beschreibt, **was tatsächlich geändert oder ausgeführt wurde**.
- `verification` beschreibt, **welche Prüfungen tatsächlich gelaufen sind und mit welchem Ergebnis**.
- `outcome` beschreibt, **was fachlich aus dem Lauf folgt**.

---

## package_vulnerability

### Erlaubte Statuswerte

- `resolved`
- `partially-resolved`
- `blocked`

### Pflichtfelder

```json
{
  "issueType": "package_vulnerability",
  "status": "resolved | partially-resolved | blocked",
  "depOrigin": "direct | transitive | mixed",
  "vulnerablePackage": "string",
  "vulnerableVersions": ["string"],
  "targetVersion": "string",
  "strategy": "update-direct | update-parent | consolidated-shared-upgrade | temp-override",
  "riskLevel": "low | medium | high",
  "complexity": "contained | architectural",
  "implementation": {
    "filesChanged": ["string"],
    "how": "string",
    "why": "string"
  },
  "verification": {
    "dependencyCheck": "pass | fail",
    "lint": "pass | fail | not-run",
    "typecheck": "pass | fail | not-run",
    "tests": "pass | fail | not-run",
    "build": "pass | fail | not-run"
  },
  "outcome": {
    "summary": "string"
  }
}
```

### Zusatzfelder in `implementation`

Optional, aber wenn vorhanden exakt so benennen:

- `dependencyUpdates`
- `parentUpdates`
- `overridesApplied`
- `commandsRun`

### Feldsemantik

- `depOrigin`
  - `direct` = das betroffene Paket ist direkt kontrollierbar deklariert
  - `transitive` = das betroffene Paket kommt nur über andere Abhängigkeiten herein
  - `mixed` = dieselbe Advisory-Arbeitseinheit enthält sowohl direkte als auch transitive Vorkommen
- `vulnerablePackage` = kanonischer Name des tatsächlich betroffenen Pakets
- `vulnerableVersions` = konkret beobachtete problematische Versionen
- `targetVersion` = Zielversion oder Zielauflösung, auf die die Remediation hinarbeitet
- `strategy`
  - `update-direct` = direkte Abhängigkeit selbst anheben
  - `update-parent` = kontrollierbare Parent-Abhängigkeit anheben
  - `consolidated-shared-upgrade` = ein gemeinsamer Hebel behebt mehrere betroffene Pfade derselben Arbeitseinheit
  - `temp-override` = temporäre manager-spezifische Override-/Resolution-Materialisierung als Übergangslösung
- `riskLevel`
  - `low` = geringe Änderungswahrscheinlichkeit oder klar lokalisierter Effekt
  - `medium` = überschaubares, aber spürbares Änderungsrisiko
  - `high` = erhöhte Wahrscheinlichkeit von Nebenwirkungen oder manueller Nacharbeit
- `complexity`
  - `contained` = die Remediation bleibt innerhalb der erlaubten Ausführungsgrenze
  - `architectural` = die Remediation überschreitet diese Grenze oder braucht nicht-lokale Entscheidungen

### Zusatzregeln

- Bei `status = resolved` muss `verification.dependencyCheck = pass` sein.
- Bei `status = blocked` oder `status = partially-resolved` müssen in `outcome` zusätzlich vorhanden sein:
  - `blockers`
  - `remediationProposal`
  - `rationale`
- Wenn `strategy = temp-override`, dann sollte `implementation.overridesApplied` nicht leer sein.

---

## code

### Erlaubte Statuswerte

- `resolved`
- `blocked`

### Resolved-Format

```json
{
  "issueType": "code",
  "status": "resolved",
  "filePath": "string",
  "lineRange": "string",
  "cweId": "string",
  "severity": "critical | high | medium | low",
  "complexity": "trivial | contained",
  "implementation": {
    "filesChanged": ["string"],
    "how": "string",
    "why": "string"
  },
  "verification": {
    "lint": "pass | fail",
    "typecheck": "pass | fail",
    "tests": "pass | fail | not-run"
  },
  "outcome": {
    "summary": "string"
  }
}
```

### Blocked-Format

```json
{
  "issueType": "code",
  "status": "blocked",
  "filePath": "string",
  "lineRange": "string",
  "cweId": "string",
  "severity": "critical | high | medium | low",
  "complexity": "false-positive | architectural",
  "outcome": {
    "summary": "string",
    "blockers": ["string"],
    "remediationProposal": "string",
    "rationale": "string"
  }
}
```

### Optionale Zusatzfelder in `implementation`

Optional, aber wenn vorhanden exakt so benennen:

- `commandsRun`

### Feldsemantik

- `filePath` = kanonischer repo-relativer Pfad zur primär betroffenen Datei
- `lineRange` = menschenlesbarer Bereich der betroffenen oder geänderten Zeilen, z. B. `42-42` oder `42-57`
- `cweId` = relevante CWE-nahe Klassifikation, sofern aus dem Finding ableitbar
- `severity` = priorisierende Severity des Findings im Resolver-Kontext
- `complexity`
  - `trivial` = sehr lokaler, offensichtlicher Fix mit minimalem Blast Radius
  - `contained` = kleiner, aber leicht kontextabhängiger Fix innerhalb des erlaubten Scopes
  - `false-positive` = Finding erfordert nach Kontextprüfung keine Codeänderung
  - `architectural` = notwendige Änderung wäre nicht mehr lokal und klar begrenzbar

---

## Validation Notes for the Orchestrator

Der Orchestrator muss mindestens prüfen:

1. JSON parsebar?
2. `issueType` korrekt?
3. `status` für den Resolver erlaubt?
4. Pflichtfelder vollständig?
5. `blocked` / `partially-resolved` vollständig begründet?
6. Dep `resolved` nur mit `dependencyCheck = pass`?
7. Keine `null`-Werte?
