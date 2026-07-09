# snyk-orchestration GOTCHAS policy

## Zweck

Diese Policy regelt **verbindlich**, wer `.snyk/GOTCHAS.md` und `.synk/{sessionId}/GOTCHAS.md` anlegt, schreibt, kuratiert und promotet.

## Ownership

### `.snyk/GOTCHAS.md`

- Typ: permanente, repo-weite Cross-Session-Lessons
- Owner: `snyk-orchestration`
- Schreibrecht: **nur** `snyk-orchestration`
- Resolver (`snyk-resolve-dep`, `snyk-resolve-code`) dürfen diese Datei **nie direkt** ändern

### `.synk/{sessionId}/GOTCHAS.md`

- Typ: session-spezifische Arbeits- und Lernnotizen
- Owner: Session-Lauf unter Führung von `snyk-orchestration`
- Initiale Erstellung: `snyk-session-init`
- Schreibrecht:
  - `snyk-resolve-dep` → advisory-spezifische Dependency-Learnings
  - `snyk-resolve-code` → advisory-spezifische Code-/False-Positive-Learnings
  - `snyk-orchestration` → Loop-/Resume-/Failure-/Cascade-Learnings

## Schreibpflichten

### `snyk-session-init`

Muss beim Start einer Session:

1. `.snyk/GOTCHAS.md` erzeugen, falls die Datei noch nicht existiert
2. `.synk/{sessionId}/GOTCHAS.md` mit der unten definierten Session-Struktur erzeugen

### `snyk-resolve-dep`

Muss **vor Rückgabe des finalen Handbacks** einen Eintrag in `.synk/{sessionId}/GOTCHAS.md` anhängen, wenn mindestens eine der folgenden Bedingungen zutrifft:

- `status == blocked`
- `status == partially-resolved`
- `strategy == temp-override`
- es gab ein repo-spezifisches Dependency-, Lockfile- oder Parent-Resolution-Verhalten, das für spätere Advisories relevant ist

### `snyk-resolve-code`

Muss **vor Rückgabe des finalen Handbacks** einen Eintrag in `.synk/{sessionId}/GOTCHAS.md` anhängen, wenn mindestens eine der folgenden Bedingungen zutrifft:

- `status == blocked`
- `complexity == false-positive`
- es gab ein repo-spezifisches Sanitization-, Validation- oder Verification-Muster, das für spätere Advisories relevant ist

### `snyk-orchestration`

Muss:

1. bei Dirty-Resume-Fällen, Failure-Auffälligkeiten oder Cascade-Auffälligkeiten selbst einen Session-GOTCHA-Eintrag schreiben
2. nach jedem **validierten** Advisory-Durchlauf die neuen Session-GOTCHAS prüfen
3. dauerhafte, wiederverwendbare Learnings in `.snyk/GOTCHAS.md` promoten
4. Promotionen deduplizieren oder vorhandene Regeln aktualisieren statt blind zu duplizieren

## Promotion-Regel für `.snyk/GOTCHAS.md`

Ein Session-GOTCHA darf nur dann in die permanente Datei übernommen werden, wenn er:

- repo-spezifisch ist
- voraussichtlich in späteren Sessions erneut relevant wird
- eine konkrete Handlungsregel enthält
- nicht nur eine einmalige Beobachtung ohne Wiederverwendungswert ist

Nicht promoten:

- einmalige Tippfehler
- zufällige Netzwerk-/CI-Störungen
- advisory-spezifische Einzelfälle ohne Wiederholungswert

## Session-Eintragsformat

Jeder Eintrag in `.synk/{sessionId}/GOTCHAS.md` muss dieses Format verwenden:

```markdown
## {advisoryKey} — {short title}
- owner: snyk-resolve-dep | snyk-resolve-code | snyk-orchestration
- status: resolved | blocked | partially-resolved | operational
- promote: yes | no
- category: dependency | override | code | verification | orchestration
- lesson: {konkrete Beobachtung oder Regel}
- evidence:
  - {Datei, Command oder Beobachtung}
  - {Datei, Command oder Beobachtung}
- next-time: {konkrete Handlungsanweisung für spätere Läufe}
```

## Permanentes Eintragsformat

Jeder Eintrag in `.snyk/GOTCHAS.md` muss dieses Format verwenden:

```markdown
## {stable short rule title}
- promoted-by: snyk-orchestration
- source-session: {sessionId}
- applies-when: {Situation / Trigger}
- rule: {dauerhafte Handlungsregel}
- verify-with:
  - {Command, Datei oder Check}
```

## Mindestinhalte der Initialdateien

### `.synk/{sessionId}/GOTCHAS.md`

Muss mindestens diese Überschriften enthalten:

```markdown
# Session GOTCHAS — {sessionId}

## Ownership

## Advisory Learnings

## Orchestrator Notes

## Promotion Candidates
```

### `.snyk/GOTCHAS.md`

Muss mindestens diese Überschriften enthalten:

```markdown
# Snyk GOTCHAS

## Ownership

## Permanent Rules
```
