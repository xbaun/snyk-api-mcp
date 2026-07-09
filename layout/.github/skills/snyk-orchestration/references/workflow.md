# snyk-orchestration workflow

## Ziel

Dieser Workflow ist normativ. `snyk-orchestration` soll nicht "frei improvisieren", sondern exakt diese Abfolge deterministisch ausführen.

## Normativer Ablauf

1. **Gate [O1] — Selection**
   - `ledger.py select --ledger ... --repo-root . --format json` ausführen
   - Resume-Fall oder Dirty-Stop aus dessen Ergebnis ableiten
   - sonst nächstes `not-started` Advisory deterministisch aus dessen Ergebnis übernehmen
   - optional für Operator-Überblick: `ledger.py analyze --ledger ... --format json`
   - `ledger.py set-status --ledger ... --key <advisoryKey> --status in-progress`

2. **Gate [O2] — Dispatch**
   - Resolver ausschließlich aus `issueType` ableiten

3. **Gate [O3] — Handoff Build**
   - Handoff strikt nach `handoff-format.md` erzeugen
   - Seed-Issues nach `advisoryKey` filtern

4. **Resolver-Run**
   - `snyk-resolve-dep` oder `snyk-resolve-code` genau einmal starten

5. **Gate [O4] — Handback Validation**
   - Handback streng gegen `handback-format.md` prüfen
   - bei Parse-/Format-Fehler `ledger.py record-failure` nutzen und den Fehler präzise persistieren

6. **Gate [O5] — Override Validation**
   - nur falls Overrides gemeldet wurden

7. **Gate [O6] — Code Health Validation**
   - Mindestkonsistenz der behaupteten Verifikationen prüfen

8. **Gate [O7] — Ledger Update**
   - `ledger.py update` mit stdin-first Handback-Übergabe (`--from-handback -`)
   - JSON-Integrität prüfen

9. **Gate [O8] — Cascade Check**
   - nur für `package_vulnerability` + `resolved`

10. **Gate [O9] — GOTCHAS Curation**
   - Session-GOTCHAS prüfen
   - dauerhafte Learnings ggf. nach `.snyk/GOTCHAS.md` promoten

11. **Loop**
   - zurück zu Gate [O1], bis keine `not-started` Advisories mehr vorhanden sind

## Harte Invarianten

- Nie direkt `issues-ledger.json` per LLM editieren
- Nie Gate-[O1]-Control-Flow durch manuelles Ledger-Scannen rekonstruieren; dafür ist `ledger.py select` zuständig
- Nie Dispatch anhand anderer Felder als `issueType`
- Nie ohne persistierten `in-progress` Status einen Resolver starten
- Nie Handback-Inhalte erraten oder still reparieren
- Nie Cascade-Apply ohne echte Lockfile-/Dependency-Evidenz
- Nie Resolver direkt in `.snyk/GOTCHAS.md` schreiben lassen

## Minimaler Entscheidungsbaum

```text
ledger lesen
└─ in-progress vorhanden?
   ├─ ja → dirty?
   │  ├─ ja → stoppe und hole explizite User-Entscheidung
   │  └─ nein → resume dieses Advisory
   └─ nein → erstes not-started per Sortierung wählen
      ├─ keines vorhanden → Ende
      └─ set-status(in-progress)
         └─ issueType?
            ├─ package_vulnerability → dep resolver
            └─ code → code resolver
```

## Ergebnis pro Advisory

Jeder Advisory-Durchlauf endet genau in einem dieser Zustände:

- `resolved`
- `blocked`
- `partially-resolved`

Es gibt keinen vierten semantischen Endzustand.

## GOTCHAS Ownership im Workflow

- `snyk-session-init` erzeugt die Dateien.
- Resolver schreiben advisory-spezifische Learnings nur nach `.synk/{sessionId}/GOTCHAS.md`.
- `snyk-orchestration` schreibt Orchestrator-Notizen ebenfalls in die Session-Datei und ist allein für Promotionen nach `.snyk/GOTCHAS.md` verantwortlich.
- Resume-/Failure-relevante Fehlerzustände werden zusätzlich im Ledger persistiert.
