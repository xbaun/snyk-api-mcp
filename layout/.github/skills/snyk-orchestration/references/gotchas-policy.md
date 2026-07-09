# snyk-orchestration GOTCHAS policy

## Purpose

This policy defines who creates, writes, curates, and promotes `.snyk/GOTCHAS.md` and `.synk/{sessionId}/GOTCHAS.md`.

## Ownership

### `.snyk/GOTCHAS.md`

- Type: permanent, repo-wide, cross-session lessons
- Owner: `snyk-orchestration`
- Write access: `snyk-orchestration` only
- Resolvers (`snyk-resolve-dep`, `snyk-resolve-code`) must never edit this file directly

### `.synk/{sessionId}/GOTCHAS.md`

- Type: session-specific work notes and learnings
- Owner: the session run under `snyk-orchestration`
- Initial creation: `snyk-session-init`
- Write access:
  - `snyk-resolve-dep` → advisory-specific dependency learnings
  - `snyk-resolve-code` → advisory-specific code or false-positive learnings
  - `snyk-orchestration` → loop, resume, failure, or cascade learnings

## Write duties

### `snyk-session-init`

At session start it must:

1. create `.snyk/GOTCHAS.md` if missing
2. create `.synk/{sessionId}/GOTCHAS.md` with the required session structure below

### `snyk-resolve-dep`

Before returning the final handback, it must append an entry to `.synk/{sessionId}/GOTCHAS.md` when any of these is true:

- `status == blocked`
- `status == partially-resolved`
- `strategy == temp-override`
- a repo-specific dependency, lockfile, or parent-resolution behavior changed the remediation path in a way future advisories should know

### `snyk-resolve-code`

Before returning the final handback, it must append an entry to `.synk/{sessionId}/GOTCHAS.md` when any of these is true:

- `status == blocked`
- `complexity == false-positive`
- a repo-specific sanitization, validation, or verification pattern changed the remediation path in a way future advisories should know

### `snyk-orchestration`

It must:

1. write its own session GOTCHA for dirty resume, failure, or cascade anomalies
2. review new session GOTCHAS after every validated advisory run
3. promote durable, reusable lessons into `.snyk/GOTCHAS.md`
4. deduplicate or update existing permanent rules instead of blindly appending duplicates

## Promotion rule for `.snyk/GOTCHAS.md`

A session GOTCHA may be promoted only when it is:

- repo-specific
- likely to matter again in later sessions
- phrased as a concrete action rule
- more than a one-off observation

Do not promote:

- one-time typos
- random network or CI noise
- advisory-specific edge cases with no reuse value

## Session entry format

Each entry in `.synk/{sessionId}/GOTCHAS.md` must use this format:

```markdown
## {advisoryKey} — {short title}
- owner: snyk-resolve-dep | snyk-resolve-code | snyk-orchestration
- status: resolved | blocked | partially-resolved | operational
- promote: yes | no
- category: dependency | override | code | verification | orchestration
- lesson: {concrete observation or rule}
- evidence:
  - {file, command, or observation}
  - {file, command, or observation}
- next-time: {concrete instruction for future runs}
```

## Permanent entry format

Each entry in `.snyk/GOTCHAS.md` must use this format:

```markdown
## {stable short rule title}
- promoted-by: snyk-orchestration
- source-session: {sessionId}
- applies-when: {situation / trigger}
- rule: {durable action rule}
- verify-with:
  - {command, file, or check}
```

## Required initial file contents

### `.synk/{sessionId}/GOTCHAS.md`

It must contain at least these headings:

```markdown
# Session GOTCHAS — {sessionId}

## Ownership

## Advisory Learnings

## Orchestrator Notes

## Promotion Candidates
```

### `.snyk/GOTCHAS.md`

It must contain at least these headings:

```markdown
# Snyk GOTCHAS

## Ownership

## Permanent Rules
```
