# snyk-ledger-remediation handback format

## Purpose

This document defines the only allowed return format from `snyk-resolve-dep` and `snyk-resolve-code` to `snyk-ledger-remediation`.

## Ownership

This document is the single source of truth for the handback protocol.

- `snyk-ledger-remediation` validates against it.
- `snyk-resolve-dep` and `snyk-resolve-code` must not redefine it.
- Agent files should point here instead of duplicating field lists or JSON shapes.

## Global rules

- Output is exactly one JSON object.
- No Markdown fences.
- No prose before or after the JSON.
- No `null` values; omit unknown fields.
- `issueType` must match the handoff exactly.
- The object must be usable directly as stdin for `ledger.py update --from-handback -`.

## Semantic baseline

- `resolved` = the work unit was remediated successfully within the allowed scope.
- `blocked` = no safe or allowed automatic remediation exists within the allowed scope.
- `partially-resolved` = only part of the work unit improved; this is valid only for `package_vulnerability`.
- `implementation` describes what actually changed or ran.
- `verification` describes which checks actually ran and what they returned.
- `outcome` describes the practical result of the run.

---

## package_vulnerability

### Allowed statuses

- `resolved`
- `partially-resolved`
- `blocked`

### Required fields

```json
{
  "issueType": "package_vulnerability",
  "status": "resolved | partially-resolved | blocked",
  "vulnerablePackage": "string",
  "vulnerableVersions": ["string"],
  "targetVersion": "string",
  "strategy": "update-direct | update-parent | consolidated-shared-upgrade | temp-override",
  "riskLevel": "low | medium | high",
  "complexity": "contained | architectural",
  "implementation": {
    "filesChanged": ["string"]
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

### Optional `implementation` fields

If present, use exactly these names:

- `dependencyUpdates`
- `parentUpdates`
- `overridesApplied`

### Field semantics

- `vulnerablePackage` = canonical name of the affected package
- `vulnerableVersions` = concrete problematic versions actually observed
- `targetVersion` = target version or target resolution for the remediation
- `strategy`
  - `update-direct` = upgrade the direct dependency
  - `update-parent` = upgrade a controllable parent dependency
  - `consolidated-shared-upgrade` = one shared lever fixes multiple affected paths in the same work unit
  - `temp-override` = temporary manager-specific override or resolution materialization
- `riskLevel`
  - `low` = low change risk or tightly localized effect
  - `medium` = bounded but noticeable change risk
  - `high` = elevated risk of side effects or manual follow-up
- `complexity`
  - `contained` = remediation stays within the allowed execution boundary
  - `architectural` = remediation exceeds that boundary or requires non-local decisions

### Additional rules

- If `status = resolved`, `verification.dependencyCheck` must be `pass`.
- If `status = blocked` or `status = partially-resolved`, `outcome` must also contain:
  - `blockers`
  - `remediationProposal`
  - `rationale`
- If `strategy = temp-override`, `implementation.overridesApplied` should not be empty.

---

## code

### Allowed statuses

- `resolved`
- `blocked`

### Resolved format

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
    "filesChanged": ["string"]
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

### Blocked format

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

### Optional `implementation` fields

None.

### Field semantics

- `filePath` = canonical repo-relative path to the primary affected file
- `lineRange` = human-readable range of affected or changed lines, for example `42-42` or `42-57`
- `cweId` = relevant CWE-like classification when it can be derived from the finding
- `severity` = severity used for resolver prioritization
- `complexity`
  - `trivial` = very local, obvious fix with minimal blast radius
  - `contained` = small but slightly context-sensitive fix within scope
  - `false-positive` = no code change is required after context inspection
  - `architectural` = the necessary change is no longer local and clearly bounded

---

## Validation notes for the coordinator

The coordinator must at least verify:

1. Is the payload valid JSON?
2. Is `issueType` correct?
3. Is `status` allowed for this resolver?
4. Are all required fields present?
5. Are `blocked` or `partially-resolved` responses fully justified?
6. Is dep `resolved` claimed only when `dependencyCheck = pass`?
7. Are there no `null` values?
