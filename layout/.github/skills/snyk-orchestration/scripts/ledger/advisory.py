from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from .common import (
    ALLOWED_FAILURE_KIND,
    ALLOWED_STATUS,
    LedgerError,
    advisory_package,
    find_advisory,
    git_status_lines,
    load_json,
    load_ledger,
    now_iso,
    parse_json_array,
    print_json,
    select_advisory,
    sort_advisories,
    status_counts,
    write_json,
)

TOP_LEVEL_HANDBACK_FIELDS = [
    'issueType',
    'status',
    'vulnerablePackage',
    'vulnerableVersions',
    'targetVersion',
    'strategy',
    'riskLevel',
    'complexity',
    'filePath',
    'lineRange',
    'cweId',
    'severity',
]
NESTED_HANDBACK_FIELDS = ['implementation', 'verification', 'outcome']


def normalize_handback(handback: dict[str, Any], advisory_key: str) -> dict[str, Any]:
    normalized = deepcopy(handback)
    outcome = normalized.get('outcome')

    outcome_fields = {
        'summary': normalized.pop('summary', None),
        'blockers': normalized.pop('blockers', None),
        'remediationProposal': normalized.pop('remediationProposal', None),
        'rationale': normalized.pop('rationale', None),
    }

    if outcome is not None and not isinstance(outcome, dict):
        raise LedgerError("Handback field 'outcome' must be an object when present.")

    merged_outcome = deepcopy(outcome) if isinstance(outcome, dict) else {}
    for key, value in outcome_fields.items():
        if value not in (None, [], {}):
            merged_outcome[key] = value

    if merged_outcome:
        merged_outcome.setdefault('result', normalized.get('status'))
        merged_outcome.setdefault('summary', f"{advisory_key}: {normalized.get('status', 'unknown')}")
        normalized['outcome'] = merged_outcome

    return normalized


def build_inline_handback(args: Any) -> dict[str, Any]:
    if not args.status:
        raise LedgerError("Inline update requires '--status'.")

    handback: dict[str, Any] = {'status': args.status}

    optional_scalar_map = {
        'issueType': args.issue_type,
        'vulnerablePackage': args.package,
        'targetVersion': args.target_version,
        'strategy': args.strategy,
        'riskLevel': args.risk_level,
        'complexity': args.complexity,
        'filePath': args.file_path,
        'lineRange': args.line_range,
        'cweId': args.cwe_id,
        'severity': args.severity,
    }
    for key, value in optional_scalar_map.items():
        if value is not None:
            handback[key] = value

    vulnerable_versions = parse_json_array(args.vuln_versions, 'vuln-versions')
    if vulnerable_versions:
        handback['vulnerableVersions'] = vulnerable_versions

    implementation = {
        'filesChanged': parse_json_array(args.files_changed, 'files-changed'),
        'dependencyUpdates': parse_json_array(args.dep_updates, 'dep-updates'),
        'parentUpdates': parse_json_array(args.parent_updates, 'parent-updates'),
        'overridesApplied': parse_json_array(args.overrides, 'overrides'),
    }
    implementation = {key: value for key, value in implementation.items() if value not in (None, [], {})}
    if implementation:
        handback['implementation'] = implementation

    verification = {
        'dependencyCheck': args.dep_check,
        'lint': args.lint,
        'typecheck': args.tsc,
        'tests': args.tests,
        'build': args.build,
    }
    verification = {key: value for key, value in verification.items() if value is not None}
    if verification:
        handback['verification'] = verification

    blockers = parse_json_array(args.blockers, 'blockers')
    if args.summary or blockers or args.remediation_proposal or args.rationale:
        handback['outcome'] = {
            'result': args.status,
            'summary': args.summary or f"{args.key}: {args.status}",
            **({'blockers': blockers} if blockers else {}),
            **({'remediationProposal': args.remediation_proposal} if args.remediation_proposal else {}),
            **({'rationale': args.rationale} if args.rationale else {}),
        }

    return handback


def apply_handback(advisory: dict[str, Any], handback: dict[str, Any]) -> None:
    handback = normalize_handback(handback, str(advisory.get('advisoryKey', '<unknown>')))

    if 'status' not in handback:
        raise LedgerError("Handback must include 'status'.")
    if handback['status'] not in ALLOWED_STATUS:
        raise LedgerError(f"Unsupported status '{handback['status']}'.")

    for field in TOP_LEVEL_HANDBACK_FIELDS:
        if field in handback:
            advisory[field] = deepcopy(handback[field])

    for field in NESTED_HANDBACK_FIELDS:
        if field in handback:
            advisory[field] = deepcopy(handback[field])

    if 'outcome' not in advisory:
        advisory['outcome'] = {
            'result': advisory['status'],
            'summary': f"{advisory['advisoryKey']}: {advisory['status']}",
        }
    elif 'result' not in advisory['outcome']:
        advisory['outcome']['result'] = advisory['status']

    if advisory['status'] == 'in-progress':
        advisory['startedAt'] = advisory.get('startedAt', now_iso())
        advisory.pop('completedAt', None)
    else:
        advisory['completedAt'] = now_iso()


def cmd_next(args: Any) -> int:
    ledger = load_ledger(Path(args.from_path))
    next_advisory = next(
        (advisory for advisory in sort_advisories(ledger['advisories']) if advisory.get('status') == 'not-started'),
        None,
    )

    if args.format == 'json':
        print_json(next_advisory)
        return 0

    if next_advisory is None:
        print('No not-started advisories found.')
        return 0

    print(
        f"{next_advisory['advisoryKey']} | {next_advisory['issueType']} | "
        f"{next_advisory['severity']} | {next_advisory['title']}"
    )
    return 0


def cmd_select(args: Any) -> int:
    ledger = load_ledger(Path(args.ledger))
    decision, selected = select_advisory(ledger)

    dirty_entries: list[str] = []
    dirty: bool | None = None
    if args.repo_root:
        dirty_entries = git_status_lines(Path(args.repo_root))
        dirty = len(dirty_entries) > 0

    if decision == 'resume' and dirty:
        decision = 'dirty-stop'

    payload = {
        'decision': decision,
        'selectedAdvisory': selected,
        'dirty': dirty,
        'dirtyEntries': dirty_entries,
        'statusCounts': status_counts(ledger['advisories']),
    }

    if args.format == 'json':
        print_json(payload)
        return 0

    if decision == 'done':
        print('done | no advisories remaining')
        return 0

    advisory = selected or {}
    print(
        f"{decision} | {advisory.get('advisoryKey', '<none>')} | "
        f"{advisory.get('issueType', '<unknown>')} | "
        f"{advisory.get('severity', '<unknown>')} | "
        f"{advisory.get('title', '<unknown>')}"
    )
    if dirty_entries:
        for entry in dirty_entries:
            print(f'dirty | {entry}')
    return 0


def cascade_candidates(ledger: dict[str, Any], resolved_key: str, package: str) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for advisory in ledger['advisories']:
        if advisory.get('advisoryKey') == resolved_key:
            continue
        if advisory.get('status') != 'not-started':
            continue
        if advisory_package(advisory) == package:
            candidates.append(advisory)
    return sort_advisories(candidates)


def cmd_cascade_check(args: Any) -> int:
    ledger_path = Path(args.ledger)
    ledger = load_ledger(ledger_path)
    resolved_advisory = find_advisory(ledger, args.resolved_key)
    resolved_package = advisory_package(resolved_advisory)
    if resolved_package and resolved_package != args.package:
        raise LedgerError(
            f"Cascade package mismatch for '{args.resolved_key}': got '{args.package}', "
            f"expected '{resolved_package}'. Use vulnerablePackage when known, otherwise the seed packageName."
        )
    candidates = cascade_candidates(ledger, args.resolved_key, args.package)

    if args.apply:
        for advisory in candidates:
            advisory['status'] = 'resolved'
            advisory['outcome'] = {
                'result': 'resolved',
                'summary': f"Cascade from {args.resolved_key}",
            }
            advisory['completedAt'] = now_iso()
        write_json(ledger_path, ledger)

    print_json(
        {
            'resolvedKey': args.resolved_key,
            'package': args.package,
            'candidateCount': len(candidates),
            'applied': bool(args.apply),
            'candidates': candidates,
        }
    )
    return 0


def cmd_update(args: Any) -> int:
    ledger_path = Path(args.ledger)
    ledger = load_ledger(ledger_path)
    advisory = find_advisory(ledger, args.key)

    if args.from_handback:
        handback = load_json(Path(args.from_handback))
        if not isinstance(handback, dict):
            raise LedgerError('Handback root must be an object.')
    else:
        handback = build_inline_handback(args)

    apply_handback(advisory, handback)
    write_json(ledger_path, ledger)
    print_json({'key': args.key, 'status': advisory['status']})
    return 0


def cmd_record_failure(args: Any) -> int:
    ledger_path = Path(args.ledger)
    ledger = load_ledger(ledger_path)
    advisory = find_advisory(ledger, args.key)

    if args.kind not in ALLOWED_FAILURE_KIND:
        raise LedgerError(f"Unsupported failure kind '{args.kind}'.")

    advisory['lastFailureKind'] = args.kind
    advisory['lastFailureAt'] = now_iso()
    if args.message:
        advisory['lastFailureMessage'] = args.message

    write_json(ledger_path, ledger)
    print_json(
        {
            'key': args.key,
            'status': advisory.get('status'),
            'lastFailureKind': advisory.get('lastFailureKind'),
        }
    )
    return 0


def cmd_set_status(args: Any) -> int:
    if args.status not in ALLOWED_STATUS:
        raise LedgerError(f"Unsupported status '{args.status}'.")

    ledger_path = Path(args.ledger)
    ledger = load_ledger(ledger_path)
    advisory = find_advisory(ledger, args.key)
    previous_status = advisory.get('status')
    advisory['status'] = args.status

    if args.status == 'in-progress':
        timestamp = now_iso()
        advisory['startedAt'] = timestamp
        advisory['lastAttemptAt'] = timestamp
        advisory.pop('completedAt', None)
    elif args.status in {'resolved', 'blocked', 'partially-resolved'}:
        advisory['completedAt'] = now_iso()

    write_json(ledger_path, ledger)
    print_json({'key': args.key, 'status': args.status})
    return 0
