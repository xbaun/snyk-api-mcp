from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
import sys
from typing import Any

from .common import (
    ALLOWED_FAILURE_KIND,
    ALLOWED_STATUS,
    ALLOWED_SEVERITY,
    LedgerError,
    advisory_package,
    find_advisory,
    git_status_lines,
    load_json,
    load_ledger,
    now_iso,
    parse_json_array,
    parse_json_object,
    print_json,
    require_list,
    require_non_empty_string,
    require_object,
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

ALLOWED_PACKAGE_STATUS = {'resolved', 'partially-resolved', 'blocked'}
ALLOWED_CODE_STATUS = {'resolved', 'blocked'}
ALLOWED_PACKAGE_STRATEGY = {
    'update-direct',
    'update-parent',
    'consolidated-shared-upgrade',
    'temp-override',
}
ALLOWED_PACKAGE_RISK_LEVEL = {'low', 'medium', 'high'}
ALLOWED_PACKAGE_COMPLEXITY = {'contained', 'architectural'}
ALLOWED_CODE_RESOLVED_COMPLEXITY = {'trivial', 'contained'}
ALLOWED_CODE_BLOCKED_COMPLEXITY = {'false-positive', 'architectural'}
ALLOWED_IMPLEMENTATION_FIELDS = {
    'filesChanged',
    'dependencyUpdates',
    'parentUpdates',
    'overridesApplied',
    'overridePreflight',
}
ALLOWED_VERIFICATION_FIELDS = {'dependencyCheck', 'lint', 'typecheck', 'tests', 'build'}
ALLOWED_OUTCOME_FIELDS = {'result', 'summary', 'blockers', 'remediationProposal', 'rationale'}
ALLOWED_TOP_LEVEL_FIELDS = set(TOP_LEVEL_HANDBACK_FIELDS) | set(NESTED_HANDBACK_FIELDS)
ALLOWED_PACKAGE_TOP_LEVEL_FIELDS = {
    'issueType',
    'status',
    'vulnerablePackage',
    'vulnerableVersions',
    'targetVersion',
    'strategy',
    'riskLevel',
    'complexity',
    'implementation',
    'verification',
    'outcome',
}
ALLOWED_CODE_RESOLVED_TOP_LEVEL_FIELDS = {
    'issueType',
    'status',
    'filePath',
    'lineRange',
    'cweId',
    'severity',
    'complexity',
    'implementation',
    'verification',
    'outcome',
}
ALLOWED_CODE_BLOCKED_TOP_LEVEL_FIELDS = {
    'issueType',
    'status',
    'filePath',
    'lineRange',
    'cweId',
    'severity',
    'complexity',
    'outcome',
}


def ensure_allowed_keys(value: dict[str, Any], allowed: set[str], field_name: str) -> None:
    unexpected = sorted(key for key in value if key not in allowed)
    if unexpected:
        raise LedgerError(
            f"Field '{field_name}' contains unsupported keys: {', '.join(unexpected)}."
        )


def ensure_no_nulls(value: Any, field_name: str) -> None:
    if value is None:
        raise LedgerError(f"Field '{field_name}' must not be null.")

    if isinstance(value, dict):
        for key, nested in value.items():
            ensure_no_nulls(nested, f'{field_name}.{key}')
        return

    if isinstance(value, list):
        for index, nested in enumerate(value):
            ensure_no_nulls(nested, f'{field_name}[{index}]')


def require_enum(value: Any, allowed: set[str], field_name: str) -> str:
    normalized = require_non_empty_string(value, field_name)
    if normalized not in allowed:
        raise LedgerError(
            f"Field '{field_name}' must be one of: {', '.join(sorted(allowed))}."
        )
    return normalized


def require_string_array(value: Any, field_name: str, *, min_items: int = 0) -> list[str]:
    items = require_list(value, field_name)
    if len(items) < min_items:
        qualifier = f' >= {min_items}' if min_items else ' >= 0'
        raise LedgerError(f"Field '{field_name}' must contain{qualifier} items.")

    result: list[str] = []
    for index, item in enumerate(items):
        result.append(require_non_empty_string(item, f'{field_name}[{index}]'))
    return result


def validate_override_preflight(preflight: Any, vulnerable_package: str) -> None:
    preflight_obj = require_object(preflight, 'implementation.overridePreflight')
    ensure_allowed_keys(preflight_obj, {'materializationPresent', 'queryPackage', 'matchingCaseKeys', 'selectorConflict', 'disposition'}, 'implementation.overridePreflight')

    missing = [
        field
        for field in ('materializationPresent', 'queryPackage', 'matchingCaseKeys', 'selectorConflict', 'disposition')
        if field not in preflight_obj
    ]
    if missing:
        raise LedgerError(
            'implementation.overridePreflight is missing required fields: '
            + ', '.join(missing)
        )

    materialization_present = preflight_obj.get('materializationPresent')
    if not isinstance(materialization_present, bool):
        raise LedgerError("Field 'implementation.overridePreflight.materializationPresent' must be boolean.")

    query_package = require_non_empty_string(
        preflight_obj.get('queryPackage'),
        'implementation.overridePreflight.queryPackage',
    )
    if query_package != vulnerable_package:
        raise LedgerError(
            "Field 'implementation.overridePreflight.queryPackage' must match 'vulnerablePackage'."
        )

    matching_case_keys = require_string_array(
        preflight_obj.get('matchingCaseKeys'),
        'implementation.overridePreflight.matchingCaseKeys',
    )
    selector_conflict = require_enum(
        preflight_obj.get('selectorConflict'),
        {'none', 'exact-selector', 'same-package'},
        'implementation.overridePreflight.selectorConflict',
    )
    disposition = require_enum(
        preflight_obj.get('disposition'),
        {'reuse-existing-case', 'create-new-case'},
        'implementation.overridePreflight.disposition',
    )

    if not materialization_present:
        if matching_case_keys:
            raise LedgerError(
                "Field 'implementation.overridePreflight.matchingCaseKeys' must be empty when no materialization existed."
            )
        if selector_conflict != 'none':
            raise LedgerError(
                "Field 'implementation.overridePreflight.selectorConflict' must be 'none' when no materialization existed."
            )
        if disposition != 'create-new-case':
            raise LedgerError(
                "Field 'implementation.overridePreflight.disposition' must be 'create-new-case' when no materialization existed."
            )

    if disposition == 'reuse-existing-case':
        if not materialization_present:
            raise LedgerError(
                "Field 'implementation.overridePreflight.disposition' cannot reuse a case without prior materialization."
            )
        if not matching_case_keys and selector_conflict == 'none':
            raise LedgerError(
                "Field 'implementation.overridePreflight.disposition' requires matchingCaseKeys or a selector conflict when reusing a case."
            )

    if disposition == 'create-new-case' and (matching_case_keys or selector_conflict == 'exact-selector'):
        raise LedgerError(
            'Temp override handback cannot create a new case when analyze already found active matching cases or an exact-selector conflict.'
        )


def validate_implementation(
    implementation: Any,
    *,
    issue_type: str,
    require_files_changed: bool,
    vulnerable_package: str | None = None,
    strategy: str | None = None,
) -> None:
    implementation_obj = require_object(implementation, 'implementation')
    ensure_allowed_keys(implementation_obj, ALLOWED_IMPLEMENTATION_FIELDS, 'implementation')

    if require_files_changed or 'filesChanged' in implementation_obj:
        require_string_array(implementation_obj.get('filesChanged'), 'implementation.filesChanged')

    if 'dependencyUpdates' in implementation_obj:
        require_string_array(implementation_obj.get('dependencyUpdates'), 'implementation.dependencyUpdates', min_items=1)
    if 'parentUpdates' in implementation_obj:
        require_string_array(implementation_obj.get('parentUpdates'), 'implementation.parentUpdates', min_items=1)

    if strategy == 'temp-override':
        require_string_array(
            implementation_obj.get('overridesApplied'),
            'implementation.overridesApplied',
            min_items=1,
        )
        validate_override_preflight(implementation_obj.get('overridePreflight'), vulnerable_package or '')
    else:
        if 'overridesApplied' in implementation_obj or 'overridePreflight' in implementation_obj:
            raise LedgerError(
                'Override fields are only allowed when strategy is temp-override.'
            )

    if issue_type == 'code' and (
        'dependencyUpdates' in implementation_obj
        or 'parentUpdates' in implementation_obj
        or 'overridesApplied' in implementation_obj
        or 'overridePreflight' in implementation_obj
    ):
        raise LedgerError('Code handbacks must not report dependency override implementation fields.')


def validate_verification(
    verification: Any,
    *,
    issue_type: str,
    status: str,
) -> None:
    verification_obj = require_object(verification, 'verification')
    ensure_allowed_keys(verification_obj, ALLOWED_VERIFICATION_FIELDS, 'verification')

    if issue_type == 'package_vulnerability':
        missing = [
            field
            for field in ('dependencyCheck', 'lint', 'typecheck', 'tests', 'build')
            if field not in verification_obj
        ]
        if missing:
            raise LedgerError(
                "verification is missing required package fields: " + ', '.join(missing)
            )
        dependency_check = require_enum(
            verification_obj.get('dependencyCheck'),
            {'pass', 'fail'},
            'verification.dependencyCheck',
        )
        for field in ('lint', 'typecheck', 'tests', 'build'):
            require_enum(verification_obj.get(field), {'pass', 'fail', 'not-run'}, f'verification.{field}')
        if status == 'resolved' and dependency_check != 'pass':
            raise LedgerError(
                "Resolved package handbacks require verification.dependencyCheck = 'pass'."
            )
        return

    missing = [field for field in ('lint', 'typecheck', 'tests') if field not in verification_obj]
    if missing:
        raise LedgerError(
            "verification is missing required code fields: " + ', '.join(missing)
        )
    for field in ('lint', 'typecheck', 'tests'):
        require_enum(verification_obj.get(field), {'pass', 'fail', 'not-run'}, f'verification.{field}')
    if 'dependencyCheck' in verification_obj or 'build' in verification_obj:
        raise LedgerError(
            'Code handbacks must not include verification.dependencyCheck or verification.build.'
        )


def validate_outcome(
    outcome: Any,
    *,
    status: str,
    require_blocking_fields: bool,
) -> None:
    outcome_obj = require_object(outcome, 'outcome')
    ensure_allowed_keys(outcome_obj, ALLOWED_OUTCOME_FIELDS, 'outcome')
    require_non_empty_string(outcome_obj.get('summary'), 'outcome.summary')
    result = require_non_empty_string(outcome_obj.get('result'), 'outcome.result')
    if result != status:
        raise LedgerError("Field 'outcome.result' must match handback 'status'.")

    if require_blocking_fields:
        require_string_array(outcome_obj.get('blockers'), 'outcome.blockers', min_items=1)
        require_non_empty_string(
            outcome_obj.get('remediationProposal'),
            'outcome.remediationProposal',
        )
        require_non_empty_string(outcome_obj.get('rationale'), 'outcome.rationale')


def validate_package_handback(handback: dict[str, Any]) -> None:
    ensure_allowed_keys(handback, ALLOWED_PACKAGE_TOP_LEVEL_FIELDS, 'handback')
    status = require_enum(handback.get('status'), ALLOWED_PACKAGE_STATUS, 'status')
    vulnerable_package = require_non_empty_string(handback.get('vulnerablePackage'), 'vulnerablePackage')
    require_string_array(handback.get('vulnerableVersions'), 'vulnerableVersions', min_items=1)
    strategy = require_enum(handback.get('strategy'), ALLOWED_PACKAGE_STRATEGY, 'strategy')
    require_non_empty_string(handback.get('targetVersion'), 'targetVersion')
    require_enum(handback.get('riskLevel'), ALLOWED_PACKAGE_RISK_LEVEL, 'riskLevel')
    require_enum(handback.get('complexity'), ALLOWED_PACKAGE_COMPLEXITY, 'complexity')
    validate_implementation(
        handback.get('implementation'),
        issue_type='package_vulnerability',
        require_files_changed=True,
        vulnerable_package=vulnerable_package,
        strategy=strategy,
    )
    validate_verification(handback.get('verification'), issue_type='package_vulnerability', status=status)
    validate_outcome(
        handback.get('outcome'),
        status=status,
        require_blocking_fields=status in {'blocked', 'partially-resolved'},
    )


def validate_code_handback(handback: dict[str, Any]) -> None:
    status = require_enum(handback.get('status'), ALLOWED_CODE_STATUS, 'status')
    allowed_fields = (
        ALLOWED_CODE_RESOLVED_TOP_LEVEL_FIELDS
        if status == 'resolved'
        else ALLOWED_CODE_BLOCKED_TOP_LEVEL_FIELDS
    )
    ensure_allowed_keys(handback, allowed_fields, 'handback')
    require_non_empty_string(handback.get('filePath'), 'filePath')
    require_non_empty_string(handback.get('lineRange'), 'lineRange')
    require_non_empty_string(handback.get('cweId'), 'cweId')
    require_enum(handback.get('severity'), ALLOWED_SEVERITY, 'severity')

    if status == 'resolved':
        require_enum(handback.get('complexity'), ALLOWED_CODE_RESOLVED_COMPLEXITY, 'complexity')
        validate_implementation(
            handback.get('implementation'),
            issue_type='code',
            require_files_changed=True,
        )
        validate_verification(handback.get('verification'), issue_type='code', status=status)
        validate_outcome(handback.get('outcome'), status=status, require_blocking_fields=False)
        return

    require_enum(handback.get('complexity'), ALLOWED_CODE_BLOCKED_COMPLEXITY, 'complexity')
    if 'implementation' in handback or 'verification' in handback:
        raise LedgerError('Blocked code handbacks must not include implementation or verification blocks.')
    validate_outcome(handback.get('outcome'), status=status, require_blocking_fields=True)


def validate_handback(advisory: dict[str, Any], handback: dict[str, Any]) -> None:
    ensure_no_nulls(handback, 'handback')
    ensure_allowed_keys(handback, ALLOWED_TOP_LEVEL_FIELDS, 'handback')

    issue_type = require_non_empty_string(handback.get('issueType'), 'issueType')
    advisory_issue_type = require_non_empty_string(advisory.get('issueType'), 'advisory.issueType')
    if issue_type != advisory_issue_type:
        raise LedgerError(
            f"Handback issueType '{issue_type}' does not match advisory issueType '{advisory_issue_type}'."
        )

    if issue_type == 'package_vulnerability':
        validate_package_handback(handback)
        return

    if issue_type == 'code':
        validate_code_handback(handback)
        return

    raise LedgerError(f"Unsupported handback issueType '{issue_type}'.")


def load_handback_input(from_handback: str) -> dict[str, Any]:
    if from_handback == '-':
        try:
            handback = json.loads(sys.stdin.read())
        except json.JSONDecodeError as exc:
            raise LedgerError(f'Invalid JSON in stdin handback: {exc}') from exc
    else:
        handback = load_json(Path(from_handback))

    if not isinstance(handback, dict):
        raise LedgerError('Handback root must be an object.')
    return handback


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
    if not args.issue_type:
        raise LedgerError("Inline update requires '--issue-type'.")

    handback: dict[str, Any] = {'issueType': args.issue_type, 'status': args.status}

    optional_scalar_map = {
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
        'overridePreflight': parse_json_object(args.override_preflight, 'override-preflight'),
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
    validate_handback(advisory, handback)

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
        handback = load_handback_input(args.from_handback)
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
