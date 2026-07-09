from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from .common import (
    ALLOWED_ISSUE_TYPE,
    ALLOWED_SEVERITY,
    LedgerError,
    LEDGER_SCHEMA_PATH,
    SEED_SCHEMA_PATH,
    SEED_TOP_LEVEL_REQUIRED,
    load_json,
    print_json,
    require_list,
    require_non_empty_string,
    require_non_negative_int,
    require_number,
    require_object,
    require_positive_int,
    sort_advisories,
    write_json,
)

SEED_ADVISORY_REQUIRED = [
    'advisoryKey',
    'title',
    'severity',
    'issueType',
    'issueCount',
    'affectedProjectCount',
    'affectedProjectIds',
    'affectedWorkspacePackages',
    'createdAt',
    'riskScoreMax',
]

INIT_LEDGER_FIELDS = [
    'advisoryKey',
    'title',
    'severity',
    'issueType',
    'riskScoreMax',
    'issueCount',
    'affectedProjectCount',
    'affectedProjectIds',
    'affectedWorkspacePackages',
    'createdAt',
    'packageName',
]


def normalize_seed_advisory(raw: dict[str, Any]) -> dict[str, Any]:
    missing = [field for field in SEED_ADVISORY_REQUIRED if field not in raw]
    if missing:
        raise LedgerError(
            f"Seed advisory '{raw.get('advisoryKey', '<unknown>')}' is missing fields: {', '.join(missing)}"
        )

    issue_type = raw.get('issueType')
    if issue_type not in ALLOWED_ISSUE_TYPE:
        raise LedgerError(
            f"Seed advisory '{raw.get('advisoryKey', '<unknown>')}' has unsupported issueType '{issue_type}'. "
            "Expected 'package_vulnerability' or 'code'."
        )

    severity = raw.get('severity')
    if severity not in ALLOWED_SEVERITY:
        raise LedgerError(
            f"Seed advisory '{raw.get('advisoryKey', '<unknown>')}' has unsupported severity '{severity}'."
        )

    issue_count = raw.get('issueCount')
    if not isinstance(issue_count, int) or issue_count < 1:
        raise LedgerError(
            f"Seed advisory '{raw.get('advisoryKey', '<unknown>')}' requires issueCount >= 1."
        )

    affected_project_count = raw.get('affectedProjectCount')
    if not isinstance(affected_project_count, int) or affected_project_count < 1:
        raise LedgerError(
            f"Seed advisory '{raw.get('advisoryKey', '<unknown>')}' requires affectedProjectCount >= 1."
        )

    affected_project_ids = raw.get('affectedProjectIds')
    if not isinstance(affected_project_ids, list) or not affected_project_ids:
        raise LedgerError(
            f"Seed advisory '{raw.get('advisoryKey', '<unknown>')}' requires a non-empty affectedProjectIds array."
        )

    affected_workspace_packages = raw.get('affectedWorkspacePackages')
    if not isinstance(affected_workspace_packages, list):
        raise LedgerError(
            f"Seed advisory '{raw.get('advisoryKey', '<unknown>')}' requires affectedWorkspacePackages to be an array."
        )

    risk_score_max = raw.get('riskScoreMax')
    if not isinstance(risk_score_max, (int, float)) or isinstance(risk_score_max, bool):
        raise LedgerError(
            f"Seed advisory '{raw.get('advisoryKey', '<unknown>')}' requires numeric riskScoreMax."
        )

    normalized = {field: deepcopy(raw[field]) for field in INIT_LEDGER_FIELDS if field in raw}
    if raw.get('issueType') == 'package_vulnerability' and 'packageName' not in normalized:
        raise LedgerError(
            f"Seed advisory '{raw['advisoryKey']}' requires packageName for issueType=package_vulnerability."
        )
    normalized['status'] = 'not-started'
    normalized['attemptCount'] = 0
    normalized['handbackRetryCount'] = 0
    return normalized


def validate_seed_query(query: Any) -> None:
    query_obj = require_object(query, 'query')
    require_non_empty_string(query_obj.get('orgId'), 'query.orgId')
    require_non_empty_string(query_obj.get('targetId'), 'query.targetId')

    if query_obj.get('status') != 'open':
        raise LedgerError("Field 'query.status' must be 'open'.")

    issue_types = require_list(query_obj.get('issueTypes'), 'query.issueTypes')
    if set(issue_types) != ALLOWED_ISSUE_TYPE:
        raise LedgerError(
            "Field 'query.issueTypes' must contain exactly ['package_vulnerability', 'code']."
        )


def validate_seed_target(target: Any) -> None:
    target_obj = require_object(target, 'target')
    require_non_empty_string(target_obj.get('id'), 'target.id')
    display_name = target_obj.get('displayName')
    if display_name is not None and not isinstance(display_name, str):
        raise LedgerError("Field 'target.displayName' must be a string or null.")


def validate_seed_collection(collection: Any) -> None:
    collection_obj = require_object(collection, 'collection')
    require_non_empty_string(collection_obj.get('fetchedAt'), 'collection.fetchedAt')
    require_non_negative_int(collection_obj.get('projectCount'), 'collection.projectCount')
    require_non_negative_int(collection_obj.get('issueCount'), 'collection.issueCount')
    require_non_negative_int(collection_obj.get('advisoryCount'), 'collection.advisoryCount')


def validate_seed_issue(issue: Any, index: int) -> None:
    issue_obj = require_object(issue, f'issues[{index}]')
    required_fields = [
        'advisoryKey',
        'restIssueId',
        'issueKey',
        'title',
        'issueType',
        'severity',
        'riskScore',
        'createdAt',
        'projectId',
        'projectName',
    ]
    missing = [field for field in required_fields if field not in issue_obj]
    if missing:
        raise LedgerError(
            f"Seed issue #{index} is missing canonical fields: {', '.join(missing)}. "
            "Canonical seed issues must use issueKey/projectId/issueType; old key/scanItemId/type aliases are not supported."
        )

    require_non_empty_string(issue_obj.get('advisoryKey'), f'issues[{index}].advisoryKey')
    require_non_empty_string(issue_obj.get('restIssueId'), f'issues[{index}].restIssueId')
    require_non_empty_string(issue_obj.get('issueKey'), f'issues[{index}].issueKey')
    require_non_empty_string(issue_obj.get('title'), f'issues[{index}].title')
    require_non_empty_string(issue_obj.get('createdAt'), f'issues[{index}].createdAt')
    require_non_empty_string(issue_obj.get('projectId'), f'issues[{index}].projectId')
    require_non_empty_string(issue_obj.get('projectName'), f'issues[{index}].projectName')
    require_number(issue_obj.get('riskScore'), f'issues[{index}].riskScore')

    issue_type = issue_obj.get('issueType')
    if issue_type not in ALLOWED_ISSUE_TYPE:
        raise LedgerError(
            f"Field 'issues[{index}].issueType' must be 'package_vulnerability' or 'code'."
        )

    severity = issue_obj.get('severity')
    if severity not in ALLOWED_SEVERITY:
        raise LedgerError(
            f"Field 'issues[{index}].severity' must be one of: {', '.join(sorted(ALLOWED_SEVERITY))}."
        )

    if issue_type == 'package_vulnerability':
        require_non_empty_string(issue_obj.get('purl'), f'issues[{index}].purl')
        require_non_empty_string(issue_obj.get('packageName'), f'issues[{index}].packageName')

    if issue_type == 'code':
        require_non_empty_string(issue_obj.get('filePath'), f'issues[{index}].filePath')
        require_positive_int(issue_obj.get('startLine'), f'issues[{index}].startLine')
        require_positive_int(issue_obj.get('endLine'), f'issues[{index}].endLine')


def validate_seed_document(seed: dict[str, Any]) -> None:
    schema_ref = seed.get('$schema')
    if schema_ref is not None and schema_ref != SEED_SCHEMA_PATH:
        raise LedgerError(
            f"Seed document has unexpected $schema '{schema_ref}'. Expected '{SEED_SCHEMA_PATH}'."
        )

    missing = [field for field in SEED_TOP_LEVEL_REQUIRED if field not in seed]
    if missing:
        raise LedgerError(
            f"Seed document is missing top-level fields: {', '.join(missing)}. "
            "Canonical issues-ledger seeds must contain both issues[] and advisories[]; ledger.py init materializes from advisories[] and does not expect local regrouping."
        )

    validate_seed_query(seed.get('query'))
    validate_seed_target(seed.get('target'))
    validate_seed_collection(seed.get('collection'))

    issues = require_list(seed.get('issues'), 'issues')
    advisories = require_list(seed.get('advisories'), 'advisories')

    collection = require_object(seed.get('collection'), 'collection')
    if collection.get('issueCount') != len(issues):
        raise LedgerError(
            f"Field 'collection.issueCount' ({collection.get('issueCount')}) does not match issues length ({len(issues)})."
        )
    if collection.get('advisoryCount') != len(advisories):
        raise LedgerError(
            f"Field 'collection.advisoryCount' ({collection.get('advisoryCount')}) does not match advisories length ({len(advisories)})."
        )

    for index, issue in enumerate(issues):
        validate_seed_issue(issue, index)


def cmd_init(args: Any) -> int:
    seed = load_json(Path(args.from_path))
    if not isinstance(seed, dict):
        raise LedgerError('Seed root must be an object.')

    validate_seed_document(seed)

    advisories = seed.get('advisories')
    if not isinstance(advisories, list):
        raise LedgerError("Seed document must contain an 'advisories' array.")

    normalized = sort_advisories([normalize_seed_advisory(item) for item in advisories])
    ledger = {
        '$schema': LEDGER_SCHEMA_PATH,
        'sessionId': args.session_id,
        'advisories': normalized,
    }
    write_json(Path(args.output), ledger)
    print_json(
        {
            'sessionId': args.session_id,
            'output': args.output,
            'advisoryCount': len(normalized),
        }
    )
    return 0
