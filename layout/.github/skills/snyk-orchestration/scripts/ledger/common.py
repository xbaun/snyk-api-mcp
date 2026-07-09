from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LEDGER_SCHEMA_PATH = '../../.github/skills/snyk-orchestration/schemas/issues-ledger.schema.json'
SEED_SCHEMA_PATH = '../../.github/skills/snyk-session-init/schemas/issues-ledger-seed.schema.json'
SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
ISSUE_TYPE_ORDER = {'package_vulnerability': 0, 'code': 1}
STATUS_ORDER = ('not-started', 'in-progress', 'resolved', 'blocked', 'partially-resolved')
ALLOWED_STATUS = set(STATUS_ORDER)
ALLOWED_FAILURE_KIND = {
    'handback-parse',
    'handback-format',
    'override-validation',
    'code-health-validation',
    'resolver-error',
    'dirty-stop',
    'other',
}
ALLOWED_SEVERITY = set(SEVERITY_ORDER)
ALLOWED_ISSUE_TYPE = set(ISSUE_TYPE_ORDER)
SEED_TOP_LEVEL_REQUIRED = ['query', 'target', 'collection', 'issues', 'advisories']
ISSUE_TYPE_ORDERED = tuple(sorted(ISSUE_TYPE_ORDER, key=ISSUE_TYPE_ORDER.get))
SEVERITY_ORDERED = tuple(sorted(SEVERITY_ORDER, key=SEVERITY_ORDER.get))


class LedgerError(RuntimeError):
    pass


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except FileNotFoundError as exc:
        raise LedgerError(f'File not found: {path}') from exc
    except json.JSONDecodeError as exc:
        raise LedgerError(f'Invalid JSON in {path}: {exc}') from exc


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')


def print_json(data: Any) -> None:
    json.dump(data, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write('\n')


def severity_rank(value: str) -> int:
    return SEVERITY_ORDER.get(value, 99)


def issue_type_rank(value: str) -> int:
    return ISSUE_TYPE_ORDER.get(value, 99)


def advisory_sort_key(advisory: dict[str, Any]) -> tuple[Any, ...]:
    return (
        issue_type_rank(str(advisory.get('issueType', ''))),
        severity_rank(str(advisory.get('severity', ''))),
        -float(advisory.get('riskScoreMax', 0)),
        -int(advisory.get('affectedProjectCount', 0)),
        -int(advisory.get('issueCount', 0)),
        str(advisory.get('createdAt', '')),
        str(advisory.get('advisoryKey', '')),
    )


def sort_advisories(advisories: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(advisories, key=advisory_sort_key)


def status_counts(advisories: list[dict[str, Any]]) -> dict[str, int]:
    counts = {status: 0 for status in STATUS_ORDER}
    for advisory in advisories:
        status = advisory.get('status')
        if status in counts:
            counts[str(status)] += 1
    return counts


def grouped_counts(advisories: list[dict[str, Any]], field_name: str, values: tuple[str, ...]) -> dict[str, int]:
    counts = {value: 0 for value in values}
    for advisory in advisories:
        value = advisory.get(field_name)
        if value in counts:
            counts[str(value)] += 1
    return counts


def git_status_lines(repo_root: Path) -> list[str]:
    try:
        result = subprocess.run(
            ['git', '-C', str(repo_root), 'status', '--porcelain'],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise LedgerError('git executable not found; cannot perform dirty-check.') from exc

    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip() or f'exit code {result.returncode}'
        raise LedgerError(f'git status failed for {repo_root}: {detail}')

    return [line.rstrip() for line in result.stdout.splitlines() if line.strip()]


def select_advisory(ledger: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    in_progress = sort_advisories(
        [advisory for advisory in ledger['advisories'] if advisory.get('status') == 'in-progress']
    )
    if len(in_progress) > 1:
        keys = ', '.join(str(advisory.get('advisoryKey')) for advisory in in_progress)
        raise LedgerError(f'Multiple in-progress advisories found: {keys}')
    if in_progress:
        return ('resume', in_progress[0])

    next_advisory = next(
        (
            advisory
            for advisory in sort_advisories(ledger['advisories'])
            if advisory.get('status') == 'not-started'
        ),
        None,
    )
    if next_advisory is None:
        return ('done', None)
    return ('start', next_advisory)


def load_ledger(path: Path) -> dict[str, Any]:
    data = load_json(path)
    if not isinstance(data, dict):
        raise LedgerError(f'Ledger root must be an object: {path}')
    advisories = data.get('advisories')
    if not isinstance(advisories, list):
        raise LedgerError(f"Ledger 'advisories' must be an array: {path}")
    return data


def find_advisory(ledger: dict[str, Any], key: str) -> dict[str, Any]:
    for advisory in ledger['advisories']:
        if advisory.get('advisoryKey') == key:
            return advisory
    raise LedgerError(f"No advisory found for advisoryKey '{key}'.")


def require_object(value: Any, field_name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise LedgerError(f"Field '{field_name}' must be an object.")
    return value


def require_list(value: Any, field_name: str) -> list[Any]:
    if not isinstance(value, list):
        raise LedgerError(f"Field '{field_name}' must be an array.")
    return value


def require_non_empty_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LedgerError(f"Field '{field_name}' must be a non-empty string.")
    return value


def require_non_negative_int(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or value < 0:
        raise LedgerError(f"Field '{field_name}' must be an integer >= 0.")
    return value


def require_positive_int(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or value < 1:
        raise LedgerError(f"Field '{field_name}' must be an integer >= 1.")
    return value


def require_number(value: Any, field_name: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise LedgerError(f"Field '{field_name}' must be numeric.")
    return float(value)


def parse_json_array(raw: str | None, field_name: str) -> list[Any]:
    if raw is None:
        return []
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise LedgerError(f"Field '{field_name}' must be valid JSON.") from exc
    if not isinstance(value, list):
        raise LedgerError(f"Field '{field_name}' must be a JSON array.")
    return value


def advisory_package(advisory: dict[str, Any]) -> str | None:
    value = advisory.get('vulnerablePackage') or advisory.get('packageName')
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if not normalized or normalized.lower() == 'unknown':
        return None
    return normalized


def compact_dict(data: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in data.items() if value not in (None, [], {})}
