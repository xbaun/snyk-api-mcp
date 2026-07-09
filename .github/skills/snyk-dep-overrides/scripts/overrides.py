#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_SCHEMA_REF = '../schemas/snyk-dep-overrides.schema.json'
ALLOWED_STATUS = {'active', 'draft', 'obsolete', 'removed'}
ALLOWED_REASON = {'security', 'compatibility', 'performance', 'other'}
REQUIRED_CASE_FIELDS = [
    'key',
    'status',
    'reason',
    'selector',
    'target',
    'package',
    'snykIds',
    'introducedBy',
    'evidenceTree',
    'watch',
    'obsoleteWhen',
]


class OverrideError(RuntimeError):
    pass


ROOT_SECTION_RE = re.compile(r"^([A-Za-z0-9_'-]+):(?:\s.*)?$")


def require_supported_materialization_manager(manager: str, command_name: str) -> None:
    if manager != 'pnpm':
        raise OverrideError(
            f"Command '{command_name}' currently supports only manager='pnpm', got '{manager}'."
        )


def infer_manager_from_materialization(path: Path) -> str | None:
    match = re.fullmatch(r'snyk-dep-overrides\.([A-Za-z0-9_-]+)\.json', path.name)
    if not match:
        return None
    return match.group(1)


def resolve_manager(path: Path, manager: str | None) -> str:
    inferred = infer_manager_from_materialization(path)
    if manager and inferred and manager != inferred:
        raise OverrideError(
            f"Provided manager '{manager}' does not match materialization path '{path.name}'."
        )

    resolved = manager or inferred
    if not resolved:
        raise OverrideError(
            "Unable to determine override manager. Provide '--manager' or use a materialization "
            "path like 'snyk-dep-overrides.<manager>.json'."
        )
    return resolved


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except FileNotFoundError as exc:
        raise OverrideError(f'File not found: {path}') from exc
    except json.JSONDecodeError as exc:
        raise OverrideError(f'Invalid JSON in {path}: {exc}') from exc


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')


def print_json(data: Any) -> None:
    json.dump(data, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write('\n')


def parse_json(raw: str, label: str) -> Any:
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise OverrideError(f"Invalid JSON for '{label}'.") from exc


def ensure_list_of_strings(value: Any, label: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise OverrideError(f"Field '{label}' must be a JSON array of non-empty strings.")
    if not allow_empty and not value:
        raise OverrideError(f"Field '{label}' must not be empty.")
    return value


def validate_case(case: Any) -> None:
    if not isinstance(case, dict):
        raise OverrideError('Override case must be an object.')

    missing = [field for field in REQUIRED_CASE_FIELDS if field not in case]
    if missing:
        raise OverrideError(f"Override case is missing fields: {', '.join(missing)}")

    if case['status'] not in ALLOWED_STATUS:
        raise OverrideError(f"Unsupported status '{case['status']}'.")
    if case['reason'] not in ALLOWED_REASON:
        raise OverrideError(f"Unsupported reason '{case['reason']}'.")

    for field in ['key', 'selector', 'target', 'package', 'introducedBy']:
        if not isinstance(case[field], str) or not case[field]:
            raise OverrideError(f"Field '{field}' must be a non-empty string.")

    ensure_list_of_strings(case['snykIds'], 'snykIds')
    ensure_list_of_strings(case['obsoleteWhen'], 'obsoleteWhen')

    evidence = case['evidenceTree']
    if not isinstance(evidence, list) or not evidence:
        raise OverrideError("Field 'evidenceTree' must be a non-empty array.")
    for index, node in enumerate(evidence):
        if not isinstance(node, dict):
            raise OverrideError(f'evidenceTree[{index}] must be an object.')
        for field in ['importer', 'directDependency', 'chain']:
            if field not in node:
                raise OverrideError(f"evidenceTree[{index}] missing field '{field}'.")
        if not isinstance(node['importer'], str) or not node['importer']:
            raise OverrideError(f"evidenceTree[{index}].importer must be a non-empty string.")
        if not isinstance(node['directDependency'], str) or not node['directDependency']:
            raise OverrideError(
                f"evidenceTree[{index}].directDependency must be a non-empty string."
            )
        ensure_list_of_strings(node['chain'], f'evidenceTree[{index}].chain')

    watch = case['watch']
    if not isinstance(watch, list):
        raise OverrideError("Field 'watch' must be an array.")
    for index, item in enumerate(watch):
        if not isinstance(item, dict):
            raise OverrideError(f'watch[{index}] must be an object.')
        for field in ['package', 'declaredIn', 'declaredVersion', 'relevance']:
            if not isinstance(item.get(field), str) or not item[field]:
                raise OverrideError(f"watch[{index}].{field} must be a non-empty string.")


def ensure_case(case: Any) -> dict[str, Any]:
    validate_case(case)

    normalized = deepcopy(case)
    timestamp = now_iso()
    normalized.setdefault('createdAt', timestamp)
    normalized['updatedAt'] = timestamp
    return normalized


def ensure_document_envelope(doc: Any, manager: str | None = None) -> dict[str, Any]:
    if not isinstance(doc, dict):
        raise OverrideError('Override document must be an object.')

    if 'schemaVersion' not in doc:
        doc['schemaVersion'] = 1
    if doc['schemaVersion'] != 1:
        raise OverrideError("Only schemaVersion=1 is supported.")

    if manager:
        doc['manager'] = manager
    if not isinstance(doc.get('manager'), str) or not doc['manager']:
        raise OverrideError("Override document requires a non-empty 'manager'.")

    if '$schema' not in doc:
        doc['$schema'] = DEFAULT_SCHEMA_REF

    cases = doc.get('cases', [])
    if not isinstance(cases, list):
        raise OverrideError("Field 'cases' must be an array.")

    return doc


def ensure_document(doc: Any, manager: str | None = None) -> dict[str, Any]:
    doc = ensure_document_envelope(doc, manager)

    validated_cases: list[dict[str, Any]] = []
    for index, case in enumerate(doc['cases']):
        try:
            validate_case(case)
        except OverrideError as exc:
            raise OverrideError(f'cases[{index}] invalid: {exc}') from exc
        validated_cases.append(deepcopy(case))

    doc['cases'] = sorted(validated_cases, key=lambda item: item['key'])
    doc['generatedAt'] = now_iso()
    return doc


def load_or_init_document(
    path: Path,
    manager: str | None,
    *,
    validate_cases: bool = True,
) -> dict[str, Any]:
    resolved_manager = resolve_manager(path, manager)
    if path.exists():
        doc = load_json(path)
    else:
        doc = {
            '$schema': DEFAULT_SCHEMA_REF,
            'schemaVersion': 1,
            'manager': resolved_manager,
            'cases': [],
        }
    if validate_cases:
        return ensure_document(doc, resolved_manager)
    return ensure_document_envelope(doc, resolved_manager)


def find_case(cases: list[dict[str, Any]], key: str) -> dict[str, Any] | None:
    return next((case for case in cases if case.get('key') == key), None)


def collect_active_cases(document: dict[str, Any]) -> list[dict[str, Any]]:
    active = [case for case in document['cases'] if case.get('status') == 'active']
    return sorted(active, key=lambda case: (str(case.get('selector', '')), str(case.get('target', '')), str(case.get('key', ''))))


def build_expected_pnpm_overrides(document: dict[str, Any]) -> dict[str, str]:
    overrides: dict[str, str] = {}
    for case in collect_active_cases(document):
        selector = str(case['selector'])
        target = str(case['target'])
        if selector in overrides and overrides[selector] != target:
            raise OverrideError(
                f"Conflicting active pnpm override targets for selector '{selector}': "
                f"'{overrides[selector]}' vs '{target}'."
            )
        overrides[selector] = target
    return dict(sorted(overrides.items()))


def load_text_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding='utf-8').splitlines()
    except FileNotFoundError as exc:
        raise OverrideError(f'File not found: {path}') from exc


def write_text_lines(path: Path, lines: list[str]) -> None:
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')


def root_section_ranges(lines: list[str]) -> list[tuple[str, int, int]]:
    starts: list[tuple[str, int]] = []
    for index, line in enumerate(lines):
        if line.startswith((' ', '\t')):
            continue
        match = ROOT_SECTION_RE.match(line)
        if match:
            starts.append((match.group(1), index))

    ranges: list[tuple[str, int, int]] = []
    for idx, (name, start) in enumerate(starts):
        end = starts[idx + 1][1] if idx + 1 < len(starts) else len(lines)
        ranges.append((name, start, end))
    return ranges


def strip_trailing_blank_lines(lines: list[str]) -> list[str]:
    result = list(lines)
    while result and result[-1] == '':
        result.pop()
    return result


def parse_yaml_scalar(raw: str) -> str:
    text = raw.strip()
    if not text:
        raise OverrideError('Empty YAML scalar in overrides block.')
    if text[0] in {'"', "'"}:
        if text[0] == '"':
            try:
                return str(json.loads(text))
            except json.JSONDecodeError as exc:
                raise OverrideError(f'Invalid quoted YAML scalar: {text}') from exc
        if len(text) < 2 or text[-1] != "'":
            raise OverrideError(f'Invalid single-quoted YAML scalar: {text}')
        return text[1:-1].replace("''", "'")
    return text


def render_yaml_scalar(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def parse_pnpm_overrides_section(section_lines: list[str]) -> dict[str, str]:
    if not section_lines:
        return {}
    header = section_lines[0].strip()
    if header != 'overrides:':
        raise OverrideError("Expected 'overrides:' section header.")

    parsed: dict[str, str] = {}
    for raw_line in section_lines[1:]:
        if not raw_line.strip():
            continue
        if raw_line.startswith('#'):
            continue
        if not raw_line.startswith('  '):
            raise OverrideError(
                'Unsupported pnpm overrides formatting; expected two-space indented selector entries.'
            )
        entry = raw_line[2:]
        if ':' not in entry:
            raise OverrideError(f"Invalid pnpm override entry: '{raw_line}'.")
        key_raw, value_raw = entry.split(':', 1)
        selector = parse_yaml_scalar(key_raw)
        target = parse_yaml_scalar(value_raw)
        parsed[selector] = target
    return dict(sorted(parsed.items()))


def render_pnpm_overrides_section(overrides: dict[str, str]) -> list[str]:
    if not overrides:
        return []
    lines = ['overrides:']
    for selector, target in sorted(overrides.items()):
        lines.append(f'  {render_yaml_scalar(selector)}: {render_yaml_scalar(target)}')
    return lines


def extract_root_section(lines: list[str], section_name: str) -> tuple[int, int, list[str]] | None:
    for name, start, end in root_section_ranges(lines):
        if name == section_name:
            return start, end, lines[start:end]
    return None


def replace_root_section(lines: list[str], section_name: str, replacement: list[str], *, insert_after: str | None = None) -> list[str]:
    current = list(lines)
    existing = extract_root_section(current, section_name)
    if existing is not None:
        start, end, _ = existing
        replacement_block = strip_trailing_blank_lines(replacement)
        if replacement_block:
            if end < len(current):
                replacement_block = replacement_block + ['']
            current = current[:start] + replacement_block + current[end:]
        else:
            current = current[:start] + current[end:]
        return strip_trailing_blank_lines(current)

    replacement_block = strip_trailing_blank_lines(replacement)
    if not replacement_block:
        return strip_trailing_blank_lines(current)

    insert_index = 0
    if insert_after:
        after_section = extract_root_section(current, insert_after)
        if after_section is not None:
            insert_index = after_section[1]

    block = list(replacement_block)
    if insert_index > 0 and current[insert_index - 1] != '':
        block = [''] + block
    if insert_index < len(current):
        block = block + ['']
    return strip_trailing_blank_lines(current[:insert_index] + block + current[insert_index:])


def load_workspace_overrides(workspace_path: Path) -> dict[str, str]:
    lines = load_text_lines(workspace_path)
    section = extract_root_section(lines, 'overrides')
    if section is None:
        return {}
    return parse_pnpm_overrides_section(section[2])


def write_workspace_overrides(workspace_path: Path, overrides: dict[str, str]) -> None:
    lines = load_text_lines(workspace_path)
    updated = replace_root_section(
        lines,
        'overrides',
        render_pnpm_overrides_section(overrides),
        insert_after='packages',
    )
    write_text_lines(workspace_path, updated)


def validate_pnpm_materialization(materialization_path: Path, workspace_path: Path, manager: str | None) -> dict[str, Any]:
    resolved_manager = resolve_manager(materialization_path, manager)
    require_supported_materialization_manager(resolved_manager, 'validate')
    document = ensure_document(load_json(materialization_path), resolved_manager)
    expected = build_expected_pnpm_overrides(document)
    actual = load_workspace_overrides(workspace_path)

    missing = [selector for selector, target in expected.items() if actual.get(selector) != target]
    unexpected = [selector for selector, target in actual.items() if expected.get(selector) != target]

    return {
        'manager': resolved_manager,
        'materialization': str(materialization_path),
        'workspace': str(workspace_path),
        'activeCaseCount': len(collect_active_cases(document)),
        'expectedOverrideCount': len(expected),
        'actualOverrideCount': len(actual),
        'missingOrMismatchedSelectors': missing,
        'unexpectedOrMismatchedSelectors': unexpected,
        'valid': not missing and not unexpected,
    }


def parse_json_array(raw: str, label: str, *, allow_empty: bool = False) -> list[Any]:
    value = parse_json(raw, label)
    if not isinstance(value, list):
        raise OverrideError(f"Field '{label}' must be a JSON array.")
    if not allow_empty and not value:
        raise OverrideError(f"Field '{label}' must not be empty.")
    return value


def build_case_from_args(args: argparse.Namespace) -> dict[str, Any]:
    return {
        'key': args.key,
        'status': args.status,
        'reason': args.reason,
        'selector': args.selector,
        'target': args.target,
        'package': args.package,
        **({'scope': args.scope} if args.scope else {}),
        **(
            {'contextSummary': args.context_summary}
            if args.context_summary
            else {}
        ),
        'snykIds': parse_json_array(args.snyk_ids, 'snyk-ids'),
        'introducedBy': args.introduced_by,
        'evidenceTree': parse_json_array(args.evidence_tree, 'evidence-tree'),
        'watch': parse_json_array(args.watch, 'watch', allow_empty=True),
        'obsoleteWhen': parse_json_array(args.obsolete_when, 'obsolete-when'),
    }


def cmd_upsert(args: argparse.Namespace) -> int:
    path = Path(args.materialization)
    document = load_or_init_document(path, args.manager, validate_cases=False)
    normalized = ensure_case(build_case_from_args(args))

    existing = find_case(document['cases'], normalized['key'])
    if existing is None:
        document['cases'].append(normalized)
    else:
        created_at = existing.get('createdAt')
        existing.clear()
        existing.update(normalized)
        if created_at:
            existing['createdAt'] = created_at

    document = ensure_document(document, args.manager or document['manager'])
    write_json(path, document)
    print_json(
        {
            'materialization': args.materialization,
            'key': normalized['key'],
            'count': len(document['cases']),
        }
    )
    return 0


def cmd_read(args: argparse.Namespace) -> int:
    path = Path(args.materialization)
    document = ensure_document(load_json(path), resolve_manager(path, args.manager))
    case = find_case(document['cases'], args.key)
    if case is None:
        raise OverrideError(f"No override case found for key '{args.key}'.")
    print_json(case)
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    path = Path(args.materialization)
    document = ensure_document(load_json(path), resolve_manager(path, args.manager))
    cases = document['cases']
    if args.status:
        cases = [case for case in cases if case.get('status') == args.status]
    print_json(cases)
    return 0


def cmd_remove(args: argparse.Namespace) -> int:
    path = Path(args.materialization)
    document = ensure_document(load_json(path), resolve_manager(path, args.manager))
    case = find_case(document['cases'], args.key)
    if case is None:
        raise OverrideError(f"No override case found for key '{args.key}'.")

    document['cases'] = [item for item in document['cases'] if item.get('key') != args.key]
    document = ensure_document(document, document['manager'])
    write_json(path, document)
    print_json({'materialization': args.materialization, 'key': args.key, 'removed': True})
    return 0


def cmd_materialize(args: argparse.Namespace) -> int:
    materialization_path = Path(args.materialization)
    workspace_path = Path(args.workspace)
    document = load_or_init_document(materialization_path, args.manager)
    require_supported_materialization_manager(document['manager'], 'materialize')
    overrides = build_expected_pnpm_overrides(document)
    write_workspace_overrides(workspace_path, overrides)
    result = validate_pnpm_materialization(materialization_path, workspace_path, document['manager'])
    if not result['valid']:
        raise OverrideError('pnpm override materialization was written but failed validation.')
    print_json(
        {
            'materialization': args.materialization,
            'workspace': args.workspace,
            'manager': document['manager'],
            'overrideCount': len(overrides),
            'selectors': list(overrides.keys()),
            'valid': True,
        }
    )
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    result = validate_pnpm_materialization(
        Path(args.materialization),
        Path(args.workspace),
        args.manager,
    )
    print_json(result)
    return 0 if result['valid'] else 1


def _case_matches_package(case: dict[str, Any], package: str) -> bool:
    return str(case.get('package', '')).lower() == package.lower()


def _case_matches_snyk_id(case: dict[str, Any], snyk_id: str) -> bool:
    return snyk_id in [str(sid) for sid in case.get('snykIds', [])]


def _selector_package(selector: str) -> str:
    if not selector:
        return ''

    if selector.startswith('@'):
        slash_index = selector.find('/')
        at_index = selector.rfind('@')
        if slash_index != -1 and at_index > slash_index:
            return selector[:at_index]
        return selector

    at_index = selector.rfind('@')
    if at_index > 0:
        return selector[:at_index]
    return selector


def _selector_conflict_type(case_selector: str, check_selector: str) -> str | None:
    if case_selector == check_selector:
        return 'exact-selector'

    case_package = _selector_package(case_selector).lower()
    check_package = _selector_package(check_selector).lower()
    if case_package and case_package == check_package:
        return 'same-package'

    return None


def _summarize_selector_conflict(case: dict[str, Any], check_selector: str) -> dict[str, Any] | None:
    case_selector = str(case.get('selector', ''))
    conflict_type = _selector_conflict_type(case_selector, check_selector)
    if conflict_type is None:
        return None

    return {
        'key': case['key'],
        'selector': case_selector,
        'target': case['target'],
        'status': case['status'],
        'conflictType': conflict_type,
    }


def cmd_analyze(args: argparse.Namespace) -> int:
    path = Path(args.materialization)
    document = ensure_document(load_json(path), resolve_manager(path, args.manager))
    cases = document['cases']

    if args.package:
        cases = [c for c in cases if _case_matches_package(c, args.package)]
    if args.snyk_id:
        cases = [c for c in cases if _case_matches_snyk_id(c, args.snyk_id)]
    selector_matches = cases
    if args.check_selector:
        selector_matches = [
            c
            for c in selector_matches
            if _selector_conflict_type(str(c.get('selector', '')), args.check_selector) is not None
        ]
        cases = selector_matches
    if args.status:
        cases = [c for c in cases if c.get('status') == args.status]

    conflicts: list[dict[str, Any]] = []
    if args.check_selector:
        conflicts = [
            conflict
            for c in selector_matches
            if c['status'] in ('active', 'draft')
            for conflict in [_summarize_selector_conflict(c, args.check_selector)]
            if conflict is not None
        ]

    query: dict[str, Any] = {'materialization': args.materialization}
    if args.manager:
        query['manager'] = args.manager
    if args.package:
        query['package'] = args.package
    if args.snyk_id:
        query['snykId'] = args.snyk_id
    if args.status:
        query['status'] = args.status
    if args.check_selector:
        query['checkSelector'] = args.check_selector

    status_counts: dict[str, int] = {}
    for c in cases:
        s = str(c.get('status', 'unknown'))
        status_counts[s] = status_counts.get(s, 0) + 1

    print_json(
        {
            'query': query,
            'matches': cases,
            'summary': {
                'totalMatches': len(cases),
                'statusCounts': status_counts,
                'totalCases': len(document['cases']),
                'conflictingSelectors': conflicts,
            },
        }
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='Deterministic helper for override materializations.')
    subparsers = parser.add_subparsers(dest='command', required=True)

    upsert_parser = subparsers.add_parser('upsert', help='Create or update one override case.')
    upsert_parser.add_argument('--materialization', required=True)
    upsert_parser.add_argument('--manager')
    upsert_parser.add_argument('--key', required=True)
    upsert_parser.add_argument('--status', required=True, choices=sorted(ALLOWED_STATUS))
    upsert_parser.add_argument('--reason', required=True, choices=sorted(ALLOWED_REASON))
    upsert_parser.add_argument('--selector', required=True)
    upsert_parser.add_argument('--target', required=True)
    upsert_parser.add_argument('--package', required=True)
    upsert_parser.add_argument('--scope')
    upsert_parser.add_argument('--context-summary')
    upsert_parser.add_argument('--snyk-ids', required=True)
    upsert_parser.add_argument('--introduced-by', required=True)
    upsert_parser.add_argument('--evidence-tree', required=True)
    upsert_parser.add_argument('--watch', required=True)
    upsert_parser.add_argument('--obsolete-when', required=True)
    upsert_parser.set_defaults(func=cmd_upsert)

    read_parser = subparsers.add_parser('read', help='Read a single override case by key.')
    read_parser.add_argument('--materialization', required=True)
    read_parser.add_argument('--manager')
    read_parser.add_argument('--key', required=True)
    read_parser.set_defaults(func=cmd_read)

    list_parser = subparsers.add_parser('list', help='List override cases with optional filters.')
    list_parser.add_argument('--materialization', required=True)
    list_parser.add_argument('--manager')
    list_parser.add_argument('--status', choices=sorted(ALLOWED_STATUS))
    list_parser.set_defaults(func=cmd_list)

    remove_parser = subparsers.add_parser('remove', help='Remove or tombstone an override case.')
    remove_parser.add_argument('--materialization', required=True)
    remove_parser.add_argument('--manager')
    remove_parser.add_argument('--key', required=True)
    remove_parser.set_defaults(func=cmd_remove)

    materialize_parser = subparsers.add_parser(
        'materialize',
        help='Materialize active override cases into the manager configuration.',
    )
    materialize_parser.add_argument('--materialization', required=True)
    materialize_parser.add_argument('--workspace', required=True)
    materialize_parser.add_argument('--manager')
    materialize_parser.set_defaults(func=cmd_materialize)

    validate_parser = subparsers.add_parser(
        'validate',
        help='Validate override JSON against the real manager configuration.',
    )
    validate_parser.add_argument('--materialization', required=True)
    validate_parser.add_argument('--workspace', required=True)
    validate_parser.add_argument('--manager')
    validate_parser.set_defaults(func=cmd_validate)

    analyze_parser = subparsers.add_parser(
        'analyze',
        help='Analyze overrides for resolver pre-flight queries: package, Snyk ID, selector conflicts.',
    )
    analyze_parser.add_argument('--materialization', required=True)
    analyze_parser.add_argument('--manager')
    analyze_parser.add_argument('--package', help='Filter cases by package name (case-insensitive).')
    analyze_parser.add_argument('--snyk-id', help='Find cases covering a specific Snyk ID.')
    analyze_parser.add_argument('--check-selector', help='Check for active/draft selector conflicts.')
    analyze_parser.add_argument('--status', choices=sorted(ALLOWED_STATUS), help='Filter by case status.')
    analyze_parser.set_defaults(func=cmd_analyze)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except OverrideError as exc:
        print(f'overrides.py error: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
