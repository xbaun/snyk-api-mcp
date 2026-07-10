from __future__ import annotations

from pathlib import Path
from typing import Any

from .common import (
    ISSUE_TYPE_ORDERED,
    SEVERITY_ORDERED,
    advisory_package,
    compact_dict,
    grouped_counts,
    load_ledger,
    print_json,
    sort_advisories,
    status_counts,
)


def advisory_brief(advisory: dict[str, Any]) -> dict[str, Any]:
    return compact_dict(
        {
            'advisoryKey': advisory.get('advisoryKey'),
            'title': advisory.get('title'),
            'issueType': advisory.get('issueType'),
            'severity': advisory.get('severity'),
            'status': advisory.get('status'),
            'package': advisory_package(advisory),
            'affectedProjectCount': advisory.get('affectedProjectCount'),
            'issueCount': advisory.get('issueCount'),
            'createdAt': advisory.get('createdAt'),
            'startedAt': advisory.get('startedAt'),
            'lastAttemptAt': advisory.get('lastAttemptAt'),
            'completedAt': advisory.get('completedAt'),
        }
    )


def outcome_summary(advisory: dict[str, Any]) -> str | None:
    outcome = advisory.get('outcome')
    if isinstance(outcome, dict):
        summary = outcome.get('summary')
        if isinstance(summary, str) and summary:
            return summary
    return None


def unique_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def blocked_reasons(advisory: dict[str, Any]) -> list[str]:
    outcome = advisory.get('outcome') if isinstance(advisory.get('outcome'), dict) else {}
    blockers = outcome.get('blockers') if isinstance(outcome, dict) else None
    reasons: list[str] = []

    if isinstance(blockers, list):
        reasons.extend(str(item) for item in blockers if isinstance(item, str) and item)

    last_failure_message = advisory.get('lastFailureMessage')
    if isinstance(last_failure_message, str) and last_failure_message:
        reasons.append(last_failure_message)

    rationale = outcome.get('rationale') if isinstance(outcome, dict) else None
    if isinstance(rationale, str) and rationale:
        reasons.append(rationale)

    summary = outcome_summary(advisory)
    if summary and not reasons:
        reasons.append(summary)

    return unique_strings(reasons)


def resolved_detail(advisory: dict[str, Any]) -> dict[str, Any]:
    implementation = advisory.get('implementation') if isinstance(advisory.get('implementation'), dict) else {}
    return compact_dict(
        {
            **advisory_brief(advisory),
            'summary': outcome_summary(advisory),
            'strategy': advisory.get('strategy'),
            'targetVersion': advisory.get('targetVersion'),
            'dependencyUpdates': implementation.get('dependencyUpdates') if isinstance(implementation, dict) else None,
            'parentUpdates': implementation.get('parentUpdates') if isinstance(implementation, dict) else None,
            'overridesApplied': implementation.get('overridesApplied') if isinstance(implementation, dict) else None,
            'overridePreflight': implementation.get('overridePreflight') if isinstance(implementation, dict) else None,
            'verification': advisory.get('verification'),
        }
    )


def blocked_detail(advisory: dict[str, Any]) -> dict[str, Any]:
    outcome = advisory.get('outcome') if isinstance(advisory.get('outcome'), dict) else {}
    return compact_dict(
        {
            **advisory_brief(advisory),
            'summary': outcome_summary(advisory),
            'blockedReasons': blocked_reasons(advisory),
            'blockers': outcome.get('blockers') if isinstance(outcome, dict) else None,
            'remediationProposal': outcome.get('remediationProposal') if isinstance(outcome, dict) else None,
            'rationale': outcome.get('rationale') if isinstance(outcome, dict) else None,
            'lastFailureKind': advisory.get('lastFailureKind'),
            'lastFailureAt': advisory.get('lastFailureAt'),
            'lastFailureMessage': advisory.get('lastFailureMessage'),
        }
    )


def partial_detail(advisory: dict[str, Any]) -> dict[str, Any]:
    outcome = advisory.get('outcome') if isinstance(advisory.get('outcome'), dict) else {}
    implementation = advisory.get('implementation') if isinstance(advisory.get('implementation'), dict) else {}
    return compact_dict(
        {
            **advisory_brief(advisory),
            'summary': outcome_summary(advisory),
            'blockedReasons': blocked_reasons(advisory),
            'strategy': advisory.get('strategy'),
            'targetVersion': advisory.get('targetVersion'),
            'dependencyUpdates': implementation.get('dependencyUpdates') if isinstance(implementation, dict) else None,
            'parentUpdates': implementation.get('parentUpdates') if isinstance(implementation, dict) else None,
            'overridesApplied': implementation.get('overridesApplied') if isinstance(implementation, dict) else None,
            'overridePreflight': implementation.get('overridePreflight') if isinstance(implementation, dict) else None,
            'verification': advisory.get('verification'),
            'remediationProposal': outcome.get('remediationProposal') if isinstance(outcome, dict) else None,
            'rationale': outcome.get('rationale') if isinstance(outcome, dict) else None,
        }
    )


def active_detail(advisory: dict[str, Any]) -> dict[str, Any]:
    return compact_dict(
        {
            **advisory_brief(advisory),
            'summary': outcome_summary(advisory),
            'lastFailureKind': advisory.get('lastFailureKind'),
            'lastFailureMessage': advisory.get('lastFailureMessage'),
        }
    )


def analyze_ledger(ledger: dict[str, Any]) -> dict[str, Any]:
    advisories = sort_advisories(ledger['advisories'])
    counts = status_counts(advisories)
    total = len(advisories)
    terminal = counts['resolved'] + counts['blocked'] + counts['partially-resolved']
    remaining = total - terminal
    completion = round((terminal / total) * 100, 2) if total else 100.0

    return {
        'sessionId': ledger.get('sessionId'),
        'summary': {
            'advisoryCount': total,
            'statusCounts': counts,
            'severityCounts': grouped_counts(advisories, 'severity', SEVERITY_ORDERED),
            'issueTypeCounts': grouped_counts(advisories, 'issueType', ISSUE_TYPE_ORDERED),
            'resolvedCount': counts['resolved'],
            'blockedCount': counts['blocked'],
            'partiallyResolvedCount': counts['partially-resolved'],
            'remainingCount': remaining,
            'completionPercent': completion,
        },
        'details': {
            'resolved': [resolved_detail(advisory) for advisory in advisories if advisory.get('status') == 'resolved'],
            'blocked': [blocked_detail(advisory) for advisory in advisories if advisory.get('status') == 'blocked'],
            'partiallyResolved': [partial_detail(advisory) for advisory in advisories if advisory.get('status') == 'partially-resolved'],
            'inProgress': [active_detail(advisory) for advisory in advisories if advisory.get('status') == 'in-progress'],
            'notStarted': [active_detail(advisory) for advisory in advisories if advisory.get('status') == 'not-started'],
        },
    }


def render_text_report(report: dict[str, Any]) -> str:
    summary = report['summary']
    details = report['details']
    lines = [
        f"session: {report.get('sessionId', '<unknown>')}",
        f"advisories: {summary['advisoryCount']} | completion: {summary['completionPercent']}% | remaining: {summary['remainingCount']}",
        'status counts: ' + ', '.join(f"{key}={value}" for key, value in summary['statusCounts'].items()),
        'severity counts: ' + ', '.join(f"{key}={value}" for key, value in summary['severityCounts'].items()),
        'issue type counts: ' + ', '.join(f"{key}={value}" for key, value in summary['issueTypeCounts'].items()),
        '',
        f"resolved ({len(details['resolved'])}):",
    ]

    for advisory in details['resolved']:
        lines.append(
            f"- {advisory['advisoryKey']} | {advisory['issueType']} | {advisory['severity']} | {advisory['title']}"
        )
        if advisory.get('summary'):
            lines.append(f"  summary: {advisory['summary']}")
        if advisory.get('completedAt'):
            lines.append(f"  completedAt: {advisory['completedAt']}")

    lines.extend(['', f"blocked ({len(details['blocked'])}):"])
    for advisory in details['blocked']:
        lines.append(
            f"- {advisory['advisoryKey']} | {advisory['issueType']} | {advisory['severity']} | {advisory['title']}"
        )
        reasons = advisory.get('blockedReasons', [])
        if reasons:
            lines.append('  why blocked:')
            lines.extend(f'    - {reason}' for reason in reasons)
        if advisory.get('remediationProposal'):
            lines.append(f"  remediation: {advisory['remediationProposal']}")
        if advisory.get('lastFailureKind'):
            suffix = f": {advisory['lastFailureMessage']}" if advisory.get('lastFailureMessage') else ''
            lines.append(f"  last failure: {advisory['lastFailureKind']}{suffix}")

    lines.extend(['', f"partially-resolved ({len(details['partiallyResolved'])}):"])
    for advisory in details['partiallyResolved']:
        lines.append(
            f"- {advisory['advisoryKey']} | {advisory['issueType']} | {advisory['severity']} | {advisory['title']}"
        )
        if advisory.get('summary'):
            lines.append(f"  summary: {advisory['summary']}")
        reasons = advisory.get('blockedReasons', [])
        if reasons:
            lines.append('  remaining blockers:')
            lines.extend(f'    - {reason}' for reason in reasons)

    lines.extend(['', f"in-progress ({len(details['inProgress'])}):"])
    for advisory in details['inProgress']:
        lines.append(
            f"- {advisory['advisoryKey']} | {advisory['issueType']} | {advisory['severity']} | {advisory['title']}"
        )

    lines.extend(['', f"not-started ({len(details['notStarted'])}):"])
    for advisory in details['notStarted']:
        lines.append(
            f"- {advisory['advisoryKey']} | {advisory['issueType']} | {advisory['severity']} | {advisory['title']}"
        )

    return '\n'.join(lines)


def cmd_analyze(args: Any) -> int:
    ledger = load_ledger(Path(args.ledger))
    report = analyze_ledger(ledger)
    if args.format == 'json':
        print_json(report)
        return 0

    print(render_text_report(report))
    return 0
