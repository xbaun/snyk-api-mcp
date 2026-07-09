from __future__ import annotations

import argparse
import sys
from textwrap import dedent

from .common import LedgerError
from .advisory import (
    cmd_cascade_check,
    cmd_next,
    cmd_record_failure,
    cmd_select,
    cmd_set_status,
    cmd_update,
)
from .analysis import cmd_analyze
from .seed import cmd_init


class HelpFormatter(argparse.RawTextHelpFormatter, argparse.ArgumentDefaultsHelpFormatter):
    pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='ledger.py',
        description=dedent(
            """
            Deterministic helper for `.synk/{sessionId}/issues-ledger.json`.

            This script is the canonical interface for ledger control-flow and ledger writes.
            Use it instead of manually editing or line-scanning `issues-ledger.json`.

            Typical lifecycle:
              1. `init`           materialize a new ledger from `issues-ledger-seed.json`
              2. `select`         decide Gate [O1]: resume | dirty-stop | start | done
              3. `analyze`        summarize progress, statuses, and blocked reasons
              4. `set-status`     persist `in-progress` before resolver dispatch
              5. `update`         persist a validated resolver handback
              6. `record-failure` persist resume/failure relevant metadata
              7. `cascade-check`  inspect/apply package vulnerability cascades

            Important: `next` is a read-only inspection helper. Orchestrators should prefer
            `select`, because only `select` understands resume + dirty-stop semantics.
            """
        ),
        epilog=dedent(
            """
            Quick start:
              python3 .github/skills/snyk-orchestration/scripts/ledger.py --help
              python3 .github/skills/snyk-orchestration/scripts/ledger.py select --help
              python3 .github/skills/snyk-orchestration/scripts/ledger.py analyze --help
              python3 .github/skills/snyk-orchestration/scripts/ledger.py update --help

            Most common commands in practice:
              init     Create `.synk/{sessionId}/issues-ledger.json` from a canonical seed.
              select   Primary Gate [O1] entrypoint for orchestration loops.
              analyze  Read-only status/progress report for the current ledger.
              update   Primary write path for validated resolver results.
            """
        ),
        formatter_class=HelpFormatter,
    )
    subparsers = parser.add_subparsers(dest='command', required=True, title='commands', metavar='COMMAND')

    init_parser = subparsers.add_parser(
        'init',
        usage='ledger.py init --from PATH --output PATH --session-id SESSION_ID',
        help='Materialize issues-ledger.json from a canonical issues-ledger-seed.json.',
        description=dedent(
            """
            Create a new session ledger from the canonical `issues-ledger-seed.json` document.

            `init` validates the seed contract, materializes advisories from `advisories[]`,
            and initializes runtime fields like `status`.

            Use this during `snyk-session-init`. Do not use it to regroup local issue data.
            """
        ),
        epilog=dedent(
            """
            Example:
              python3 .github/skills/snyk-orchestration/scripts/ledger.py init \
                --from .synk/2026-07-09T120000Z/issues-ledger-seed.json \
                --output .synk/2026-07-09T120000Z/issues-ledger.json \
                --session-id 2026-07-09T120000Z
            """
        ),
        formatter_class=HelpFormatter,
    )
    init_parser.add_argument(
        '--from',
        dest='from_path',
        required=True,
        metavar='PATH',
        help='Path to the canonical `issues-ledger-seed.json` input document.',
    )
    init_parser.add_argument(
        '--output',
        required=True,
        metavar='PATH',
        help='Path where the materialized `issues-ledger.json` should be written.',
    )
    init_parser.add_argument(
        '--session-id',
        required=True,
        metavar='SESSION_ID',
        help='Session identifier to persist into the ledger root.',
    )
    init_parser.set_defaults(func=cmd_init)

    next_parser = subparsers.add_parser(
        'next',
        usage='ledger.py next --from PATH [--format text|json]',
        help='Read-only helper: return the next not-started advisory only.',
        description=dedent(
            """
            Return the next advisory with `status == not-started` using the deterministic sort order.

            This command is useful for debugging or quick inspection. It does not perform
            resume detection and does not know about repo dirtiness.

            For real orchestration loops, prefer `select`.
            """
        ),
        epilog=dedent(
            """
            Examples:
              python3 .github/skills/snyk-orchestration/scripts/ledger.py next \
                --from .synk/{sessionId}/issues-ledger.json

              python3 .github/skills/snyk-orchestration/scripts/ledger.py next \
                --from .synk/{sessionId}/issues-ledger.json \
                --format json
            """
        ),
        formatter_class=HelpFormatter,
    )
    next_parser.add_argument(
        '--from',
        dest='from_path',
        required=True,
        metavar='PATH',
        help='Path to the existing `issues-ledger.json` file to inspect.',
    )
    next_parser.add_argument(
        '--format',
        choices=['text', 'json'],
        default='text',
        help='Output format for the selected advisory.',
    )
    next_parser.set_defaults(func=cmd_next)

    select_parser = subparsers.add_parser(
        'select',
        usage='ledger.py select --ledger PATH [--repo-root PATH] [--format text|json]',
        help='Primary Gate [O1] helper: decide resume, dirty-stop, start, or done.',
        description=dedent(
            """
            Evaluate Gate [O1] deterministically.

            `select` reads the ledger, checks whether exactly one advisory is already
            `in-progress`, optionally performs a `git status --porcelain` dirty-check,
            and otherwise selects the next `not-started` advisory by the normative sort order.

            Returned `decision` values:
              resume      clean repo + exactly one in-progress advisory
              dirty-stop  dirty repo + exactly one in-progress advisory
              start       no in-progress advisory, next not-started advisory selected
              done        no resumable advisory and no not-started advisory remain
            """
        ),
        epilog=dedent(
            """
            Examples:
              python3 .github/skills/snyk-orchestration/scripts/ledger.py select \
                --ledger .synk/{sessionId}/issues-ledger.json \
                --repo-root . \
                --format json

              python3 .github/skills/snyk-orchestration/scripts/ledger.py select \
                --ledger .synk/{sessionId}/issues-ledger.json
            """
        ),
        formatter_class=HelpFormatter,
    )
    select_parser.add_argument(
        '--ledger',
        required=True,
        metavar='PATH',
        help='Path to the session `issues-ledger.json` that drives orchestration state.',
    )
    select_parser.add_argument(
        '--repo-root',
        metavar='PATH',
        help='Optional repository root used for `git status --porcelain` dirty-checks.',
    )
    select_parser.add_argument(
        '--format',
        choices=['text', 'json'],
        default='json',
        help='Output format. `json` is recommended for agents.',
    )
    select_parser.set_defaults(func=cmd_select)

    analyze_parser = subparsers.add_parser(
        'analyze',
        usage='ledger.py analyze --ledger PATH [--format text|json]',
        help='Read-only overview of findings, progress, resolved items, and blocked reasons.',
        description=dedent(
            """
            Summarize the current `issues-ledger.json` in a read-only report.

            `analyze` returns:
              - top-level counts by status, severity, and issue type
              - completion progress for the session
              - detailed resolved advisories
              - detailed blocked advisories, especially why they are blocked
              - partially-resolved, in-progress, and not-started overviews

            Use this for operator visibility, status reporting, and resume triage.
            """
        ),
        epilog=dedent(
            """
            Examples:
              python3 .github/skills/snyk-orchestration/scripts/ledger.py analyze \
                --ledger .synk/{sessionId}/issues-ledger.json

              python3 .github/skills/snyk-orchestration/scripts/ledger.py analyze \
                --ledger .synk/{sessionId}/issues-ledger.json \
                --format text
            """
        ),
        formatter_class=HelpFormatter,
    )
    analyze_parser.add_argument(
        '--ledger',
        required=True,
        metavar='PATH',
        help='Path to the session `issues-ledger.json` to analyze.',
    )
    analyze_parser.add_argument(
        '--format',
        choices=['text', 'json'],
        default='json',
        help='Output format. `json` is recommended for agents, `text` for human scanning.',
    )
    analyze_parser.set_defaults(func=cmd_analyze)

    cascade_parser = subparsers.add_parser(
        'cascade-check',
        usage='ledger.py cascade-check --ledger PATH --resolved-key KEY --package PACKAGE [--apply] [--dry-run]',
        help='List or apply cascade candidates for a resolved package vulnerability.',
        description=dedent(
            """
            Find other `not-started` advisories that may have been fixed by the same package
            remediation as an already resolved advisory.

            Without `--apply`, this command is read-only and reports candidate advisories.
            With `--apply`, it marks matching candidates as `resolved` and stamps
            `completedAt` plus a minimal cascade outcome.

            Use this only for `package_vulnerability` advisories after real dependency evidence
            confirms that the vulnerable package/version disappeared.

            Package identity rules:
                - pass the canonical package identity for the resolved advisory
                - prefer `vulnerablePackage` once a resolver established it
                - otherwise use the seed-derived `packageName`
                - do not invent alternative package names for cascade matching
            """
        ),
        epilog=dedent(
            """
            Examples:
              python3 .github/skills/snyk-orchestration/scripts/ledger.py cascade-check \
                --ledger .synk/{sessionId}/issues-ledger.json \
                --resolved-key SNYK-JS-FOO-123 \
                --package foo \
                --dry-run

              python3 .github/skills/snyk-orchestration/scripts/ledger.py cascade-check \
                --ledger .synk/{sessionId}/issues-ledger.json \
                --resolved-key SNYK-JS-FOO-123 \
                --package foo \
                --apply
            """
        ),
        formatter_class=HelpFormatter,
    )
    cascade_parser.add_argument(
        '--ledger',
        required=True,
        metavar='PATH',
        help='Path to the session `issues-ledger.json` to inspect or update.',
    )
    cascade_parser.add_argument(
        '--resolved-key',
        required=True,
        metavar='KEY',
        help='Advisory key of the already resolved advisory that triggered the cascade check.',
    )
    cascade_parser.add_argument(
        '--package',
        required=True,
        metavar='PACKAGE',
        help='Canonical package identity for cascade matching: prefer `vulnerablePackage`, otherwise seed `packageName`.',
    )
    cascade_mode = cascade_parser.add_mutually_exclusive_group()
    cascade_mode.add_argument(
        '--apply',
        action='store_true',
        help='Persist cascade candidates as resolved instead of only reporting them.',
    )
    cascade_mode.add_argument(
        '--dry-run',
        action='store_true',
        help='Explicit no-write mode for readability in orchestration logs.',
    )
    cascade_parser.set_defaults(func=cmd_cascade_check)

    update_parser = subparsers.add_parser(
        'update',
        usage='ledger.py update --ledger PATH --key KEY (--from-handback - | --from-handback PATH | inline flags...)',
        help='Persist one advisory result from a handback JSON stream, file, or deterministic inline flags.',
        description=dedent(
            """
            Patch a single advisory in `issues-ledger.json`.

            Preferred mode:
              pass `--from-handback -`
              and stream a validated resolver handback JSON object via stdin.

            Secondary mode:
              pass `--from-handback PATH`
              when a validated resolver handback JSON object already exists on disk.

            Fallback mode:
              provide inline flags for deterministic testing, debugging,
              or narrowly scoped manual repair.
              Inline flags still need to obey the handback contract semantics.

            `update` writes final result fields like `status`, `implementation`, `verification`,
            and `outcome`, and stamps `completedAt` for non-`in-progress` states.
            """
        ),
        epilog=dedent(
            """
            Examples:
              cat .synk/{sessionId}/handback.json |
                python3 .github/skills/snyk-orchestration/scripts/ledger.py update \
                  --ledger .synk/{sessionId}/issues-ledger.json \
                  --key SNYK-JS-FOO-123 \
                  --from-handback -

              python3 .github/skills/snyk-orchestration/scripts/ledger.py update \
                --ledger .synk/{sessionId}/issues-ledger.json \
                --key SNYK-JS-FOO-123 \
                --from-handback .synk/{sessionId}/handback.json

              python3 .github/skills/snyk-orchestration/scripts/ledger.py update \
                --ledger .synk/{sessionId}/issues-ledger.json \
                --key SNYK-CODE-BAR-456 \
                --issue-type code \
                --status blocked \
                --file-path src/example.ts \
                --line-range 42-57 \
                --cwe-id CWE-79 \
                --severity high \
                --complexity architectural \
                --summary "Needs a broader refactor" \
                --blockers '["Shared sanitizer is missing"]' \
                --remediation-proposal "Refactor shared validation layer" \
                --rationale "A local patch would be incomplete"
            """
        ),
        formatter_class=HelpFormatter,
    )
    update_parser.add_argument(
        '--ledger',
        required=True,
        metavar='PATH',
        help='Path to the session `issues-ledger.json` that should be patched.',
    )
    update_parser.add_argument(
        '--key',
        required=True,
        metavar='KEY',
        help='Advisory key to update inside the ledger.',
    )
    update_parser.add_argument(
        '--from-handback',
        metavar='PATH',
        help='Resolver handback JSON source. Use `-` to read from stdin; pass a path only when the handback already exists on disk.',
    )
    update_parser.add_argument('--issue-type', help='Handback field `issueType`.')
    update_parser.add_argument('--status', help='Handback field `status`. Required for inline mode.')
    update_parser.add_argument('--package', help='Handback field `vulnerablePackage`.')
    update_parser.add_argument(
        '--vuln-versions',
        metavar='JSON',
        help='JSON array for handback field `vulnerableVersions`, e.g. ["1.2.3"].',
    )
    update_parser.add_argument('--target-version', help='Handback field `targetVersion`.')
    update_parser.add_argument('--strategy', help='Handback field `strategy` for dependency advisories.')
    update_parser.add_argument('--risk-level', help='Handback field `riskLevel` for dependency advisories.')
    update_parser.add_argument('--complexity', help='Handback field `complexity`.')
    update_parser.add_argument('--file-path', help='Handback field `filePath` for code advisories.')
    update_parser.add_argument('--line-range', help='Handback field `lineRange` for code advisories.')
    update_parser.add_argument('--cwe-id', help='Handback field `cweId` for code advisories.')
    update_parser.add_argument('--severity', help='Handback field `severity`, typically for code advisories.')
    update_parser.add_argument(
        '--files-changed',
        metavar='JSON',
        help='JSON array for `implementation.filesChanged`.',
    )
    update_parser.add_argument(
        '--dep-updates',
        metavar='JSON',
        help='JSON array for `implementation.dependencyUpdates`.',
    )
    update_parser.add_argument(
        '--parent-updates',
        metavar='JSON',
        help='JSON array for `implementation.parentUpdates`.',
    )
    update_parser.add_argument(
        '--overrides',
        metavar='JSON',
        help='JSON array for `implementation.overridesApplied`.',
    )
    update_parser.add_argument(
        '--dep-check',
        choices=['pass', 'fail'],
        help='Handback field `verification.dependencyCheck`.',
    )
    update_parser.add_argument(
        '--lint',
        choices=['pass', 'fail', 'not-run'],
        help='Handback field `verification.lint`.',
    )
    update_parser.add_argument(
        '--tsc',
        choices=['pass', 'fail', 'not-run'],
        help='Handback field `verification.typecheck`.',
    )
    update_parser.add_argument(
        '--tests',
        choices=['pass', 'fail', 'not-run'],
        help='Handback field `verification.tests`.',
    )
    update_parser.add_argument(
        '--build',
        choices=['pass', 'fail', 'not-run'],
        help='Handback field `verification.build`.',
    )
    update_parser.add_argument('--summary', help='Handback field `outcome.summary`.')
    update_parser.add_argument(
        '--blockers',
        metavar='JSON',
        help='JSON array for `outcome.blockers`.',
    )
    update_parser.add_argument(
        '--remediation-proposal',
        help='Handback field `outcome.remediationProposal`.',
    )
    update_parser.add_argument('--rationale', help='Handback field `outcome.rationale`.')
    update_parser.set_defaults(func=cmd_update)

    failure_parser = subparsers.add_parser(
        'record-failure',
        usage='ledger.py record-failure --ledger PATH --key KEY --kind KIND [options]',
        help='Persist resume/failure relevant metadata for one advisory.',
        description=dedent(
            """
            Persist operational failure metadata without inventing a new business outcome.

            Use this when a gate fails in a way that must survive resume, such as handback
            parse failures, validation failures, dirty stops, or resolver runtime problems.

            `record-failure` updates metadata like `lastFailureKind`, `lastFailureAt`,
            and `lastFailureMessage`.
            """
        ),
        epilog=dedent(
            """
            Example:
              python3 .github/skills/snyk-orchestration/scripts/ledger.py record-failure \
                --ledger .synk/{sessionId}/issues-ledger.json \
                --key SNYK-JS-FOO-123 \
                --kind handback-format \
                --message "Missing outcome.remediationProposal"
            """
        ),
        formatter_class=HelpFormatter,
    )
    failure_parser.add_argument(
        '--ledger',
        required=True,
        metavar='PATH',
        help='Path to the session `issues-ledger.json` to update.',
    )
    failure_parser.add_argument(
        '--key',
        required=True,
        metavar='KEY',
        help='Advisory key whose failure metadata should be updated.',
    )
    failure_parser.add_argument(
        '--kind',
        required=True,
        metavar='KIND',
        help='Failure kind, e.g. `handback-format`, `dirty-stop`, or `resolver-error`.',
    )
    failure_parser.add_argument('--message', help='Optional human-readable error detail to persist.')
    failure_parser.set_defaults(func=cmd_record_failure)

    status_parser = subparsers.add_parser(
        'set-status',
        usage='ledger.py set-status --ledger PATH --key KEY --status STATUS',
        help='Persist a status transition for one advisory.',
        description=dedent(
            """
            Set the status of one advisory and maintain runtime timestamps.

            Most orchestrator runs use this to mark an advisory as `in-progress` before
            resolver dispatch. Final advisory results should usually be written through
            `update`, because `update` also persists implementation/verification/outcome fields.
            """
        ),
        epilog=dedent(
            """
            Examples:
              python3 .github/skills/snyk-orchestration/scripts/ledger.py set-status \
                --ledger .synk/{sessionId}/issues-ledger.json \
                --key SNYK-JS-FOO-123 \
                --status in-progress

              python3 .github/skills/snyk-orchestration/scripts/ledger.py set-status \
                --ledger .synk/{sessionId}/issues-ledger.json \
                --key SNYK-JS-FOO-123 \
                --status blocked
            """
        ),
        formatter_class=HelpFormatter,
    )
    status_parser.add_argument(
        '--ledger',
        required=True,
        metavar='PATH',
        help='Path to the session `issues-ledger.json` to update.',
    )
    status_parser.add_argument(
        '--key',
        required=True,
        metavar='KEY',
        help='Advisory key whose status should be changed.',
    )
    status_parser.add_argument(
        '--status',
        required=True,
        metavar='STATUS',
        help='New advisory status to persist.',
    )
    status_parser.set_defaults(func=cmd_set_status)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except LedgerError as exc:
        print(f'ledger.py error: {exc}', file=sys.stderr)
        return 1
