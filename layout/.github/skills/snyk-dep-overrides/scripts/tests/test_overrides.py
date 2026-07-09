from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import overrides


class OverridesScriptTests(unittest.TestCase):
    def _case(
        self,
        *,
        key: str,
        status: str,
        selector: str,
        target: str,
        package: str,
        snyk_id: str,
    ) -> dict[str, object]:
        return {
            'key': key,
            'status': status,
            'reason': 'security',
            'selector': selector,
            'target': target,
            'package': package,
            'snykIds': [snyk_id],
            'introducedBy': 'test-session',
            'createdAt': '2026-07-09T00:00:00Z',
            'updatedAt': '2026-07-09T00:00:00Z',
            'evidenceTree': [
                {
                    'importer': 'workspace-root',
                    'directDependency': 'vite@7.0.0',
                    'chain': ['vite@7.0.0', f'{package}@1.0.0'],
                }
            ],
            'watch': [
                {
                    'package': 'vite',
                    'declaredIn': 'package.json',
                    'declaredVersion': '^7.0.0',
                    'relevance': 'Direct lever for override reevaluation.',
                }
            ],
            'obsoleteWhen': [
                f'All watched packages resolve {package} natively',
                'Removing selector does not reintroduce the vulnerable package version',
            ],
        }

    def _write_document(self, path: Path, cases: list[dict[str, object]]) -> None:
        path.write_text(
            json.dumps(
                {
                    '$schema': '../schemas/snyk-dep-overrides.schema.json',
                    'schemaVersion': 1,
                    'manager': 'pnpm',
                    'generatedAt': '2026-07-09T00:00:00Z',
                    'cases': cases,
                },
                indent=2,
            )
            + '\n',
            encoding='utf-8',
        )

    def _run_main(self, argv: list[str]) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = overrides.main(argv)
        return exit_code, stdout.getvalue(), stderr.getvalue()

    def test_read_supports_explicit_manager_for_noncanonical_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            materialization = Path(tmp) / 'fixture.json'
            self._write_document(
                materialization,
                [
                    self._case(
                        key='esbuild-active',
                        status='active',
                        selector='esbuild@<0.28.0',
                        target='^0.28.1',
                        package='esbuild',
                        snyk_id='SNYK-JS-ESBUILD-1',
                    )
                ],
            )

            exit_code, stdout, stderr = self._run_main(
                [
                    'read',
                    '--materialization',
                    str(materialization),
                    '--manager',
                    'pnpm',
                    '--key',
                    'esbuild-active',
                ]
            )

        self.assertEqual(exit_code, 0, stderr)
        payload = json.loads(stdout)
        self.assertEqual(payload['key'], 'esbuild-active')
        self.assertEqual(payload['selector'], 'esbuild@<0.28.0')

    def test_analyze_filters_matches_by_check_selector_and_reports_conflicts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            materialization = Path(tmp) / 'fixture.json'
            self._write_document(
                materialization,
                [
                    self._case(
                        key='esbuild-active',
                        status='active',
                        selector='esbuild@<0.28.0',
                        target='^0.28.1',
                        package='esbuild',
                        snyk_id='SNYK-JS-ESBUILD-1',
                    ),
                    self._case(
                        key='esbuild-draft',
                        status='draft',
                        selector='esbuild@^0.28.5',
                        target='^0.28.5',
                        package='esbuild',
                        snyk_id='SNYK-JS-ESBUILD-2',
                    ),
                    self._case(
                        key='other-active',
                        status='active',
                        selector='rollup@<4.0.0',
                        target='^4.0.0',
                        package='rollup',
                        snyk_id='SNYK-JS-ROLLUP-1',
                    ),
                ],
            )

            exit_code, stdout, stderr = self._run_main(
                [
                    'analyze',
                    '--materialization',
                    str(materialization),
                    '--manager',
                    'pnpm',
                    '--check-selector',
                    'esbuild@<0.28.0',
                    '--status',
                    'active',
                ]
            )

        self.assertEqual(exit_code, 0, stderr)
        payload = json.loads(stdout)
        self.assertEqual(payload['query']['manager'], 'pnpm')
        self.assertEqual([case['key'] for case in payload['matches']], ['esbuild-active'])
        self.assertEqual(payload['summary']['totalMatches'], 1)
        self.assertEqual(
            payload['summary']['statusCounts'],
            {'active': 1},
        )
        self.assertEqual(
            payload['summary']['conflictingSelectors'],
            [
                {
                    'key': 'esbuild-active',
                    'selector': 'esbuild@<0.28.0',
                    'target': '^0.28.1',
                    'status': 'active',
                    'conflictType': 'exact-selector',
                },
                {
                    'key': 'esbuild-draft',
                    'selector': 'esbuild@^0.28.5',
                    'target': '^0.28.5',
                    'status': 'draft',
                    'conflictType': 'same-package',
                },
            ],
        )

    def test_selector_conflict_type_handles_scoped_packages(self) -> None:
        self.assertEqual(
            overrides._selector_conflict_type('@types/node@<20.0.0', '@types/node@<20.0.0'),
            'exact-selector',
        )
        self.assertEqual(
            overrides._selector_conflict_type('@types/node@^20.1.0', '@types/node@<20.0.0'),
            'same-package',
        )
        self.assertIsNone(
            overrides._selector_conflict_type('@types/node@^20.1.0', '@types/react@<19.0.0')
        )


if __name__ == '__main__':
    unittest.main()
