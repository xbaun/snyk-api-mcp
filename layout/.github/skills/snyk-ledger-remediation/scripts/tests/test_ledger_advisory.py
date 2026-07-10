from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from ledger import advisory, analysis


class LedgerAdvisoryTests(unittest.TestCase):
    def test_build_inline_handback_requires_issue_type(self) -> None:
        args = SimpleNamespace(
            key='ADV-MISSING-TYPE',
            issue_type=None,
            status='blocked',
            package=None,
            vuln_versions=None,
            target_version=None,
            strategy=None,
            risk_level=None,
            complexity='architectural',
            file_path='src/index.ts',
            line_range='10-12',
            cwe_id='CWE-79',
            severity='high',
            files_changed=None,
            dep_updates=None,
            parent_updates=None,
            overrides=None,
            override_preflight=None,
            dep_check=None,
            lint=None,
            tsc=None,
            tests=None,
            build=None,
            summary='blocked',
            blockers='["shared sanitization missing"]',
            remediation_proposal='refactor shared layer',
            rationale='local fix incomplete',
        )

        with self.assertRaises(advisory.LedgerError) as context:
            advisory.build_inline_handback(args)

        self.assertIn('--issue-type', str(context.exception))

    def test_apply_handback_rejects_missing_issue_type(self) -> None:
        advisory_entry = {
            'advisoryKey': 'ADV-1',
            'issueType': 'package_vulnerability',
            'status': 'in-progress',
        }

        with self.assertRaises(advisory.LedgerError) as context:
            advisory.apply_handback(
                advisory_entry,
                {
                    'status': 'resolved',
                    'vulnerablePackage': 'esbuild',
                    'vulnerableVersions': ['0.27.0'],
                    'targetVersion': '^0.28.1',
                    'strategy': 'update-direct',
                    'riskLevel': 'low',
                    'complexity': 'contained',
                    'implementation': {'filesChanged': []},
                    'verification': {
                        'dependencyCheck': 'pass',
                        'lint': 'not-run',
                        'typecheck': 'not-run',
                        'tests': 'not-run',
                        'build': 'not-run',
                    },
                    'outcome': {'summary': 'fixed'},
                },
            )

        self.assertIn('issueType', str(context.exception))

    def test_apply_handback_rejects_code_partial_status(self) -> None:
        advisory_entry = {
            'advisoryKey': 'ADV-2',
            'issueType': 'code',
            'status': 'in-progress',
        }

        with self.assertRaises(advisory.LedgerError) as context:
            advisory.apply_handback(
                advisory_entry,
                {
                    'issueType': 'code',
                    'status': 'partially-resolved',
                    'filePath': 'src/index.ts',
                    'lineRange': '10-12',
                    'cweId': 'CWE-79',
                    'severity': 'high',
                    'complexity': 'contained',
                    'implementation': {'filesChanged': ['src/index.ts']},
                    'verification': {
                        'lint': 'pass',
                        'typecheck': 'pass',
                        'tests': 'not-run',
                    },
                    'outcome': {'summary': 'partially fixed'},
                },
            )

        self.assertIn('status', str(context.exception))

    def test_apply_handback_rejects_resolved_package_without_dependency_pass(self) -> None:
        advisory_entry = {
            'advisoryKey': 'ADV-3',
            'issueType': 'package_vulnerability',
            'status': 'in-progress',
        }

        with self.assertRaises(advisory.LedgerError) as context:
            advisory.apply_handback(
                advisory_entry,
                {
                    'issueType': 'package_vulnerability',
                    'status': 'resolved',
                    'vulnerablePackage': 'esbuild',
                    'vulnerableVersions': ['0.27.0'],
                    'targetVersion': '^0.28.1',
                    'strategy': 'update-direct',
                    'riskLevel': 'low',
                    'complexity': 'contained',
                    'implementation': {'filesChanged': ['package.json']},
                    'verification': {
                        'dependencyCheck': 'fail',
                        'lint': 'pass',
                        'typecheck': 'pass',
                        'tests': 'pass',
                        'build': 'pass',
                    },
                    'outcome': {'summary': 'claimed fixed'},
                },
            )

        self.assertIn('dependencyCheck', str(context.exception))

    def test_apply_handback_rejects_package_code_fields(self) -> None:
        advisory_entry = {
            'advisoryKey': 'ADV-3B',
            'issueType': 'package_vulnerability',
            'status': 'in-progress',
        }

        with self.assertRaises(advisory.LedgerError) as context:
            advisory.apply_handback(
                advisory_entry,
                {
                    'issueType': 'package_vulnerability',
                    'status': 'blocked',
                    'vulnerablePackage': 'esbuild',
                    'vulnerableVersions': ['0.27.0'],
                    'targetVersion': '^0.28.1',
                    'strategy': 'update-parent',
                    'riskLevel': 'medium',
                    'complexity': 'architectural',
                    'filePath': 'src/index.ts',
                    'implementation': {'filesChanged': []},
                    'verification': {
                        'dependencyCheck': 'fail',
                        'lint': 'not-run',
                        'typecheck': 'not-run',
                        'tests': 'not-run',
                        'build': 'not-run',
                    },
                    'outcome': {
                        'summary': 'blocked',
                        'blockers': ['needs manual upgrade'],
                        'remediationProposal': 'upgrade parent package',
                        'rationale': 'shared dependency',
                    },
                },
            )

        self.assertIn('unsupported keys', str(context.exception))

    def test_apply_handback_rejects_null_values(self) -> None:
        advisory_entry = {
            'advisoryKey': 'ADV-4',
            'issueType': 'package_vulnerability',
            'status': 'in-progress',
        }

        with self.assertRaises(advisory.LedgerError) as context:
            advisory.apply_handback(
                advisory_entry,
                {
                    'issueType': 'package_vulnerability',
                    'status': 'blocked',
                    'vulnerablePackage': 'esbuild',
                    'vulnerableVersions': ['0.27.0'],
                    'targetVersion': '^0.28.1',
                    'strategy': 'update-parent',
                    'riskLevel': 'medium',
                    'complexity': 'architectural',
                    'implementation': {'filesChanged': []},
                    'verification': {
                        'dependencyCheck': 'fail',
                        'lint': 'not-run',
                        'typecheck': 'not-run',
                        'tests': 'not-run',
                        'build': 'not-run',
                    },
                    'outcome': {
                        'summary': 'blocked',
                        'blockers': ['needs manual upgrade'],
                        'remediationProposal': None,
                        'rationale': 'shared dependency',
                    },
                },
            )

        self.assertIn('must not be null', str(context.exception))

    def test_apply_handback_rejects_code_dependency_fields(self) -> None:
        advisory_entry = {
            'advisoryKey': 'ADV-4B',
            'issueType': 'code',
            'status': 'in-progress',
        }

        with self.assertRaises(advisory.LedgerError) as context:
            advisory.apply_handback(
                advisory_entry,
                {
                    'issueType': 'code',
                    'status': 'resolved',
                    'filePath': 'src/index.ts',
                    'lineRange': '10-12',
                    'cweId': 'CWE-79',
                    'severity': 'high',
                    'complexity': 'contained',
                    'vulnerablePackage': 'esbuild',
                    'implementation': {'filesChanged': ['src/index.ts']},
                    'verification': {
                        'lint': 'pass',
                        'typecheck': 'pass',
                        'tests': 'not-run',
                    },
                    'outcome': {'summary': 'fixed'},
                },
            )

        self.assertIn('unsupported keys', str(context.exception))

    def test_apply_handback_rejects_temp_override_duplicate_case_creation(self) -> None:
        advisory_entry = {
            'advisoryKey': 'ADV-5',
            'issueType': 'package_vulnerability',
            'status': 'in-progress',
        }

        with self.assertRaises(advisory.LedgerError) as context:
            advisory.apply_handback(
                advisory_entry,
                {
                    'issueType': 'package_vulnerability',
                    'status': 'resolved',
                    'vulnerablePackage': 'esbuild',
                    'vulnerableVersions': ['0.27.0'],
                    'targetVersion': '^0.28.1',
                    'strategy': 'temp-override',
                    'riskLevel': 'low',
                    'complexity': 'contained',
                    'implementation': {
                        'filesChanged': ['pnpm-workspace.yaml'],
                        'overridesApplied': ['esbuild@<0.28.0 -> ^0.28.1'],
                        'overridePreflight': {
                            'materializationPresent': True,
                            'queryPackage': 'esbuild',
                            'matchingCaseKeys': ['esbuild-active'],
                            'selectorConflict': 'exact-selector',
                            'disposition': 'create-new-case',
                        },
                    },
                    'verification': {
                        'dependencyCheck': 'pass',
                        'lint': 'not-run',
                        'typecheck': 'not-run',
                        'tests': 'not-run',
                        'build': 'not-run',
                    },
                    'outcome': {'summary': 'duplicated existing case'},
                },
            )

        self.assertIn('create a new case', str(context.exception))

    def test_build_inline_handback_parses_override_preflight(self) -> None:
        args = SimpleNamespace(
            key='ADV-1',
            issue_type='package_vulnerability',
            status='resolved',
            package='esbuild',
            vuln_versions='["0.27.0"]',
            target_version='^0.28.1',
            strategy='temp-override',
            risk_level='low',
            complexity='contained',
            file_path=None,
            line_range=None,
            cwe_id=None,
            severity=None,
            files_changed='["pnpm-workspace.yaml", "snyk-dep-overrides.pnpm.json"]',
            dep_updates=None,
            parent_updates=None,
            overrides='["esbuild@<0.28.0 -> ^0.28.1"]',
            override_preflight=(
                '{"materializationPresent": true, "queryPackage": "esbuild", '
                '"matchingCaseKeys": ["esbuild-active"], '
                '"selectorConflict": "exact-selector", '
                '"disposition": "reuse-existing-case"}'
            ),
            dep_check='pass',
            lint='not-run',
            tsc='not-run',
            tests='not-run',
            build='not-run',
            summary='Reused existing override case',
            blockers=None,
            remediation_proposal=None,
            rationale=None,
        )

        handback = advisory.build_inline_handback(args)

        self.assertEqual(handback['implementation']['overridePreflight']['queryPackage'], 'esbuild')
        self.assertEqual(
            handback['implementation']['overridePreflight']['disposition'],
            'reuse-existing-case',
        )

    def test_resolved_detail_includes_override_preflight(self) -> None:
        detail = analysis.resolved_detail(
            {
                'advisoryKey': 'ADV-1',
                'title': 'esbuild advisory',
                'issueType': 'package_vulnerability',
                'severity': 'high',
                'status': 'resolved',
                'issueCount': 1,
                'affectedProjectCount': 1,
                'createdAt': '2026-07-10T00:00:00Z',
                'strategy': 'temp-override',
                'targetVersion': '^0.28.1',
                'implementation': {
                    'overridesApplied': ['esbuild@<0.28.0 -> ^0.28.1'],
                    'overridePreflight': {
                        'materializationPresent': True,
                        'queryPackage': 'esbuild',
                        'matchingCaseKeys': ['esbuild-active'],
                        'selectorConflict': 'exact-selector',
                        'disposition': 'reuse-existing-case',
                    },
                },
                'verification': {'dependencyCheck': 'pass'},
                'outcome': {'summary': 'Reused existing override case'},
            }
        )

        self.assertEqual(detail['overridePreflight']['selectorConflict'], 'exact-selector')
        self.assertEqual(detail['overridePreflight']['matchingCaseKeys'], ['esbuild-active'])


if __name__ == '__main__':
    unittest.main()