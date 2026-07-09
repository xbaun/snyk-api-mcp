from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

REPO_ROOT = Path(__file__).resolve().parents[5]
FIXTURE_DIR = REPO_ROOT / '.temp' / 'debug' / 'files'

from dep.adapters import NpmAdapter, PnpmAdapter, YarnAdapter, collect_list_evidence_paths
from dep.common import AnalysisContext, DepAnalysisError, ManifestInfo
from dep.adapters.yarn import version_satisfies_selector


class PnpmAdapterFallbackTests(unittest.TestCase):
    def test_collect_list_evidence_paths_reconstructs_transitive_chain(self) -> None:
        manifest = ManifestInfo(
            name='studio-app',
            manifest_path=Path('/tmp/apps/studio/package.json'),
            relative_manifest_path='apps/studio/package.json',
            relative_dir='apps/studio',
            raw={
                'name': 'studio-app',
                'dependencies': {
                    '@sanity/vision': '5.17.1',
                },
            },
        )
        trees = [
            {
                'name': 'studio-app',
                'version': '1.0.0',
                'dependencies': {
                    '@sanity/vision': {
                        'from': '@sanity/vision',
                        'version': '5.17.1',
                        'dependencies': {
                            'json-2-csv': {
                                'from': 'json-2-csv',
                                'version': '5.5.9',
                            }
                        },
                    }
                },
            }
        ]

        paths = collect_list_evidence_paths(trees, [manifest], 'json-2-csv', 8)

        self.assertEqual(
            paths,
            [
                {
                    'importer': 'studio-app',
                    'importerPath': 'apps/studio',
                    'dependencyType': 'dependencies',
                    'directDependency': '@sanity/vision@5.17.1',
                    'chain': ['@sanity/vision@5.17.1', 'json-2-csv@5.5.9'],
                }
            ],
        )

    def test_load_evidence_paths_falls_back_to_pnpm_list(self) -> None:
        adapter = PnpmAdapter()
        context = AnalysisContext(
            repo_root=Path('/tmp/repo'),
            package_name='json-2-csv',
            workspace_package='apps/studio',
            manager='pnpm',
            max_paths=8,
            prod_only=False,
            dev_only=False,
            vulnerable_versions=(),
        )
        manifest = ManifestInfo(
            name='studio-app',
            manifest_path=Path('/tmp/apps/studio/package.json'),
            relative_manifest_path='apps/studio/package.json',
            relative_dir='apps/studio',
            raw={'name': 'studio-app', 'dependencies': {'@sanity/vision': '5.17.1'}},
        )
        fallback_paths = [
            {
                'importer': 'studio-app',
                'importerPath': 'apps/studio',
                'dependencyType': 'dependencies',
                'directDependency': '@sanity/vision@5.17.1',
                'chain': ['@sanity/vision@5.17.1', 'json-2-csv@5.5.9'],
            }
        ]

        with patch('dep.adapters.pnpm.collect_evidence_paths', return_value=[]), patch.object(
            adapter,
            '_load_list_evidence_paths',
            return_value=fallback_paths,
        ) as load_list_paths:
            paths = adapter._load_evidence_paths(
                context,
                [manifest],
                [{'name': 'json-2-csv', 'version': '5.5.9'}],
            )

        self.assertEqual(paths, fallback_paths)
        load_list_paths.assert_called_once_with(context, [manifest])

    def test_trace_fails_clearly_when_no_path_can_be_proven(self) -> None:
        adapter = PnpmAdapter()
        context = AnalysisContext(
            repo_root=Path('/tmp/repo'),
            package_name='json-2-csv',
            workspace_package='apps/studio',
            manager='pnpm',
            max_paths=8,
            prod_only=False,
            dev_only=False,
            vulnerable_versions=(),
        )
        manifest = ManifestInfo(
            name='studio-app',
            manifest_path=Path('/tmp/apps/studio/package.json'),
            relative_manifest_path='apps/studio/package.json',
            relative_dir='apps/studio',
            raw={'name': 'studio-app', 'dependencies': {'@sanity/vision': '5.17.1'}},
        )

        with patch.object(
            adapter,
            '_load_why_graph',
            return_value=[{'name': 'json-2-csv', 'version': '5.5.9'}],
        ), patch.object(adapter, '_load_evidence_paths', return_value=[]):
            with self.assertRaisesRegex(
                DepAnalysisError,
                'present in the pnpm graph, but no dependency path could be reconstructed',
            ):
                adapter.trace(context, [manifest])


class NpmAdapterFixtureTests(unittest.TestCase):
    def test_trace_reconstructs_package_lock_chain(self) -> None:
        package_lock = json.loads((FIXTURE_DIR / 'package-lock.json').read_text(encoding='utf-8'))
        manifest = ManifestInfo(
            name=package_lock['packages']['']['name'],
            manifest_path=FIXTURE_DIR / 'package.json',
            relative_manifest_path='package.json',
            relative_dir='.',
            raw=package_lock['packages'][''],
        )
        context = AnalysisContext(
            repo_root=FIXTURE_DIR,
            package_name='graphql-tag',
            workspace_package=None,
            manager='npm',
            max_paths=8,
            prod_only=False,
            dev_only=False,
            vulnerable_versions=(),
        )

        result = NpmAdapter().trace(context, [manifest])

        self.assertEqual(result['manager'], 'npm')
        self.assertEqual(
            result['evidencePaths'][0],
            {
                'importer': manifest.name,
                'importerPath': '.',
                'dependencyType': 'dependencies',
                'directDependency': '@apollo/client@3.7.5',
                'chain': ['@apollo/client@3.7.5', 'graphql-tag@2.12.6'],
            },
        )
        self.assertIn(
            {
                'package': '@apollo/client',
                'declaredIn': 'package.json',
                'dependencyType': 'dependencies',
                'declaredVersion': '3.7.5',
            },
            result['controllableParents'],
        )
        self.assertEqual(result['candidateLevers'], ['update-parent', 'temp-override'])

    def test_verify_reports_reachable_vulnerable_npm_versions(self) -> None:
        package_lock = json.loads((FIXTURE_DIR / 'package-lock.json').read_text(encoding='utf-8'))
        manifest = ManifestInfo(
            name=package_lock['packages']['']['name'],
            manifest_path=FIXTURE_DIR / 'package.json',
            relative_manifest_path='package.json',
            relative_dir='.',
            raw=package_lock['packages'][''],
        )
        context = AnalysisContext(
            repo_root=FIXTURE_DIR,
            package_name='graphql-tag',
            workspace_package=None,
            manager='npm',
            max_paths=8,
            prod_only=False,
            dev_only=False,
            vulnerable_versions=('2.12.6',),
        )

        result = NpmAdapter().verify(context, [manifest])

        self.assertEqual(result['dependencyCheck'], 'fail')
        self.assertEqual(result['observedVersions'], ['2.12.6'])
        self.assertEqual(result['reachableVulnerableVersions'], ['2.12.6'])
        self.assertEqual(
            result['remainingPaths'][0]['chain'],
            ['@apollo/client@3.7.5', 'graphql-tag@2.12.6'],
        )

    def test_trace_does_not_treat_peer_only_npm_declarations_as_reachable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo_root = Path(tmp)
            package_lock = {
                'name': 'peer-only-app',
                'lockfileVersion': 3,
                'packages': {
                    '': {
                        'name': 'peer-only-app',
                        'version': '1.0.0',
                        'peerDependencies': {
                            'left-pad': '^1.3.0',
                        },
                    },
                    'node_modules/left-pad': {
                        'version': '1.3.0',
                    },
                },
            }
            (repo_root / 'package-lock.json').write_text(json.dumps(package_lock), encoding='utf-8')

            manifest = ManifestInfo(
                name='peer-only-app',
                manifest_path=repo_root / 'package.json',
                relative_manifest_path='package.json',
                relative_dir='.',
                raw=package_lock['packages'][''],
            )
            context = AnalysisContext(
                repo_root=repo_root,
                package_name='left-pad',
                workspace_package=None,
                manager='npm',
                max_paths=8,
                prod_only=False,
                dev_only=False,
                vulnerable_versions=(),
            )

            result = NpmAdapter().trace(context, [manifest])

        self.assertEqual(result['evidencePaths'], [])
        self.assertEqual(result['controllableParents'], [])
        self.assertEqual(result['candidateLevers'], [])


class YarnAdapterFixtureTests(unittest.TestCase):
    def test_trace_reconstructs_yarn_lock_chain(self) -> None:
        manifest = ManifestInfo(
            name='fixture-yarn-app',
            manifest_path=FIXTURE_DIR / 'package.json',
            relative_manifest_path='package.json',
            relative_dir='.',
            raw={
                'name': 'fixture-yarn-app',
                'dependencies': {
                    'glob': '^10.4.5',
                },
            },
        )
        context = AnalysisContext(
            repo_root=FIXTURE_DIR,
            package_name='package-json-from-dist',
            workspace_package=None,
            manager='yarn',
            max_paths=8,
            prod_only=False,
            dev_only=False,
            vulnerable_versions=(),
        )

        result = YarnAdapter().trace(context, [manifest])

        self.assertEqual(result['manager'], 'yarn')
        self.assertEqual(
            result['evidencePaths'][0],
            {
                'importer': 'fixture-yarn-app',
                'importerPath': '.',
                'dependencyType': 'dependencies',
                'directDependency': 'glob@10.4.5',
                'chain': ['glob@10.4.5', 'package-json-from-dist@1.0.1'],
            },
        )
        self.assertIn(
            {
                'package': 'glob',
                'declaredIn': 'package.json',
                'dependencyType': 'dependencies',
                'declaredVersion': '^10.4.5',
            },
            result['controllableParents'],
        )
        self.assertEqual(result['candidateLevers'], ['update-parent', 'temp-override'])

    def test_verify_reports_reachable_vulnerable_yarn_versions(self) -> None:
        manifest = ManifestInfo(
            name='fixture-yarn-app',
            manifest_path=FIXTURE_DIR / 'package.json',
            relative_manifest_path='package.json',
            relative_dir='.',
            raw={
                'name': 'fixture-yarn-app',
                'dependencies': {
                    'glob': '^10.4.5',
                },
            },
        )
        context = AnalysisContext(
            repo_root=FIXTURE_DIR,
            package_name='package-json-from-dist',
            workspace_package=None,
            manager='yarn',
            max_paths=8,
            prod_only=False,
            dev_only=False,
            vulnerable_versions=('1.0.1',),
        )

        result = YarnAdapter().verify(context, [manifest])

        self.assertEqual(result['dependencyCheck'], 'fail')
        self.assertEqual(result['observedVersions'], ['1.0.1'])
        self.assertEqual(result['reachableVulnerableVersions'], ['1.0.1'])
        self.assertEqual(
            result['remainingPaths'][0]['chain'],
            ['glob@10.4.5', 'package-json-from-dist@1.0.1'],
        )

    def test_trace_does_not_treat_peer_only_yarn_declarations_as_reachable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo_root = Path(tmp)
            (repo_root / 'yarn.lock').write_text(
                '# yarn lockfile v1\n\nleft-pad@^1.3.0:\n  version "1.3.0"\n',
                encoding='utf-8',
            )
            manifest = ManifestInfo(
                name='peer-only-app',
                manifest_path=repo_root / 'package.json',
                relative_manifest_path='package.json',
                relative_dir='.',
                raw={
                    'name': 'peer-only-app',
                    'peerDependencies': {
                        'left-pad': '^1.3.0',
                    },
                },
            )
            context = AnalysisContext(
                repo_root=repo_root,
                package_name='left-pad',
                workspace_package=None,
                manager='yarn',
                max_paths=8,
                prod_only=False,
                dev_only=False,
                vulnerable_versions=(),
            )

            result = YarnAdapter().trace(context, [manifest])

        self.assertEqual(result['evidencePaths'], [])
        self.assertEqual(result['controllableParents'], [])
        self.assertEqual(result['candidateLevers'], [])


class YarnSemverFallbackTests(unittest.TestCase):
    def test_prerelease_does_not_satisfy_plain_release_caret_range(self) -> None:
        self.assertFalse(version_satisfies_selector('1.0.0-beta.1', '^1.0.0'))

    def test_hyphen_range_is_supported(self) -> None:
        self.assertTrue(version_satisfies_selector('1.5.0', '1.0.0 - 2.0.0'))


if __name__ == '__main__':
    unittest.main()
