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

REPO_ROOT = next(parent for parent in Path(__file__).resolve().parents if (parent / 'fixtures').exists())
FIXTURE_DIR = REPO_ROOT / 'fixtures'

FIXTURE_MANIFEST_RAW = {
    'name': 'fixture-dep-app',
    'dependencies': {
        'axios': '^1.18.1',
    },
}

from dep.adapters import NpmAdapter, PnpmAdapter, YarnAdapter, collect_list_evidence_paths
from dep.common import AnalysisContext, DepAnalysisError, ManifestInfo
from dep.adapters.yarn import version_satisfies_selector


def build_fixture_manifest() -> ManifestInfo:
    return ManifestInfo(
        name=FIXTURE_MANIFEST_RAW['name'],
        manifest_path=FIXTURE_DIR / 'package.json',
        relative_manifest_path='package.json',
        relative_dir='.',
        raw=FIXTURE_MANIFEST_RAW,
    )


class PnpmAdapterFallbackTests(unittest.TestCase):
    def test_collect_list_evidence_paths_reconstructs_transitive_chain(self) -> None:
        manifest = build_fixture_manifest()
        trees = [
            {
                'name': manifest.name,
                'version': '1.0.0',
                'dependencies': {
                    'axios': {
                        'from': 'axios',
                        'version': '1.18.1',
                        'dependencies': {
                            'form-data': {
                                'from': 'form-data',
                                'version': '4.0.6',
                                'dependencies': {
                                    'mime-types': {
                                        'from': 'mime-types',
                                        'version': '2.1.35',
                                        'dependencies': {
                                            'mime-db': {
                                                'from': 'mime-db',
                                                'version': '1.52.0',
                                            }
                                        },
                                    }
                                },
                            }
                        },
                    }
                },
            }
        ]

        paths = collect_list_evidence_paths(trees, [manifest], 'mime-db', 8)

        self.assertEqual(
            paths,
            [
                {
                    'importer': manifest.name,
                    'importerPath': '.',
                    'dependencyType': 'dependencies',
                    'directDependency': 'axios@1.18.1',
                    'chain': [
                        'axios@1.18.1',
                        'form-data@4.0.6',
                        'mime-types@2.1.35',
                        'mime-db@1.52.0',
                    ],
                }
            ],
        )

    def test_load_evidence_paths_falls_back_to_pnpm_list(self) -> None:
        adapter = PnpmAdapter()
        context = AnalysisContext(
            repo_root=FIXTURE_DIR,
            package_name='mime-db',
            workspace_package=None,
            manager='pnpm',
            max_paths=8,
            prod_only=False,
            dev_only=False,
            vulnerable_versions=(),
        )
        manifest = build_fixture_manifest()
        fallback_paths = [
            {
                'importer': manifest.name,
                'importerPath': '.',
                'dependencyType': 'dependencies',
                'directDependency': 'axios@1.18.1',
                'chain': [
                    'axios@1.18.1',
                    'form-data@4.0.6',
                    'mime-types@2.1.35',
                    'mime-db@1.52.0',
                ],
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
                [{'name': 'mime-db', 'version': '1.52.0'}],
            )

        self.assertEqual(paths, fallback_paths)
        load_list_paths.assert_called_once_with(context, [manifest])

    def test_trace_fails_clearly_when_no_path_can_be_proven(self) -> None:
        adapter = PnpmAdapter()
        context = AnalysisContext(
            repo_root=FIXTURE_DIR,
            package_name='mime-db',
            workspace_package=None,
            manager='pnpm',
            max_paths=8,
            prod_only=False,
            dev_only=False,
            vulnerable_versions=(),
        )
        manifest = build_fixture_manifest()

        with patch.object(
            adapter,
            '_load_why_graph',
            return_value=[{'name': 'mime-db', 'version': '1.52.0'}],
        ), patch.object(adapter, '_load_evidence_paths', return_value=[]):
            with self.assertRaisesRegex(
                DepAnalysisError,
                'present in the pnpm graph, but no dependency path could be reconstructed',
            ):
                adapter.trace(context, [manifest])


class NpmAdapterFixtureTests(unittest.TestCase):
    def test_trace_reconstructs_package_lock_chain(self) -> None:
        manifest = build_fixture_manifest()
        context = AnalysisContext(
            repo_root=FIXTURE_DIR,
            package_name='mime-db',
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
                'directDependency': 'axios@1.18.1',
                'chain': [
                    'axios@1.18.1',
                    'form-data@4.0.6',
                    'mime-types@2.1.35',
                    'mime-db@1.52.0',
                ],
            },
        )
        self.assertIn(
            {
                'package': 'axios',
                'declaredIn': 'package.json',
                'dependencyType': 'dependencies',
                'declaredVersion': '^1.18.1',
            },
            result['controllableParents'],
        )
        self.assertEqual(result['candidateLevers'], ['update-parent', 'temp-override'])

    def test_verify_reports_reachable_vulnerable_npm_versions(self) -> None:
        manifest = build_fixture_manifest()
        context = AnalysisContext(
            repo_root=FIXTURE_DIR,
            package_name='mime-db',
            workspace_package=None,
            manager='npm',
            max_paths=8,
            prod_only=False,
            dev_only=False,
            vulnerable_versions=('1.52.0',),
        )

        result = NpmAdapter().verify(context, [manifest])

        self.assertEqual(result['dependencyCheck'], 'fail')
        self.assertEqual(result['observedVersions'], ['1.52.0'])
        self.assertEqual(result['reachableVulnerableVersions'], ['1.52.0'])
        self.assertEqual(
            result['remainingPaths'][0]['chain'],
            ['axios@1.18.1', 'form-data@4.0.6', 'mime-types@2.1.35', 'mime-db@1.52.0'],
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
        manifest = build_fixture_manifest()
        context = AnalysisContext(
            repo_root=FIXTURE_DIR,
            package_name='mime-db',
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
                'importer': manifest.name,
                'importerPath': '.',
                'dependencyType': 'dependencies',
                'directDependency': 'axios@1.18.1',
                'chain': [
                    'axios@1.18.1',
                    'form-data@4.0.6',
                    'mime-types@2.1.35',
                    'mime-db@1.52.0',
                ],
            },
        )
        self.assertIn(
            {
                'package': 'axios',
                'declaredIn': 'package.json',
                'dependencyType': 'dependencies',
                'declaredVersion': '^1.18.1',
            },
            result['controllableParents'],
        )
        self.assertEqual(result['candidateLevers'], ['update-parent', 'temp-override'])

    def test_verify_reports_reachable_vulnerable_yarn_versions(self) -> None:
        manifest = build_fixture_manifest()
        context = AnalysisContext(
            repo_root=FIXTURE_DIR,
            package_name='mime-db',
            workspace_package=None,
            manager='yarn',
            max_paths=8,
            prod_only=False,
            dev_only=False,
            vulnerable_versions=('1.52.0',),
        )

        result = YarnAdapter().verify(context, [manifest])

        self.assertEqual(result['dependencyCheck'], 'fail')
        self.assertEqual(result['observedVersions'], ['1.52.0'])
        self.assertEqual(result['reachableVulnerableVersions'], ['1.52.0'])
        self.assertEqual(
            result['remainingPaths'][0]['chain'],
            ['axios@1.18.1', 'form-data@4.0.6', 'mime-types@2.1.35', 'mime-db@1.52.0'],
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
