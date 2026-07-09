from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from ..common import (
    AnalysisContext,
    DepAnalysisError,
    ManifestInfo,
    RUNTIME_DEPENDENCY_FIELDS,
    collect_direct_declarations,
    determine_analysis_root,
    parse_package_ref,
    resolve_analysis_directory,
)
from ._shared import (
    PackageManagerAdapter,
    build_candidate_levers,
    build_controllable_parents,
    collect_evidence_paths,
    collect_list_evidence_paths,
    collect_observed_versions,
    collect_reachable_importers,
    determine_dep_origin,
)


class PnpmAdapter(PackageManagerAdapter):
    name = 'pnpm'

    def detect_score(self, repo_root: Path) -> int:
        score = 0
        if (repo_root / 'pnpm-workspace.yaml').exists():
            score += 100
        if (repo_root / 'pnpm-lock.yaml').exists():
            score += 80
        if (repo_root / 'package.json').exists():
            score += 10
        return score

    def inspect(self, context: AnalysisContext, manifests: list[ManifestInfo]) -> dict[str, Any]:
        graph = self._load_why_graph(context, manifests)
        direct_declarations = collect_direct_declarations(manifests, context.package_name)
        evidence_paths = self._load_evidence_paths(context, manifests, graph)

        return {
            'manager': self.name,
            'packageName': context.package_name,
            'workspacePackage': context.workspace_package or 'unknown',
            'analysisRoot': determine_analysis_root(context.repo_root, manifests),
            'manifestPaths': [manifest.relative_manifest_path for manifest in manifests],
            'directDeclarations': direct_declarations,
            'observedVersions': collect_observed_versions(graph),
            'reachableImporters': collect_reachable_importers(evidence_paths),
            'packagePresent': bool(graph),
        }

    def trace(self, context: AnalysisContext, manifests: list[ManifestInfo]) -> dict[str, Any]:
        graph = self._load_why_graph(context, manifests)
        active_direct_declarations = collect_direct_declarations(
            manifests,
            context.package_name,
            RUNTIME_DEPENDENCY_FIELDS,
        )
        evidence_paths = self._load_evidence_paths(context, manifests, graph)
        controllable_parents = build_controllable_parents(
            manifests,
            active_direct_declarations,
            evidence_paths,
            context.package_name,
        )

        if graph and not evidence_paths:
            raise DepAnalysisError(
                f"Package '{context.package_name}' is present in the pnpm graph, but no dependency path "
                'could be reconstructed from pnpm why or pnpm list.'
            )

        dep_origin = determine_dep_origin(
            context.package_name,
            active_direct_declarations,
            evidence_paths,
        )
        candidate_levers = build_candidate_levers(
            context.package_name,
            bool(graph),
            active_direct_declarations,
            controllable_parents,
        )

        return {
            'manager': self.name,
            'packageName': context.package_name,
            'workspacePackage': context.workspace_package or 'unknown',
            'depOrigin': dep_origin,
            'controllableParents': controllable_parents,
            'evidencePaths': evidence_paths,
            'candidateLevers': candidate_levers,
        }

    def verify(self, context: AnalysisContext, manifests: list[ManifestInfo]) -> dict[str, Any]:
        if not context.vulnerable_versions:
            raise DepAnalysisError("verify requires at least one '--vulnerable-version'.")

        graph = self._load_why_graph(context, manifests)
        evidence_paths = self._load_evidence_paths(context, manifests, graph)
        observed_versions = collect_observed_versions(graph)
        vulnerable_versions = tuple(dict.fromkeys(context.vulnerable_versions))
        vulnerable_set = set(vulnerable_versions)
        reachable_vulnerable_versions = [version for version in observed_versions if version in vulnerable_set]

        remaining_paths = [
            path
            for path in evidence_paths
            if parse_package_ref(path['chain'][-1])[1] in vulnerable_set
        ]

        dependency_check = 'fail' if reachable_vulnerable_versions else 'pass'
        if not graph:
            summary = (
                f"Package '{context.package_name}' is not present in the analyzed dependency graph; "
                'no vulnerable version is reachable.'
            )
        elif dependency_check == 'pass':
            summary = (
                f"No reachable vulnerable versions of '{context.package_name}' remain in the analyzed dependency graph."
            )
        else:
            versions = ', '.join(reachable_vulnerable_versions)
            summary = f"Vulnerable versions of '{context.package_name}' remain reachable: {versions}."

        return {
            'manager': self.name,
            'packageName': context.package_name,
            'workspacePackage': context.workspace_package or 'unknown',
            'observedVersions': observed_versions,
            'vulnerableVersionsChecked': list(vulnerable_versions),
            'reachableVulnerableVersions': reachable_vulnerable_versions,
            'remainingPaths': remaining_paths,
            'dependencyCheck': dependency_check,
            'summary': summary,
        }

    def _load_why_graph(
        self,
        context: AnalysisContext,
        manifests: list[ManifestInfo],
    ) -> list[dict[str, Any]]:
        analysis_dir = resolve_analysis_directory(context.repo_root, manifests)
        command = [
            'pnpm',
            '--dir',
            str(analysis_dir),
            '--loglevel',
            'error',
            'why',
            context.package_name,
            '--json',
        ]
        if context.prod_only:
            command.append('--prod')
        if context.dev_only:
            command.append('--dev')

        completed = subprocess.run(
            command,
            cwd=context.repo_root,
            capture_output=True,
            text=True,
            check=False,
        )
        stdout = completed.stdout.strip()
        stderr = completed.stderr.strip()

        if completed.returncode != 0:
            message = stderr or stdout or f"pnpm why exited with status {completed.returncode}."
            raise DepAnalysisError(f'Failed to inspect dependency graph: {message}')
        if not stdout:
            return []

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise DepAnalysisError('pnpm why returned invalid JSON output.') from exc

        if isinstance(data, dict):
            return [data]
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        raise DepAnalysisError('pnpm why returned an unexpected JSON shape.')

    def _load_evidence_paths(
        self,
        context: AnalysisContext,
        manifests: list[ManifestInfo],
        graph: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        evidence_paths = collect_evidence_paths(graph, manifests, context.max_paths)
        if evidence_paths or not graph:
            return evidence_paths
        return self._load_list_evidence_paths(context, manifests)

    def _load_list_evidence_paths(
        self,
        context: AnalysisContext,
        manifests: list[ManifestInfo],
    ) -> list[dict[str, Any]]:
        analysis_dir = resolve_analysis_directory(context.repo_root, manifests)
        command = [
            'pnpm',
            '--dir',
            str(analysis_dir),
            '--loglevel',
            'error',
            'list',
            context.package_name,
            '--json',
            '--depth',
            'Infinity',
        ]
        if context.prod_only:
            command.append('--prod')
        if context.dev_only:
            command.append('--dev')

        completed = subprocess.run(
            command,
            cwd=context.repo_root,
            capture_output=True,
            text=True,
            check=False,
        )
        stdout = completed.stdout.strip()
        stderr = completed.stderr.strip()

        if completed.returncode != 0:
            message = stderr or stdout or f"pnpm list exited with status {completed.returncode}."
            raise DepAnalysisError(f'Failed to reconstruct dependency paths: {message}')
        if not stdout:
            return []

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise DepAnalysisError('pnpm list returned invalid JSON output.') from exc

        trees: list[dict[str, Any]]
        if isinstance(data, dict):
            trees = [data]
        elif isinstance(data, list):
            trees = [item for item in data if isinstance(item, dict)]
        else:
            raise DepAnalysisError('pnpm list returned an unexpected JSON shape.')

        return collect_list_evidence_paths(
            trees,
            manifests,
            context.package_name,
            context.max_paths,
        )
