from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Any

from ..common import (
    AnalysisContext,
    DepAnalysisError,
    ManifestInfo,
    RUNTIME_DEPENDENCY_FIELDS,
    collect_direct_declarations,
    determine_analysis_root,
    format_package_ref,
    load_json,
    parse_package_ref,
)
from ._shared import (
    PackageManagerAdapter,
    build_candidate_levers,
    build_controllable_parents,
    collect_reachable_importers,
    determine_dep_origin,
    record_list_evidence_path,
)


class NpmAdapter(PackageManagerAdapter):
    name = 'npm'

    def detect_score(self, repo_root: Path) -> int:
        return 50 if (repo_root / 'package-lock.json').exists() else 0

    def inspect(self, context: AnalysisContext, manifests: list[ManifestInfo]) -> dict[str, Any]:
        package_present, observed_versions, evidence_paths = analyze_npm_lockfile(
            context.repo_root,
            manifests,
            context.package_name,
            context.max_paths,
        )
        direct_declarations = collect_direct_declarations(manifests, context.package_name)

        return {
            'manager': self.name,
            'packageName': context.package_name,
            'workspacePackage': context.workspace_package or 'unknown',
            'analysisRoot': determine_analysis_root(context.repo_root, manifests),
            'manifestPaths': [manifest.relative_manifest_path for manifest in manifests],
            'directDeclarations': direct_declarations,
            'observedVersions': observed_versions,
            'reachableImporters': collect_reachable_importers(evidence_paths),
            'packagePresent': package_present,
        }

    def trace(self, context: AnalysisContext, manifests: list[ManifestInfo]) -> dict[str, Any]:
        package_present, _observed_versions, evidence_paths = analyze_npm_lockfile(
            context.repo_root,
            manifests,
            context.package_name,
            context.max_paths,
        )
        active_direct_declarations = collect_direct_declarations(
            manifests,
            context.package_name,
            RUNTIME_DEPENDENCY_FIELDS,
        )
        controllable_parents = build_controllable_parents(
            manifests,
            active_direct_declarations,
            evidence_paths,
            context.package_name,
        )

        if package_present and not evidence_paths:
            raise DepAnalysisError(
                f"Package '{context.package_name}' is present in the npm lockfile graph, but no dependency path "
                'could be reconstructed from package-lock.json.'
            )

        dep_origin = determine_dep_origin(
            context.package_name,
            active_direct_declarations,
            evidence_paths,
        )
        candidate_levers = build_candidate_levers(
            context.package_name,
            package_present,
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

        package_present, observed_versions, evidence_paths = analyze_npm_lockfile(
            context.repo_root,
            manifests,
            context.package_name,
            context.max_paths,
        )
        vulnerable_versions = tuple(dict.fromkeys(context.vulnerable_versions))
        vulnerable_set = set(vulnerable_versions)
        reachable_vulnerable_versions = [version for version in observed_versions if version in vulnerable_set]
        remaining_paths = [
            path
            for path in evidence_paths
            if parse_package_ref(path['chain'][-1])[1] in vulnerable_set
        ]

        dependency_check = 'fail' if reachable_vulnerable_versions else 'pass'
        if not package_present:
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


def analyze_npm_lockfile(
    repo_root: Path,
    manifests: list[ManifestInfo],
    package_name: str,
    max_paths: int,
) -> tuple[bool, list[str], list[dict[str, Any]]]:
    lockfile_path = repo_root / 'package-lock.json'
    raw = load_json(lockfile_path)
    if not isinstance(raw, dict):
        raise DepAnalysisError('package-lock.json must be a JSON object.')

    packages = raw.get('packages')
    if not isinstance(packages, dict):
        raise DepAnalysisError('package-lock.json must contain a top-level packages object.')

    evidence_paths: list[dict[str, Any]] = []
    seen_paths: set[tuple[str, str, tuple[str, ...]]] = set()
    observed_versions: list[str] = []
    seen_versions: set[str] = set()
    package_present = False

    for manifest in manifests:
        importer_path = '' if manifest.relative_dir == '.' else manifest.relative_dir
        importer_entry = packages.get(importer_path)
        if not isinstance(importer_entry, dict):
            continue

        found = walk_npm_entry(
            packages=packages,
            current_path=importer_path,
            current_entry=importer_entry,
            importer_manifest=manifest,
            package_name=package_name,
            max_paths=max_paths,
            collected=evidence_paths,
            seen_paths=seen_paths,
            observed_versions=observed_versions,
            seen_versions=seen_versions,
        )
        package_present = package_present or found
        if len(evidence_paths) >= max_paths:
            break

    return package_present, observed_versions, evidence_paths


def walk_npm_entry(
    *,
    packages: dict[str, Any],
    current_path: str,
    current_entry: dict[str, Any],
    importer_manifest: ManifestInfo,
    package_name: str,
    max_paths: int,
    collected: list[dict[str, Any]],
    seen_paths: set[tuple[str, str, tuple[str, ...]]],
    observed_versions: list[str],
    seen_versions: set[str],
    trail: list[str] | None = None,
    stack: set[str] | None = None,
) -> bool:
    if len(collected) >= max_paths and observed_versions:
        return True

    dependencies = current_entry.get('dependencies')
    if not isinstance(dependencies, dict):
        return False

    found = False
    next_trail = list(trail or [])
    next_stack = set(stack or set())
    if current_path:
        next_stack.add(current_path)

    for dependency_name in dependencies:
        if not isinstance(dependency_name, str) or not dependency_name:
            continue
        resolved_path = resolve_npm_dependency_path(packages, current_path, dependency_name)
        if resolved_path is None or resolved_path in next_stack:
            continue
        dependency_entry = packages.get(resolved_path)
        if not isinstance(dependency_entry, dict):
            continue

        dependency_version = dependency_entry.get('version')
        dependency_ref = format_package_ref(
            dependency_name,
            dependency_version if isinstance(dependency_version, str) else None,
        )
        dependency_trail = next_trail + [dependency_ref]

        if dependency_name == package_name:
            if isinstance(dependency_version, str) and dependency_version and dependency_version not in seen_versions:
                seen_versions.add(dependency_version)
                observed_versions.append(dependency_version)
            record_list_evidence_path(
                importer_manifest=importer_manifest,
                chain=dependency_trail,
                collected=collected,
                seen=seen_paths,
            )
            found = True
            if len(collected) >= max_paths:
                continue

        child_found = walk_npm_entry(
            packages=packages,
            current_path=resolved_path,
            current_entry=dependency_entry,
            importer_manifest=importer_manifest,
            package_name=package_name,
            max_paths=max_paths,
            collected=collected,
            seen_paths=seen_paths,
            observed_versions=observed_versions,
            seen_versions=seen_versions,
            trail=dependency_trail,
            stack=next_stack,
        )
        found = found or child_found

    return found


def resolve_npm_dependency_path(packages: dict[str, Any], current_path: str, dependency_name: str) -> str | None:
    search_path = current_path
    seen: set[str] = set()

    while True:
        candidate = build_npm_package_path(search_path, dependency_name)
        if candidate in packages:
            return candidate
        if search_path in seen:
            return None
        seen.add(search_path)
        if search_path == '':
            return None
        search_path = npm_parent_resolution_path(search_path)


def build_npm_package_path(base_path: str, dependency_name: str) -> str:
    if not base_path:
        return f'node_modules/{dependency_name}'
    return f'{base_path}/node_modules/{dependency_name}'


def npm_parent_resolution_path(path: str) -> str:
    if '/node_modules/' in path:
        return path.rsplit('/node_modules/', 1)[0]
    if path.startswith('node_modules/'):
        return ''
    parent = PurePosixPath(path).parent.as_posix()
    return '' if parent == '.' else parent
