from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from ..common import (
    AnalysisContext,
    DepAnalysisError,
    ManifestInfo,
    RUNTIME_DEPENDENCY_FIELDS,
    format_package_ref,
    parse_package_ref,
)


class PackageManagerAdapter(ABC):
    name: str
    supported: bool = True

    @abstractmethod
    def detect_score(self, repo_root: Path) -> int:
        raise NotImplementedError

    def ensure_supported(self) -> None:
        if not self.supported:
            raise DepAnalysisError(
                f"Manager '{self.name}' was selected but is not implemented yet. "
                'Add a dedicated adapter instead of falling back to manual lockfile reading.'
            )

    @abstractmethod
    def inspect(self, context: AnalysisContext, manifests: list[ManifestInfo]) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def trace(self, context: AnalysisContext, manifests: list[ManifestInfo]) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def verify(self, context: AnalysisContext, manifests: list[ManifestInfo]) -> dict[str, Any]:
        raise NotImplementedError


def collect_observed_versions(graph: list[dict[str, Any]]) -> list[str]:
    versions: list[str] = []
    seen: set[str] = set()
    for node in graph:
        version = node.get('version')
        if isinstance(version, str) and version and version not in seen:
            seen.add(version)
            versions.append(version)
    return versions


def manifest_lookup(manifests: list[ManifestInfo]) -> dict[str, ManifestInfo]:
    return {manifest.name: manifest for manifest in manifests}


def collect_evidence_paths(
    graph: list[dict[str, Any]],
    manifests: list[ManifestInfo],
    max_paths: int,
) -> list[dict[str, Any]]:
    lookup = manifest_lookup(manifests)
    collected: list[dict[str, Any]] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()

    def walk(node: dict[str, Any], trail: list[str]) -> None:
        if len(collected) >= max_paths:
            return

        dep_field = node.get('depField')
        if isinstance(dep_field, str):
            importer_name = node.get('name')
            if isinstance(importer_name, str) and importer_name:
                reversed_trail = list(reversed(trail))
                chain = reversed_trail[1:]
                if chain:
                    key = (importer_name, dep_field, tuple(chain))
                    if key not in seen:
                        seen.add(key)
                        importer_manifest = lookup.get(importer_name)
                        collected.append(
                            {
                                'importer': importer_name,
                                'importerPath': importer_manifest.relative_dir if importer_manifest else 'unknown',
                                'dependencyType': dep_field,
                                'directDependency': chain[0],
                                'chain': chain,
                            }
                        )
                        if len(collected) >= max_paths:
                            return

        dependents = node.get('dependents')
        if not isinstance(dependents, list):
            return
        for dependent in dependents:
            if not isinstance(dependent, dict):
                continue
            dependent_name = dependent.get('name')
            if not isinstance(dependent_name, str) or not dependent_name:
                continue
            dependent_version = dependent.get('version')
            dependent_ref = format_package_ref(
                dependent_name,
                dependent_version if isinstance(dependent_version, str) else None,
            )
            walk(dependent, trail + [dependent_ref])

    for root in graph:
        if not isinstance(root, dict):
            continue
        root_name = root.get('name')
        if not isinstance(root_name, str) or not root_name:
            continue
        root_version = root.get('version')
        root_ref = format_package_ref(
            root_name,
            root_version if isinstance(root_version, str) else None,
        )
        walk(root, [root_ref])
        if len(collected) >= max_paths:
            break

    return collected


def collect_reachable_importers(evidence_paths: list[dict[str, Any]]) -> list[dict[str, str]]:
    importers: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for path in evidence_paths:
        importer = path.get('importer')
        importer_path = path.get('importerPath')
        if not isinstance(importer, str) or not isinstance(importer_path, str):
            continue
        key = (importer, importer_path)
        if key in seen:
            continue
        seen.add(key)
        importers.append({'name': importer, 'path': importer_path})
    return importers


def collect_list_evidence_paths(
    trees: list[dict[str, Any]],
    manifests: list[ManifestInfo],
    package_name: str,
    max_paths: int,
) -> list[dict[str, Any]]:
    lookup = manifest_lookup(manifests)
    collected: list[dict[str, Any]] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()

    for tree in trees:
        importer_name = tree.get('name')
        if not isinstance(importer_name, str) or not importer_name:
            continue
        importer_manifest = lookup.get(importer_name)
        if importer_manifest is None:
            continue

        walk_list_tree(
            tree=tree,
            importer_manifest=importer_manifest,
            package_name=package_name,
            collected=collected,
            seen=seen,
            max_paths=max_paths,
        )
        if len(collected) >= max_paths:
            break

    return collected


def walk_list_tree(
    *,
    tree: dict[str, Any],
    importer_manifest: ManifestInfo,
    package_name: str,
    collected: list[dict[str, Any]],
    seen: set[tuple[str, str, tuple[str, ...]]],
    max_paths: int,
    trail: list[str] | None = None,
) -> None:
    if len(collected) >= max_paths:
        return

    dependencies = tree.get('dependencies')
    if not isinstance(dependencies, dict):
        return

    next_trail = list(trail or [])
    for dependency_name, dependency in dependencies.items():
        if not isinstance(dependency_name, str) or not dependency_name:
            continue
        if not isinstance(dependency, dict):
            continue

        dependency_version = dependency.get('version')
        dependency_ref = format_package_ref(
            dependency_name,
            dependency_version if isinstance(dependency_version, str) else None,
        )
        dependency_trail = next_trail + [dependency_ref]

        if dependency_name == package_name:
            record_list_evidence_path(
                importer_manifest=importer_manifest,
                chain=dependency_trail,
                collected=collected,
                seen=seen,
            )
            if len(collected) >= max_paths:
                return

        walk_list_tree(
            tree=dependency,
            importer_manifest=importer_manifest,
            package_name=package_name,
            collected=collected,
            seen=seen,
            max_paths=max_paths,
            trail=dependency_trail,
        )
        if len(collected) >= max_paths:
            return


def record_list_evidence_path(
    *,
    importer_manifest: ManifestInfo,
    chain: list[str],
    collected: list[dict[str, Any]],
    seen: set[tuple[str, str, tuple[str, ...]]],
) -> None:
    if not chain:
        return

    direct_dependency_name, _direct_dependency_version = parse_package_ref(chain[0])
    dependency_entries = importer_manifest.dependency_entries(direct_dependency_name)
    dependency_type = dependency_entries[0]['dependencyType'] if dependency_entries else 'unknown'
    key = (importer_manifest.name, dependency_type, tuple(chain))
    if key in seen:
        return

    seen.add(key)
    collected.append(
        {
            'importer': importer_manifest.name,
            'importerPath': importer_manifest.relative_dir,
            'dependencyType': dependency_type,
            'directDependency': chain[0],
            'chain': chain,
        }
    )


def build_controllable_parents(
    manifests: list[ManifestInfo],
    direct_declarations: list[dict[str, str]],
    evidence_paths: list[dict[str, Any]],
    package_name: str,
) -> list[dict[str, str]]:
    parents: list[dict[str, str]] = []
    seen: set[tuple[str, str, str, str]] = set()

    for declaration in direct_declarations:
        key = (
            declaration['package'],
            declaration['declaredIn'],
            declaration['dependencyType'],
            declaration['declaredVersion'],
        )
        if key in seen:
            continue
        seen.add(key)
        parents.append(dict(declaration))

    for path in evidence_paths:
        direct_dependency = path.get('directDependency')
        importer = path.get('importer')
        if not isinstance(direct_dependency, str) or not isinstance(importer, str):
            continue
        dependency_name, _dependency_version = parse_package_ref(direct_dependency)
        if dependency_name == package_name:
            continue
        importer_manifest = next((manifest for manifest in manifests if manifest.name == importer), None)
        if importer_manifest is None:
            continue
        for declaration in importer_manifest.dependency_entries(
            dependency_name,
            RUNTIME_DEPENDENCY_FIELDS,
        ):
            key = (
                declaration['package'],
                declaration['declaredIn'],
                declaration['dependencyType'],
                declaration['declaredVersion'],
            )
            if key in seen:
                continue
            seen.add(key)
            parents.append(dict(declaration))

    return parents


def determine_dep_origin(
    package_name: str,
    direct_declarations: list[dict[str, str]],
    evidence_paths: list[dict[str, Any]],
) -> str:
    has_direct = bool(direct_declarations)
    has_transitive = False

    for path in evidence_paths:
        direct_dependency = path.get('directDependency')
        if not isinstance(direct_dependency, str) or not direct_dependency:
            continue
        direct_dependency_name, _direct_dependency_version = parse_package_ref(direct_dependency)
        if direct_dependency_name == package_name:
            has_direct = True
        else:
            has_transitive = True

    if has_direct and has_transitive:
        return 'mixed'
    if has_direct:
        return 'direct'
    return 'transitive'


def build_candidate_levers(
    package_name: str,
    package_present: bool,
    direct_declarations: list[dict[str, str]],
    controllable_parents: list[dict[str, str]],
) -> list[str]:
    candidate_levers: list[str] = []
    if direct_declarations:
        candidate_levers.append('update-direct')
    if any(parent['package'] != package_name for parent in controllable_parents):
        candidate_levers.append('update-parent')
    if package_present and not direct_declarations:
        candidate_levers.append('temp-override')
    return candidate_levers


__all__ = [
    'PackageManagerAdapter',
    'build_candidate_levers',
    'build_controllable_parents',
    'collect_evidence_paths',
    'collect_list_evidence_paths',
    'collect_observed_versions',
    'collect_reachable_importers',
    'determine_dep_origin',
    'record_list_evidence_path',
    'walk_list_tree',
]
