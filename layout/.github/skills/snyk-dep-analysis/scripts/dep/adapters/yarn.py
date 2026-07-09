from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..common import (
    AnalysisContext,
    DEPENDENCY_FIELDS,
    DepAnalysisError,
    ManifestInfo,
    RUNTIME_DEPENDENCY_FIELDS,
    collect_direct_declarations,
    determine_analysis_root,
    format_package_ref,
    parse_package_ref,
)
from ._shared import (
    PackageManagerAdapter,
    build_candidate_levers,
    build_controllable_parents,
    collect_reachable_importers,
    record_list_evidence_path,
)


YARN_DEP_LINE_RE = re.compile(r'^("[^"]+"|[^ ]+) ("[^"]+"|[^ ]+)$')


@dataclass(frozen=True)
class YarnLockEntry:
    version: str
    dependencies: dict[str, str]


@dataclass(frozen=True)
class SemverVersion:
    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...] = ()


class YarnAdapter(PackageManagerAdapter):
    name = 'yarn'

    def detect_score(self, repo_root: Path) -> int:
        return 50 if (repo_root / 'yarn.lock').exists() else 0

    def inspect(self, context: AnalysisContext, manifests: list[ManifestInfo]) -> dict[str, Any]:
        package_present, observed_versions, evidence_paths = analyze_yarn_lockfile(
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
        package_present, _observed_versions, evidence_paths = analyze_yarn_lockfile(
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
                f"Package '{context.package_name}' is present in the Yarn lockfile graph, but no dependency path "
                'could be reconstructed from yarn.lock.'
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
            'controllableParents': controllable_parents,
            'evidencePaths': evidence_paths,
            'candidateLevers': candidate_levers,
        }

    def verify(self, context: AnalysisContext, manifests: list[ManifestInfo]) -> dict[str, Any]:
        if not context.vulnerable_versions:
            raise DepAnalysisError("verify requires at least one '--vulnerable-version'.")

        package_present, observed_versions, evidence_paths = analyze_yarn_lockfile(
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


def analyze_yarn_lockfile(
    repo_root: Path,
    manifests: list[ManifestInfo],
    package_name: str,
    max_paths: int,
) -> tuple[bool, list[str], list[dict[str, Any]]]:
    entries = parse_yarn_lockfile(repo_root / 'yarn.lock')
    selector_index = build_yarn_selector_index(entries)
    candidate_cache: dict[tuple[str, str], list[tuple[str, YarnLockEntry]]] = {}
    evidence_paths: list[dict[str, Any]] = []
    seen_paths: set[tuple[str, str, tuple[str, ...]]] = set()
    observed_versions: list[str] = []
    seen_versions: set[str] = set()
    package_present = False

    for manifest in manifests:
        found = walk_yarn_manifest(
            entries=entries,
            selector_index=selector_index,
            candidate_cache=candidate_cache,
            manifest=manifest,
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


def walk_yarn_manifest(
    *,
    entries: dict[str, YarnLockEntry],
    selector_index: dict[str, list[str]],
    candidate_cache: dict[tuple[str, str], list[tuple[str, YarnLockEntry]]],
    manifest: ManifestInfo,
    package_name: str,
    max_paths: int,
    collected: list[dict[str, Any]],
    seen_paths: set[tuple[str, str, tuple[str, ...]]],
    observed_versions: list[str],
    seen_versions: set[str],
) -> bool:
    found = False

    for dependency_name, dependency_spec, _dependency_type in iter_manifest_dependency_specs(
        manifest,
        RUNTIME_DEPENDENCY_FIELDS,
    ):
        candidates = resolve_yarn_candidates(
            entries,
            selector_index,
            candidate_cache,
            dependency_name,
            dependency_spec,
        )
        for selector, entry in candidates:
            dependency_ref = format_package_ref(dependency_name, entry.version or None)
            dependency_trail = [dependency_ref]
            if dependency_name == package_name:
                if entry.version and entry.version not in seen_versions:
                    seen_versions.add(entry.version)
                    observed_versions.append(entry.version)
                record_list_evidence_path(
                    importer_manifest=manifest,
                    chain=dependency_trail,
                    collected=collected,
                    seen=seen_paths,
                )
                found = True
                if len(collected) >= max_paths:
                    continue

            child_found = walk_yarn_entry(
                entries=entries,
                selector_index=selector_index,
                candidate_cache=candidate_cache,
                entry=entry,
                importer_manifest=manifest,
                package_name=package_name,
                max_paths=max_paths,
                collected=collected,
                seen_paths=seen_paths,
                observed_versions=observed_versions,
                seen_versions=seen_versions,
                trail=dependency_trail,
                stack={selector},
            )
            found = found or child_found

    return found


def walk_yarn_entry(
    *,
    entries: dict[str, YarnLockEntry],
    selector_index: dict[str, list[str]],
    candidate_cache: dict[tuple[str, str], list[tuple[str, YarnLockEntry]]],
    entry: YarnLockEntry,
    importer_manifest: ManifestInfo,
    package_name: str,
    max_paths: int,
    collected: list[dict[str, Any]],
    seen_paths: set[tuple[str, str, tuple[str, ...]]],
    observed_versions: list[str],
    seen_versions: set[str],
    trail: list[str],
    stack: set[str],
) -> bool:
    if len(collected) >= max_paths and observed_versions:
        return True

    found = False
    for dependency_name, dependency_spec in entry.dependencies.items():
        candidates = resolve_yarn_candidates(
            entries,
            selector_index,
            candidate_cache,
            dependency_name,
            dependency_spec,
        )
        for selector, dependency_entry in candidates:
            if selector in stack:
                continue

            dependency_ref = format_package_ref(dependency_name, dependency_entry.version or None)
            dependency_trail = trail + [dependency_ref]

            if dependency_name == package_name:
                if dependency_entry.version and dependency_entry.version not in seen_versions:
                    seen_versions.add(dependency_entry.version)
                    observed_versions.append(dependency_entry.version)
                record_list_evidence_path(
                    importer_manifest=importer_manifest,
                    chain=dependency_trail,
                    collected=collected,
                    seen=seen_paths,
                )
                found = True
                if len(collected) >= max_paths:
                    continue

            child_found = walk_yarn_entry(
                entries=entries,
                selector_index=selector_index,
                candidate_cache=candidate_cache,
                entry=dependency_entry,
                importer_manifest=importer_manifest,
                package_name=package_name,
                max_paths=max_paths,
                collected=collected,
                seen_paths=seen_paths,
                observed_versions=observed_versions,
                seen_versions=seen_versions,
                trail=dependency_trail,
                stack=stack | {selector},
            )
            found = found or child_found

    return found


def parse_yarn_lockfile(path: Path) -> dict[str, YarnLockEntry]:
    try:
        lines = path.read_text(encoding='utf-8').splitlines()
    except FileNotFoundError as exc:
        raise DepAnalysisError(f'File not found: {path}') from exc

    selectors_to_entries: dict[str, YarnLockEntry] = {}
    line_index = 0
    lockfile_version_seen = False

    while line_index < len(lines):
        line = lines[line_index]
        stripped = line.strip()
        if not stripped:
            line_index += 1
            continue
        if stripped.startswith('#'):
            if stripped == '# yarn lockfile v1':
                lockfile_version_seen = True
            line_index += 1
            continue
        if line.startswith(' '):
            line_index += 1
            continue
        if not line.endswith(':'):
            raise DepAnalysisError(f'Unsupported yarn.lock syntax near line {line_index + 1}.')

        selectors = split_yarn_selectors(line[:-1])
        version = ''
        dependencies: dict[str, str] = {}
        line_index += 1

        while line_index < len(lines):
            inner_line = lines[line_index]
            inner_stripped = inner_line.strip()
            if not inner_stripped:
                line_index += 1
                continue
            if not inner_line.startswith('  '):
                break
            if inner_stripped.startswith('version '):
                version = parse_yarn_value(inner_stripped[len('version '):])
                line_index += 1
                continue
            if inner_stripped in {'dependencies:', 'optionalDependencies:'}:
                line_index += 1
                while line_index < len(lines):
                    dependency_line = lines[line_index]
                    dependency_stripped = dependency_line.strip()
                    if not dependency_stripped:
                        line_index += 1
                        continue
                    if not dependency_line.startswith('    '):
                        break
                    dependency_name, dependency_spec = parse_yarn_dependency_line(dependency_stripped)
                    dependencies[dependency_name] = dependency_spec
                    line_index += 1
                continue
            line_index += 1

        entry = YarnLockEntry(version=version, dependencies=dependencies)
        for selector in selectors:
            selectors_to_entries[selector] = entry

    if not lockfile_version_seen:
        raise DepAnalysisError('Only Yarn Classic lockfile v1 is currently supported.')

    return selectors_to_entries


def split_yarn_selectors(raw: str) -> list[str]:
    selectors: list[str] = []
    current: list[str] = []
    in_quotes = False

    for character in raw:
        if character == '"':
            in_quotes = not in_quotes
            current.append(character)
            continue
        if character == ',' and not in_quotes:
            selector = ''.join(current).strip()
            if selector:
                selectors.append(parse_yarn_value(selector))
            current = []
            continue
        current.append(character)

    selector = ''.join(current).strip()
    if selector:
        selectors.append(parse_yarn_value(selector))
    return selectors


def parse_yarn_dependency_line(raw: str) -> tuple[str, str]:
    match = YARN_DEP_LINE_RE.match(raw)
    if match is None:
        raise DepAnalysisError(f'Unsupported yarn.lock dependency line: {raw}')
    return parse_yarn_value(match.group(1)), parse_yarn_value(match.group(2))


def parse_yarn_value(raw: str) -> str:
    value = raw.strip()
    if value.startswith('"') and value.endswith('"') and len(value) >= 2:
        return value[1:-1]
    return value


def build_yarn_selector(dependency_name: str, dependency_spec: str) -> str:
    return f'{dependency_name}@{dependency_spec}'


def build_yarn_selector_index(entries: dict[str, YarnLockEntry]) -> dict[str, list[str]]:
    index: dict[str, list[str]] = {}
    for selector in entries:
        package_name, _package_spec = parse_package_ref(selector)
        index.setdefault(package_name, []).append(selector)
    for selectors in index.values():
        selectors.sort()
    return index


def resolve_yarn_candidates(
    entries: dict[str, YarnLockEntry],
    selector_index: dict[str, list[str]],
    candidate_cache: dict[tuple[str, str], list[tuple[str, YarnLockEntry]]],
    dependency_name: str,
    dependency_spec: str,
) -> list[tuple[str, YarnLockEntry]]:
    cache_key = (dependency_name, dependency_spec)
    cached = candidate_cache.get(cache_key)
    if cached is not None:
        return cached

    exact_selector = build_yarn_selector(dependency_name, dependency_spec)
    exact_entry = entries.get(exact_selector)
    if exact_entry is not None:
        candidate_cache[cache_key] = [(exact_selector, exact_entry)]
        return candidate_cache[cache_key]

    candidates: list[tuple[str, YarnLockEntry]] = []
    seen_entries: set[int] = set()
    for selector in selector_index.get(dependency_name, []):
        entry = entries[selector]
        if not version_satisfies_selector(entry.version, dependency_spec):
            continue
        entry_id = id(entry)
        if entry_id in seen_entries:
            continue
        seen_entries.add(entry_id)
        candidates.append((selector, entry))

    candidate_cache[cache_key] = candidates
    return candidates


def parse_semver(value: str) -> SemverVersion | None:
    normalized = value.strip()
    if normalized.startswith('='):
        normalized = normalized[1:].strip()
    match = re.match(r'^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+.*)?$', normalized)
    if match is None:
        return None
    prerelease = tuple(part for part in (match.group(4) or '').split('.') if part)
    return SemverVersion(
        major=int(match.group(1)),
        minor=int(match.group(2) or '0'),
        patch=int(match.group(3) or '0'),
        prerelease=prerelease,
    )


def compare_semver(left: SemverVersion, right: SemverVersion) -> int:
    left_core = (left.major, left.minor, left.patch)
    right_core = (right.major, right.minor, right.patch)
    if left_core < right_core:
        return -1
    if left_core > right_core:
        return 1
    if not left.prerelease and not right.prerelease:
        return 0
    if not left.prerelease:
        return 1
    if not right.prerelease:
        return -1

    for left_part, right_part in zip(left.prerelease, right.prerelease):
        left_numeric = left_part.isdigit()
        right_numeric = right_part.isdigit()
        if left_numeric and right_numeric:
            left_value = int(left_part)
            right_value = int(right_part)
            if left_value < right_value:
                return -1
            if left_value > right_value:
                return 1
            continue
        if left_numeric != right_numeric:
            return -1 if left_numeric else 1
        if left_part < right_part:
            return -1
        if left_part > right_part:
            return 1

    if len(left.prerelease) < len(right.prerelease):
        return -1
    if len(left.prerelease) > len(right.prerelease):
        return 1
    return 0


def version_satisfies_selector(version: str, selector: str) -> bool:
    normalized_selector = selector.strip()
    if not normalized_selector or normalized_selector in {'*', 'x', 'X'}:
        return True
    if normalized_selector.startswith(('workspace:', 'file:', 'link:', 'portal:', 'patch:', 'npm:')):
        return False

    version_semver = parse_semver(version)
    if version_semver is None:
        return False

    for branch in normalized_selector.split('||'):
        if branch_satisfied(version_semver, branch.strip()):
            return True
    return False


def branch_satisfied(version: SemverVersion, branch: str) -> bool:
    if not branch or branch in {'*', 'x', 'X'}:
        return True

    if ' - ' in branch:
        lower_raw, upper_raw = branch.split(' - ', 1)
        lower = parse_semver(lower_raw)
        upper = parse_semver(upper_raw)
        if lower is None or upper is None:
            return False
        return compare_semver(version, lower) >= 0 and compare_semver(version, upper) <= 0

    if ' ' in branch:
        tokens = [token for token in branch.split() if token]
        return all(token_satisfied(version, token) for token in tokens)
    return token_satisfied(version, branch)


def token_satisfied(version: SemverVersion, token: str) -> bool:
    if token in {'*', 'x', 'X'}:
        return True
    if token.startswith('^'):
        lower = parse_semver(token[1:])
        if lower is None or compare_semver(version, lower) < 0:
            return False
        if lower.major > 0:
            upper = SemverVersion(lower.major + 1, 0, 0)
        elif lower.minor > 0:
            upper = SemverVersion(0, lower.minor + 1, 0)
        else:
            upper = SemverVersion(0, 0, lower.patch + 1)
        return compare_semver(version, upper) < 0
    if token.startswith('~'):
        lower = parse_semver(token[1:])
        if lower is None or compare_semver(version, lower) < 0:
            return False
        upper = SemverVersion(lower.major, lower.minor + 1, 0)
        return compare_semver(version, upper) < 0

    for operator in ('>=', '<=', '>', '<'):
        if token.startswith(operator):
            bound = parse_semver(token[len(operator):])
            if bound is None:
                return False
            if operator == '>=':
                return compare_semver(version, bound) >= 0
            if operator == '<=':
                return compare_semver(version, bound) <= 0
            if operator == '>':
                return compare_semver(version, bound) > 0
            return compare_semver(version, bound) < 0

    if any(marker in token for marker in ('*', 'x', 'X')):
        return wildcard_token_satisfied(version, token)

    exact = parse_semver(token)
    if exact is None:
        return False
    return compare_semver(version, exact) == 0


def wildcard_token_satisfied(version: SemverVersion, token: str) -> bool:
    normalized = token.strip()
    if normalized.startswith('='):
        normalized = normalized[1:].strip()
    if normalized.startswith('v'):
        normalized = normalized[1:]

    parts = normalized.split('.')
    version_parts = (version.major, version.minor, version.patch)
    for index, part in enumerate(parts[:3]):
        if part in {'*', 'x', 'X'}:
            return True
        if not part.isdigit() or version_parts[index] != int(part):
            return False
    return True


def iter_manifest_dependency_specs(
    manifest: ManifestInfo,
    dependency_fields: tuple[str, ...] = DEPENDENCY_FIELDS,
) -> list[tuple[str, str, str]]:
    dependencies: list[tuple[str, str, str]] = []
    for dependency_type in dependency_fields:
        section = manifest.raw.get(dependency_type)
        if not isinstance(section, dict):
            continue
        for dependency_name, dependency_spec in section.items():
            if not isinstance(dependency_name, str) or not dependency_name:
                continue
            if not isinstance(dependency_spec, str) or not dependency_spec:
                continue
            dependencies.append((dependency_name, dependency_spec, dependency_type))
    return dependencies
