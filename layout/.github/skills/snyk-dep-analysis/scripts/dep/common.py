from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote

IGNORED_DIRS = {
    '.git',
    '.hg',
    '.idea',
    '.next',
    '.nuxt',
    '.pnpm-store',
    '.reports',
    '.synk',
    '.turbo',
    '.venv',
    '.vscode',
    'build',
    'coverage',
    'dist',
    'node_modules',
    'out',
}
DEPENDENCY_FIELDS = ('dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies')
RUNTIME_DEPENDENCY_FIELDS = ('dependencies', 'devDependencies', 'optionalDependencies')
DEFAULT_MAX_PATHS = 8


class DepAnalysisError(RuntimeError):
    pass


@dataclass(frozen=True)
class ManifestInfo:
    name: str
    manifest_path: Path
    relative_manifest_path: str
    relative_dir: str
    raw: dict[str, Any]

    def dependency_entries(
        self,
        package_name: str,
        dependency_fields: tuple[str, ...] = DEPENDENCY_FIELDS,
    ) -> list[dict[str, str]]:
        entries: list[dict[str, str]] = []
        for dependency_type in dependency_fields:
            section = self.raw.get(dependency_type)
            if isinstance(section, dict) and isinstance(section.get(package_name), str):
                entries.append(
                    {
                        'package': package_name,
                        'declaredIn': self.relative_manifest_path,
                        'dependencyType': dependency_type,
                        'declaredVersion': section[package_name],
                    }
                )
        return entries


@dataclass(frozen=True)
class AnalysisContext:
    repo_root: Path
    package_name: str
    workspace_package: str | None
    manager: str | None
    max_paths: int
    prod_only: bool
    dev_only: bool
    vulnerable_versions: tuple[str, ...]


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except FileNotFoundError as exc:
        raise DepAnalysisError(f'File not found: {path}') from exc
    except json.JSONDecodeError as exc:
        raise DepAnalysisError(f'Invalid JSON in {path}: {exc}') from exc


def print_json(data: Any) -> None:
    json.dump(data, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write('\n')


def normalize_workspace_package(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    if not normalized or normalized.lower() == 'unknown':
        return None
    return normalized


def ensure_existing_directory(path: Path) -> Path:
    resolved = path.resolve()
    if not resolved.exists() or not resolved.is_dir():
        raise DepAnalysisError(f'Repo root is not a directory: {resolved}')
    return resolved


def extract_package_name(package_name: str | None, purl: str | None) -> str:
    if package_name:
        return package_name
    if not purl:
        raise DepAnalysisError("Provide '--package-name' or '--purl'.")
    if not purl.startswith('pkg:npm/'):
        raise DepAnalysisError(f"Unsupported purl '{purl}'. Expected an npm package purl.")

    value = purl[len('pkg:npm/'):].split('?', 1)[0].split('#', 1)[0]
    if '@' in value[1:]:
        value = value.rsplit('@', 1)[0]
    package = unquote(value)
    if not package:
        raise DepAnalysisError(f"Unable to determine package name from purl '{purl}'.")
    return package


def iter_package_json_paths(repo_root: Path) -> list[Path]:
    paths: list[Path] = []
    seen: set[Path] = set()
    for path in repo_root.rglob('package.json'):
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        paths.append(resolved)
    return sorted(paths)


def load_manifests(repo_root: Path) -> list[ManifestInfo]:
    manifests: list[ManifestInfo] = []
    for manifest_path in iter_package_json_paths(repo_root):
        raw = load_json(manifest_path)
        if not isinstance(raw, dict):
            continue
        name = raw.get('name')
        if not isinstance(name, str) or not name:
            continue
        relative_manifest_path = manifest_path.relative_to(repo_root).as_posix()
        relative_dir = manifest_path.parent.relative_to(repo_root).as_posix() or '.'
        manifests.append(
            ManifestInfo(
                name=name,
                manifest_path=manifest_path,
                relative_manifest_path=relative_manifest_path,
                relative_dir=relative_dir,
                raw=raw,
            )
        )
    if not manifests:
        raise DepAnalysisError(f'No package manifests found under {repo_root}.')
    return manifests


def select_manifests(manifests: list[ManifestInfo], workspace_package: str | None) -> list[ManifestInfo]:
    if workspace_package is None:
        return manifests

    matches = [
        manifest
        for manifest in manifests
        if workspace_package in {
            manifest.name,
            manifest.relative_dir,
            manifest.relative_manifest_path,
        }
    ]
    if not matches:
        raise DepAnalysisError(
            f"No package manifest matches workspacePackage '{workspace_package}'."
        )
    return matches


def resolve_analysis_directory(repo_root: Path, manifests: list[ManifestInfo]) -> Path:
    if len(manifests) == 1:
        return manifests[0].manifest_path.parent
    return repo_root


def determine_analysis_root(repo_root: Path, manifests: list[ManifestInfo]) -> str:
    return resolve_analysis_directory(repo_root, manifests).relative_to(repo_root).as_posix() or '.'


def collect_direct_declarations(
    manifests: list[ManifestInfo],
    package_name: str,
    dependency_fields: tuple[str, ...] = DEPENDENCY_FIELDS,
) -> list[dict[str, str]]:
    declarations: list[dict[str, str]] = []
    for manifest in manifests:
        declarations.extend(manifest.dependency_entries(package_name, dependency_fields))
    return declarations


def format_package_ref(name: str, version: str | None) -> str:
    if version:
        return f'{name}@{version}'
    return name


def parse_package_ref(value: str) -> tuple[str, str | None]:
    if '@' not in value[1:]:
        return value, None
    name, version = value.rsplit('@', 1)
    return name, version or None
