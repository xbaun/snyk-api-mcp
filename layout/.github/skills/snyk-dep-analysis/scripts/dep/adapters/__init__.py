from __future__ import annotations

from pathlib import Path

from ..common import DepAnalysisError
from ._shared import (
    PackageManagerAdapter,
    build_candidate_levers,
    build_controllable_parents,
    collect_evidence_paths,
    collect_list_evidence_paths,
    collect_observed_versions,
    collect_reachable_importers,
    record_list_evidence_path,
    walk_list_tree,
)
from .npm import NpmAdapter
from .pnpm import PnpmAdapter
from .yarn import YarnAdapter


ADAPTERS: dict[str, PackageManagerAdapter] = {
    adapter.name: adapter
    for adapter in (
        PnpmAdapter(),
        NpmAdapter(),
        YarnAdapter(),
    )
}


def resolve_adapter(repo_root: Path, manager: str | None) -> PackageManagerAdapter:
    if manager:
        adapter = ADAPTERS.get(manager)
        if adapter is None:
            raise DepAnalysisError(
                f"Unsupported manager '{manager}'. Available adapters: {', '.join(sorted(ADAPTERS))}."
            )
        adapter.ensure_supported()
        return adapter

    scored = [
        (score, adapter)
        for adapter in ADAPTERS.values()
        if (score := adapter.detect_score(repo_root)) > 0
    ]
    if not scored:
        raise DepAnalysisError(
            'Unable to detect a supported package manager from repo files. '
            'Provide --manager explicitly or add a dedicated adapter.'
        )

    scored.sort(key=lambda item: item[0], reverse=True)
    best_score, best_adapter = scored[0]
    competing = [adapter.name for score, adapter in scored if score == best_score]
    if len(competing) > 1:
        raise DepAnalysisError(
            f"Ambiguous package manager detection: {', '.join(sorted(competing))}. Provide --manager explicitly."
        )
    best_adapter.ensure_supported()
    return best_adapter


__all__ = [
    'ADAPTERS',
    'NpmAdapter',
    'PackageManagerAdapter',
    'PnpmAdapter',
    'YarnAdapter',
    'build_candidate_levers',
    'build_controllable_parents',
    'collect_evidence_paths',
    'collect_list_evidence_paths',
    'collect_observed_versions',
    'collect_reachable_importers',
    'record_list_evidence_path',
    'resolve_adapter',
    'walk_list_tree',
]
