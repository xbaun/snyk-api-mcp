from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .adapters import ADAPTERS, resolve_adapter
from .common import (
    AnalysisContext,
    DEFAULT_MAX_PATHS,
    DepAnalysisError,
    ensure_existing_directory,
    extract_package_name,
    load_manifests,
    normalize_workspace_package,
    print_json,
    select_manifests,
)


def build_context(args: argparse.Namespace) -> AnalysisContext:
    repo_root = ensure_existing_directory(Path(args.repo_root))
    package_name = extract_package_name(args.package_name, args.purl)
    workspace_package = normalize_workspace_package(args.workspace_package)
    vulnerable_versions = tuple(getattr(args, 'vulnerable_version', None) or [])
    return AnalysisContext(
        repo_root=repo_root,
        package_name=package_name,
        workspace_package=workspace_package,
        manager=args.manager,
        max_paths=max(1, int(args.max_paths)),
        prod_only=bool(args.prod_only),
        dev_only=bool(args.dev_only),
        vulnerable_versions=vulnerable_versions,
    )


def run_command(args: argparse.Namespace, method_name: str) -> int:
    context = build_context(args)
    manifests = select_manifests(load_manifests(context.repo_root), context.workspace_package)
    adapter = resolve_adapter(context.repo_root, context.manager)
    method = getattr(adapter, method_name)
    print_json(method(context, manifests))
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    return run_command(args, 'inspect')


def cmd_trace(args: argparse.Namespace) -> int:
    return run_command(args, 'trace')


def cmd_verify(args: argparse.Namespace) -> int:
    return run_command(args, 'verify')


def add_common_args(parser: argparse.ArgumentParser, *, include_verify_args: bool = False) -> None:
    parser.add_argument('--repo-root', required=True)
    parser.add_argument('--manager', choices=sorted(ADAPTERS))
    identity_group = parser.add_mutually_exclusive_group(required=True)
    identity_group.add_argument('--package-name')
    identity_group.add_argument('--purl')
    parser.add_argument('--workspace-package')
    parser.add_argument('--max-paths', type=int, default=DEFAULT_MAX_PATHS)

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument('--prod-only', action='store_true')
    mode_group.add_argument('--dev-only', action='store_true')

    if include_verify_args:
        parser.add_argument('--vulnerable-version', action='append')


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='Deterministic dependency fact gathering and verification via package-manager adapters.'
    )
    subparsers = parser.add_subparsers(dest='command', required=True)

    inspect_parser = subparsers.add_parser('inspect', help='Build the initial dependency fact set.')
    add_common_args(inspect_parser)
    inspect_parser.set_defaults(func=cmd_inspect)

    trace_parser = subparsers.add_parser(
        'trace',
        help='Build dependency trace evidence and controllable levers.',
    )
    add_common_args(trace_parser)
    trace_parser.set_defaults(func=cmd_trace)

    verify_parser = subparsers.add_parser(
        'verify',
        help='Verify whether vulnerable versions remain reachable.',
    )
    add_common_args(verify_parser, include_verify_args=True)
    verify_parser.set_defaults(func=cmd_verify)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except DepAnalysisError as exc:
        print(f'dep.py error: {exc}', file=sys.stderr)
        return 1
