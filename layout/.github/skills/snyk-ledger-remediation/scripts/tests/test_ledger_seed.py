from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from ledger import seed


class LedgerSeedTests(unittest.TestCase):
    def test_validate_seed_document_requires_schema(self) -> None:
        document = {
            'query': {
                'orgId': 'org-1',
                'targetId': 'target-1',
                'status': 'open',
                'issueTypes': ['package_vulnerability', 'code'],
            },
            'target': {
                'id': 'target-1',
                'displayName': 'demo-target',
            },
            'collection': {
                'fetchedAt': '2026-07-10T00:00:00Z',
                'projectCount': 0,
                'issueCount': 0,
                'advisoryCount': 0,
            },
            'issues': [],
            'advisories': [],
        }

        with self.assertRaises(seed.LedgerError) as context:
            seed.validate_seed_document(document)

        self.assertIn('$schema', str(context.exception))

    def test_validate_seed_document_accepts_target_scope(self) -> None:
        document = {
            '$schema': '../../.github/skills/snyk-session-init/schemas/issues-ledger-seed.schema.json',
            'query': {
                'orgId': 'org-1',
                'targetId': 'target-1',
                'status': 'open',
                'issueTypes': ['package_vulnerability', 'code'],
            },
            'target': {
                'id': 'target-1',
                'displayName': 'demo-target',
            },
            'collection': {
                'fetchedAt': '2026-07-10T00:00:00Z',
                'projectCount': 0,
                'issueCount': 0,
                'advisoryCount': 0,
            },
            'issues': [],
            'advisories': [],
        }

        seed.validate_seed_document(document)

    def test_cmd_init_accepts_project_scope_seed(self) -> None:
        document = {
            '$schema': '../../.github/skills/snyk-session-init/schemas/project-issues-ledger-seed.schema.json',
            'query': {
                'orgId': 'org-1',
                'projectId': 'project-1',
                'status': 'open',
                'issueTypes': ['package_vulnerability', 'code'],
            },
            'project': {
                'id': 'project-1',
                'name': 'demo-project',
                'type': 'npm',
                'kind': 'package',
                'targetId': 'target-1',
                'workspacePackage': None,
            },
            'collection': {
                'fetchedAt': '2026-07-10T00:00:00Z',
                'projectCount': 1,
                'issueCount': 0,
                'advisoryCount': 0,
            },
            'issues': [],
            'advisories': [],
        }

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            seed_path = tmp_path / 'issues-ledger-seed.json'
            output_path = tmp_path / 'issues-ledger.json'
            seed_path.write_text(json.dumps(document), encoding='utf-8')

            args = SimpleNamespace(
                from_path=str(seed_path),
                output=str(output_path),
                session_id='session-1',
            )

            with redirect_stdout(io.StringIO()):
                exit_code = seed.cmd_init(args)

            self.assertEqual(exit_code, 0)

            materialized = json.loads(output_path.read_text(encoding='utf-8'))
            self.assertEqual(materialized['$schema'], seed.LEDGER_SCHEMA_PATH)
            self.assertEqual(materialized['sessionId'], 'session-1')
            self.assertEqual(materialized['advisories'], [])

    def test_validate_seed_document_rejects_scope_schema_mismatch(self) -> None:
        document = {
            '$schema': '../../.github/skills/snyk-session-init/schemas/issues-ledger-seed.schema.json',
            'query': {
                'orgId': 'org-1',
                'projectId': 'project-1',
                'status': 'open',
                'issueTypes': ['package_vulnerability', 'code'],
            },
            'project': {
                'id': 'project-1',
                'name': 'demo-project',
                'type': 'npm',
                'kind': 'package',
                'targetId': None,
                'workspacePackage': None,
            },
            'collection': {
                'fetchedAt': '2026-07-10T00:00:00Z',
                'projectCount': 1,
                'issueCount': 0,
                'advisoryCount': 0,
            },
            'issues': [],
            'advisories': [],
        }

        with self.assertRaises(seed.LedgerError) as context:
            seed.validate_seed_document(document)

        self.assertIn("requires $schema", str(context.exception))


if __name__ == '__main__':
    unittest.main()