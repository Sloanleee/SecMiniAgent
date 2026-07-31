import logging
import sqlite3
import tempfile
import unittest
from pathlib import Path

from secminiagent.memory.migration import MigrationCapability, SchemaMigrator
from tests.memory.fixtures.schema_v1_factory import create_schema_v1_fixture
from secminiagent.memory.factory import create_schema_migrator
from secminiagent.storage.transcript import TranscriptStore


class MigrationLeakageTest(unittest.TestCase):
    def test_shadow_database_and_journal_contain_no_plaintext(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = create_schema_v1_fixture(Path(tmp))
            migrator = SchemaMigrator(
                fixture.database_path, key_provider=fixture.key_provider, workspace_id=fixture.workspace_id,
            )
            migrator.prepare_shadow(MigrationCapability.internal_test())
            raw = fixture.database_path.read_bytes()
            for canary in (
                b"synthetic first request", b"synthetic tool output", b"synthetic security finding",
            ):
                self.assertNotIn(canary, raw)
            connection = sqlite3.connect(fixture.database_path)
            rows = connection.execute(
                "SELECT phase,outcome,source_record_id_hash,target_record_id_hash FROM migration_journal_v2"
            ).fetchall()
            connection.close()
            self.assertTrue(rows)
            self.assertNotIn("synthetic", repr(rows).lower())

    def test_production_style_shadow_wal_and_errors_do_not_leak_canary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            canary = "M7_CANARY_CONTENT_7f1d9c"
            transcript = TranscriptStore(root)
            session = transcript.create()
            session.record_message({"role": "user", "content": canary})
            migrator = create_schema_migrator(root)
            migrator.prepare_shadow(MigrationCapability.internal_test())
            for path in (root / ".secminiagent" / "memory").rglob("*"):
                if path.is_file():
                    self.assertNotIn(canary.encode(), path.read_bytes(), str(path))


if __name__ == "__main__":
    unittest.main()
