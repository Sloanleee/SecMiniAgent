import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from secminiagent.cli import run_memory_command
from secminiagent.storage.transcript import TranscriptStore


class SchemaMigrationCLITest(unittest.TestCase):
    def test_migration_status_does_not_initialize_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(run_memory_command(["--cwd", str(root), "migration-status"]), 0)
            self.assertFalse((root / ".secminiagent").exists())
            self.assertEqual(json.loads(output.getvalue())["state"], "uninitialized")

    def test_dry_run_cli_does_not_mutate_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = TranscriptStore(root)
            session = store.create()
            session.record_message({"role": "user", "content": "synthetic cli request"})
            database = store.database_path
            before = hashlib.sha256(database.read_bytes()).digest()
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(
                    run_memory_command(["--cwd", str(root), "migrate-schema", "--to", "2", "--dry-run"]),
                    0,
                )
            self.assertEqual(before, hashlib.sha256(database.read_bytes()).digest())
            report = json.loads(output.getvalue())
            self.assertEqual(report["phase"], "dry_run")
            self.assertNotIn("synthetic cli request", output.getvalue())

    def test_production_activate_requires_an_existing_v1_source_and_creates_no_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            error = io.StringIO()
            with contextlib.redirect_stderr(error):
                self.assertEqual(run_memory_command(["--cwd", str(root), "migrate-schema", "--to", "2", "--yes"]), 1)
            self.assertIn("MIGRATION_SOURCE_UNAVAILABLE", error.getvalue())
            self.assertFalse((root / ".secminiagent").exists())

    def test_uninitialized_dry_run_creates_no_database_key_salt_or_chroma(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(
                    run_memory_command(["--cwd", str(root), "migrate-schema", "--to", "2", "--dry-run"]),
                    0,
                )
            self.assertFalse((root / ".secminiagent").exists())
            self.assertIn("SCHEMA_UNINITIALIZED", output.getvalue())


if __name__ == "__main__":
    unittest.main()
