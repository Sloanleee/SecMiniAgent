import sqlite3
import tempfile
import unittest
from pathlib import Path

from secminiagent.memory.errors import MemoryMigrationConflict, MemoryMigrationFailed, MemoryStateIntegrityError
from secminiagent.memory.migration import MigrationCapability, SchemaMigrator
from tests.memory.fixtures.schema_v1_factory import create_schema_v1_fixture


class InjectedFailure(RuntimeError):
    pass


class SchemaMigrationRecoveryTest(unittest.TestCase):
    def test_each_failpoint_keeps_v1_authoritative_and_resume_has_no_duplicates(self):
        for point in ("after_prepare", "after_thread", "after_run", "after_memory", "after_relation", "before_verify", "after_verify"):
            with self.subTest(point=point), tempfile.TemporaryDirectory() as tmp:
                fixture = create_schema_v1_fixture(Path(tmp))
                def fail(name, _reason):
                    if name == point:
                        raise InjectedFailure(point)
                migrator = SchemaMigrator(
                    fixture.database_path, key_provider=fixture.key_provider,
                    workspace_id=fixture.workspace_id, failpoint=fail,
                )
                with self.assertRaises(InjectedFailure):
                    migrator.prepare_shadow(MigrationCapability.internal_test())
                connection = sqlite3.connect(fixture.database_path)
                self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 1)
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM memories").fetchone()[0], 10)
                connection.close()
                resumed = SchemaMigrator(
                    fixture.database_path, key_provider=fixture.key_provider, workspace_id=fixture.workspace_id,
                ).resume(MigrationCapability.internal_test())
                self.assertEqual(resumed.target_records, 10)

    def test_during_switch_rolls_back_to_v1(self):
        for point in ("before_switch", "during_switch"):
            with self.subTest(point=point), tempfile.TemporaryDirectory() as tmp:
                fixture = create_schema_v1_fixture(Path(tmp))
                base = SchemaMigrator(fixture.database_path, key_provider=fixture.key_provider, workspace_id=fixture.workspace_id)
                base.prepare_shadow(MigrationCapability.internal_test())
                def fail(name, _reason):
                    if name == point:
                        raise InjectedFailure(name)
                switching = SchemaMigrator(
                    fixture.database_path, key_provider=fixture.key_provider, workspace_id=fixture.workspace_id, failpoint=fail,
                )
                with self.assertRaises(InjectedFailure):
                    switching.activate_for_test(MigrationCapability.internal_test())
                connection = sqlite3.connect(fixture.database_path)
                self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 1)
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM memories").fetchone()[0], 10)
                connection.close()

    def test_tampered_journal_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = create_schema_v1_fixture(Path(tmp))
            migrator = SchemaMigrator(fixture.database_path, key_provider=fixture.key_provider, workspace_id=fixture.workspace_id)
            migrator.prepare_shadow(MigrationCapability.internal_test())
            connection = sqlite3.connect(fixture.database_path)
            connection.execute("UPDATE migration_journal_v2 SET phase='switched' WHERE phase='prepared'")
            connection.commit()
            connection.close()
            with self.assertRaises(MemoryMigrationFailed):
                migrator.verify_shadow()

    def test_two_migration_writers_conflict(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = create_schema_v1_fixture(Path(tmp))
            locker = sqlite3.connect(fixture.database_path)
            locker.execute("BEGIN IMMEDIATE")
            try:
                migrator = SchemaMigrator(fixture.database_path, key_provider=fixture.key_provider, workspace_id=fixture.workspace_id)
                with self.assertRaises(MemoryMigrationConflict):
                    migrator.prepare_shadow(MigrationCapability.internal_test())
            finally:
                locker.rollback()
                locker.close()

    def test_v1_write_after_plan_invalidates_shadow_before_switch(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = create_schema_v1_fixture(Path(tmp))
            migrator = SchemaMigrator(fixture.database_path, key_provider=fixture.key_provider, workspace_id=fixture.workspace_id)
            migrator.prepare_shadow(MigrationCapability.internal_test())
            connection = sqlite3.connect(fixture.database_path)
            connection.execute("UPDATE memories SET index_status='index_failed' WHERE id='workspace-note'")
            connection.commit()
            connection.close()
            # Snapshot intentionally excludes mutable index status; changing an authority-bound row identity marker must invalidate.
            connection = sqlite3.connect(fixture.database_path)
            connection.execute("UPDATE memories SET created_at='2027-01-01T00:00:00+00:00' WHERE id='workspace-note'")
            connection.commit()
            connection.close()
            self.assertFalse(migrator.verify_shadow().valid)


if __name__ == "__main__":
    unittest.main()
