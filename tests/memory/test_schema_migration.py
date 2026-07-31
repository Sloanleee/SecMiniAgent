import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path

from secminiagent.memory.errors import MemoryIntegrityError, MemoryMigrationFailed, MemorySchemaUnsupported
from secminiagent.memory.migration import MigrationCapability, SchemaMigrator
from secminiagent.memory.migration_v1_v2 import (
    LegacyEvent, infer_legacy_runs, legacy_main_thread_id, legacy_note_mapping,
)
from secminiagent.memory.canonical import digest_provenance
from secminiagent.memory.schema import inspect_database_path, SchemaState
from secminiagent.memory.state_auth import StateAuthenticator
from secminiagent.memory.store_v2 import SQLiteV2Store
from tests.memory.fixtures.schema_v1_factory import create_schema_v1_fixture
from secminiagent.memory.factory import create_schema_migrator
from secminiagent.memory.keys import WorkspaceKeyManager
from secminiagent.storage.transcript import TranscriptStore


class SchemaMigrationTest(unittest.TestCase):
    def test_dry_run_with_missing_key_fails_without_creating_key_directory(self):
        class ReversingProtector:
            @staticmethod
            def protect(value):
                return value[::-1]

            @staticmethod
            def unprotect(value):
                return value[::-1]

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = create_schema_v1_fixture(root)
            keys_dir = root / "keys-that-must-not-be-created"
            manager = WorkspaceKeyManager(keys_dir, ReversingProtector(), create=False)
            migrator = SchemaMigrator(
                fixture.database_path, key_provider=manager, workspace_id=fixture.workspace_id,
            )
            with self.assertRaisesRegex(MemoryIntegrityError, "workspace key is unavailable"):
                migrator.dry_run()
            self.assertFalse(keys_dir.exists())

    def test_schema_v1_fixture_contains_expected_session_and_workspace_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = create_schema_v1_fixture(Path(tmp))
            connection = sqlite3.connect(fixture.database_path)
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM memories").fetchone()[0], 10)
            connection.close()

    def test_schema_v1_fixture_preserves_tool_pairs_and_never_uses_real_memory_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = create_schema_v1_fixture(Path(tmp))
            self.assertTrue(fixture.database_path.is_relative_to(Path(tmp)))
            migrator = self._migrator(fixture)
            migrator.prepare_shadow(MigrationCapability.internal_test())
            connection = sqlite3.connect(fixture.database_path)
            tool_call = connection.execute("SELECT run_id,run_sequence FROM memories_v2 WHERE id='message-2'").fetchone()
            tool_result = connection.execute("SELECT run_id,run_sequence FROM memories_v2 WHERE id='message-3'").fetchone()
            self.assertEqual(tool_call[0], tool_result[0])
            self.assertLess(tool_call[1], tool_result[1])
            note = connection.execute(
                "SELECT note_kind,verification_status,lifecycle_status FROM memories_v2 WHERE id='workspace-note'"
            ).fetchone()
            self.assertEqual(note, (None, "unknown", "candidate"))
            expected = digest_provenance((), fixture.key_provider.derive_key(fixture.workspace_id, "provenance")[0])
            self.assertEqual(
                {bytes(row[0]) for row in connection.execute("SELECT provenance_digest FROM memories_v2")},
                {expected},
            )
            connection.close()

    def test_current_public_v1_api_is_compatible_with_migration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            transcript = TranscriptStore(root)
            session = transcript.create()
            session.record_message({"role": "user", "content": "synthetic public api request"})
            session.record_message({"role": "assistant", "content": "synthetic public api answer"})
            migrator = create_schema_migrator(root)
            self.assertEqual(migrator.dry_run().runs, 1)
            self.assertTrue(migrator.prepare_shadow(MigrationCapability.internal_test()).target_records >= 3)
            self.assertTrue(migrator.verify_shadow().valid)

    def test_dry_run_does_not_modify_v1_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = create_schema_v1_fixture(Path(tmp))
            before = hashlib.sha256(fixture.database_path.read_bytes()).digest()
            report = self._migrator(fixture).dry_run()
            after = hashlib.sha256(fixture.database_path.read_bytes()).digest()
            self.assertEqual(before, after)
            self.assertEqual(report.runs, 2)
            self.assertEqual(inspect_database_path(fixture.database_path).state, SchemaState.V1)

    def test_dry_run_main_thread_id_is_deterministic(self):
        key = b"m" * 32
        self.assertEqual(legacy_main_thread_id(key, "s"), legacy_main_thread_id(key, "s"))
        self.assertNotEqual(legacy_main_thread_id(key, "s"), legacy_main_thread_id(key, "other"))

    def test_legacy_runs_are_inferred_from_top_level_user_messages(self):
        events = (
            LegacyEvent("u1", 1, "message", "user"), LegacyEvent("a1", 2, "message", "assistant"),
            LegacyEvent("u2", 3, "message", "user"), LegacyEvent("a2", 4, "message", "assistant"),
        )
        result = infer_legacy_runs(events, key=b"m" * 32, session_id="s")
        self.assertEqual(len(result.runs), 2)
        self.assertTrue(all(run.status == "completed" for run in result.runs))

    def test_unassigned_events_use_deterministic_legacy_run(self):
        result = infer_legacy_runs((LegacyEvent("a", 1, "message", "assistant"),), key=b"m" * 32, session_id="s")
        self.assertEqual(result.runs[0].migration_origin, "legacy_unassigned")

    def test_legacy_note_kind_mapping_is_conservative(self):
        self.assertEqual(legacy_note_mapping("security_finding")[0], "finding")
        self.assertEqual(legacy_note_mapping("project_fact")[0], "fact")
        self.assertEqual(legacy_note_mapping("user_note")[:3], (None, "unknown", "candidate"))

    def test_shadow_migration_reencrypts_with_v2_aad_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = create_schema_v1_fixture(Path(tmp))
            migrator = self._migrator(fixture)
            first = migrator.prepare_shadow(MigrationCapability.internal_test())
            second = migrator.resume(MigrationCapability.internal_test())
            self.assertEqual(first.target_records, 10)
            self.assertEqual(second.target_records, 10)
            self.assertTrue(migrator.verify_shadow().valid)
            connection = sqlite3.connect(fixture.database_path)
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM memories_v2").fetchone()[0], 10)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM memories WHERE scope='workspace'").fetchone()[0], 3)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM memories_v2 WHERE scope='workspace' AND session_id IS NULL").fetchone()[0], 3)
            connection.close()

    def test_normal_v2_recall_does_not_write_last_recalled_at_or_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = create_schema_v1_fixture(Path(tmp))
            migrator = self._migrator(fixture)
            migrator.prepare_shadow(MigrationCapability.internal_test())
            state_key = fixture.key_provider.derive_key(fixture.workspace_id, "state")[0]
            relation_key = fixture.key_provider.derive_key(fixture.workspace_id, "relation")[0]
            store = SQLiteV2Store(
                fixture.database_path, key_provider=fixture.key_provider,
                authenticator=StateAuthenticator(state_key, relation_key=relation_key), shadow=True,
            )
            connection = sqlite3.connect(fixture.database_path)
            before = connection.execute(
                "SELECT state_version,state_mac,last_recalled_at FROM memories_v2 WHERE id='message-1'"
            ).fetchone()
            connection.close()
            self.assertIn(b"synthetic first request", store.read_memory("message-1"))
            connection = sqlite3.connect(fixture.database_path)
            after = connection.execute(
                "SELECT state_version,state_mac,last_recalled_at FROM memories_v2 WHERE id='message-1'"
            ).fetchone()
            connection.close()
            self.assertEqual(before, after)
            self.assertIsNone(after[2])

    def test_v2_ciphertext_copy_and_bound_metadata_tampering_fail(self):
        for mutation in ("ciphertext_copy", "classification"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                fixture = create_schema_v1_fixture(Path(tmp))
                migrator = self._migrator(fixture)
                migrator.prepare_shadow(MigrationCapability.internal_test())
                state_key = fixture.key_provider.derive_key(fixture.workspace_id, "state")[0]
                relation_key = fixture.key_provider.derive_key(fixture.workspace_id, "relation")[0]
                store = SQLiteV2Store(
                    fixture.database_path, key_provider=fixture.key_provider,
                    authenticator=StateAuthenticator(state_key, relation_key=relation_key), shadow=True,
                )
                connection = sqlite3.connect(fixture.database_path)
                if mutation == "ciphertext_copy":
                    source = connection.execute("SELECT ciphertext,nonce FROM memories_v2 WHERE id='message-1'").fetchone()
                    connection.execute(
                        "UPDATE memories_v2 SET ciphertext=?,nonce=? WHERE id='message-2'", source
                    )
                    target = "message-2"
                else:
                    connection.execute("UPDATE memories_v2 SET classification='confidential' WHERE id='message-1'")
                    target = "message-1"
                connection.commit()
                connection.close()
                with self.assertRaises(MemoryIntegrityError):
                    store.read_memory(target)

    def test_cross_entity_ciphertext_copy_fails_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = create_schema_v1_fixture(Path(tmp))
            migrator = self._migrator(fixture)
            migrator.prepare_shadow(MigrationCapability.internal_test())
            connection = sqlite3.connect(fixture.database_path)
            payload = connection.execute("SELECT ciphertext,nonce FROM sessions_v2 LIMIT 1").fetchone()
            connection.execute("UPDATE threads_v2 SET ciphertext=?,nonce=?", payload)
            connection.commit()
            connection.close()
            with self.assertRaises(MemoryMigrationFailed):
                migrator.verify_shadow()

    def test_test_capability_switches_atomically_and_old_runtime_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = create_schema_v1_fixture(Path(tmp))
            migrator = self._migrator(fixture)
            migrator.prepare_shadow(MigrationCapability.internal_test())
            migrator.activate_for_test(MigrationCapability.internal_test())
            self.assertEqual(inspect_database_path(fixture.database_path).state, SchemaState.V2)
            from secminiagent.memory.store import SQLiteMemoryStore
            with self.assertRaises(MemorySchemaUnsupported):
                SQLiteMemoryStore(fixture.database_path)

    def test_production_activation_capability_is_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = create_schema_v1_fixture(Path(tmp))
            migrator = self._migrator(fixture)
            migrator.prepare_shadow(MigrationCapability.internal_test())
            with self.assertRaisesRegex(MemoryMigrationFailed, "M7_V2_RUNTIME_NOT_READY"):
                migrator.activate_for_test(MigrationCapability())

    @staticmethod
    def _migrator(fixture):
        return SchemaMigrator(
            fixture.database_path, key_provider=fixture.key_provider, workspace_id=fixture.workspace_id,
        )


if __name__ == "__main__":
    unittest.main()
