import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from secminiagent.storage.transcript import TranscriptStore


class SecureTranscriptTest(unittest.TestCase):
    def test_new_session_is_encrypted_and_resumes_in_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = TranscriptStore(root)
            session = store.create()
            messages = [
                {"role": "user", "content": "first message"},
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call-1",
                            "type": "function",
                            "function": {"name": "read_file", "arguments": '{"file_path":"README.md"}'},
                        }
                    ],
                },
                {"role": "tool", "tool_call_id": "call-1", "content": "[OK]\nresult"},
                {"role": "assistant", "content": "done"},
            ]
            for message in messages:
                session.record_message(message)

            loaded = store.load(session.id)
            self.assertEqual(loaded.messages, messages)
            self.assertEqual(loaded.messages[1]["tool_calls"][0]["id"], loaded.messages[2]["tool_call_id"])
            self.assertFalse((root / ".secminiagent" / "sessions").exists())
            database = root / ".secminiagent" / "memory" / "memory.db"
            self.assertNotIn(b"first message", database.read_bytes())

    def test_secret_message_is_replaced_in_persistence_without_logging_plaintext(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = TranscriptStore(root)
            session = store.create()
            synthetic = 'password = "Synthet1c-Only-Value"'
            session.record_message({"role": "user", "content": synthetic})
            loaded = store.load(session.id)
            self.assertEqual(loaded.messages[0]["content"], "[REDACTED:SECRET]")
            for persisted_file in (root / ".secminiagent").rglob("*"):
                if persisted_file.is_file():
                    self.assertNotIn(synthetic.encode(), persisted_file.read_bytes(), str(persisted_file))

    def test_legacy_migration_is_explicit_preserving_and_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            legacy = root / ".secminiagent" / "sessions"
            legacy.mkdir(parents=True)
            session_id = "legacy-session-1"
            source = legacy / f"{session_id}.jsonl"
            events = [
                {"ts": "2026-01-01T00:00:00Z", "type": "meta", "session_id": session_id},
                {"ts": "2026-01-01T00:00:01Z", "type": "message", "message": {"role": "user", "content": "hello"}},
                {
                    "ts": "2026-01-01T00:00:02Z",
                    "type": "message",
                    "message": {"role": "user", "content": 'token = "Synthet1c-Only-Token"'},
                },
            ]
            source.write_text("\n".join(json.dumps(item) for item in events) + "\n", encoding="utf-8")

            store = TranscriptStore(root)
            first = store.migrate_legacy_sessions()
            self.assertEqual(first.migrated_sessions, 1)
            self.assertEqual(first.migrated_messages, 2)
            self.assertEqual(first.redacted_messages, 1)
            self.assertTrue(source.exists())
            self.assertEqual(len(store.load(session_id).messages), 2)

            second = store.migrate_legacy_sessions()
            self.assertEqual(second.skipped_sessions, 1)
            self.assertEqual(len(store.load(session_id).messages), 2)

    def test_legacy_source_is_deleted_only_when_explicitly_requested(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            legacy = root / ".secminiagent" / "sessions"
            legacy.mkdir(parents=True)
            source = legacy / "delete-me.jsonl"
            source.write_text('{"type":"message","message":{"role":"user","content":"hello"}}\n', encoding="utf-8")
            report = TranscriptStore(root).migrate_legacy_sessions(delete_source=True)
            self.assertEqual(report.source_files_deleted, 1)
            self.assertFalse(source.exists())


if __name__ == "__main__":
    unittest.main()
