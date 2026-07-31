import sqlite3
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from secminiagent.memory.cascade_delete import CascadeDeletionService
from secminiagent.memory.errors import MemoryConfirmationRequired, MemoryIntegrityError
from secminiagent.memory.models import MemoryScope, NoteKind
from secminiagent.memory.search import HybridMemorySearch
from tests.memory.m7_lifecycle_helpers import create_long_term_service


class M7SecurityAdversarialTest(unittest.TestCase):
    def test_deletion_token_tamper_and_snapshot_change_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, store, lifecycle, _, long_term, context = create_long_term_service(Path(tmp))
            thread = lifecycle.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            long_term.add_note(bound, "deletion snapshot source", MemoryScope.THREAD, NoteKind.FACT)
            deletion = CascadeDeletionService(long_term, deletion_key=store.key_provider.derive_key(context.workspace_id, "deletion")[0])
            preview = deletion.preview(bound, "thread", thread.thread_id)
            offset = len(preview.confirmation_token) // 2
            tampered = preview.confirmation_token[:offset] + ("A" if preview.confirmation_token[offset] != "A" else "B") + preview.confirmation_token[offset + 1:]
            with self.assertRaises(MemoryConfirmationRequired):
                deletion.execute(bound, "thread", thread.thread_id, tampered)
            long_term.add_note(bound, "snapshot changed", MemoryScope.THREAD, NoteKind.FACT)
            with self.assertRaises(MemoryConfirmationRequired):
                deletion.execute(bound, "thread", thread.thread_id, preview.confirmation_token)

    def test_ciphertext_and_state_copy_attack_never_returns_plaintext(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, _, lifecycle, _, long_term, context = create_long_term_service(Path(tmp))
            thread = lifecycle.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            first = long_term.add_note(bound, "first protected body", MemoryScope.THREAD, NoteKind.FACT)
            second = long_term.add_note(bound, "second protected body", MemoryScope.THREAD, NoteKind.FACT)
            connection = sqlite3.connect(path)
            try:
                source = connection.execute("SELECT ciphertext,nonce FROM memories WHERE id=?", (first.note_id,)).fetchone()
                connection.execute("UPDATE memories SET ciphertext=?,nonce=? WHERE id=?", (*source, second.note_id))
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(MemoryIntegrityError):
                long_term.get_note(bound, second.note_id)
            hits = HybridMemorySearch(long_term.store, long_term.lifecycle_store).search(bound, "protected body")
            self.assertEqual(tuple(item.memory_id for item in hits), (first.note_id,))

    def test_database_wal_journal_and_temp_surfaces_have_no_plaintext_canary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _, _, lifecycle, _, long_term, context = create_long_term_service(root)
            thread = lifecycle.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            canary = b"SYNTHETIC_WAL_CANARY_PRIVATE_20260731"
            long_term.add_note(bound, canary.decode(), MemoryScope.THREAD, NoteKind.FACT)
            for path in root.rglob("*"):
                if path.is_file() and path.suffix.lower() in {".db", ".wal", ".journal", ".tmp"}:
                    self.assertNotIn(canary, path.read_bytes(), str(path))


if __name__ == "__main__":
    unittest.main()
