import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from secminiagent.memory.errors import MemoryAccessDenied, MemoryLifecycleConflict
from secminiagent.memory.models import MemoryScope, NoteKind, NoteStatus, VerificationStatus
from tests.memory.m7_lifecycle_helpers import create_long_term_service


class ExplicitNotesTest(unittest.TestCase):
    def _bound(self, root):
        path, store, lifecycle, _, service, context = create_long_term_service(root)
        thread = lifecycle.create_thread(context)
        return path, store, service, replace(context, thread_id=thread.thread_id)

    def test_user_add_confirm_revise_and_retract_are_immutable(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, store, service, context = self._bound(Path(tmp))
            old = service.add_note(context, "use deterministic local storage", MemoryScope.THREAD, NoteKind.DECISION)
            self.assertEqual((old.status, old.verification), (NoteStatus.ACTIVE, VerificationStatus.USER_CONFIRMED))
            with store.connection() as connection:
                old_ciphertext = bytes(connection.execute("SELECT ciphertext FROM memories WHERE id=?", (old.note_id,)).fetchone()[0])
            revised = service.revise_note(context, old.note_id, "use encrypted local storage", old.revision)
            self.assertNotEqual(old.note_id, revised.note_id)
            self.assertEqual(revised.revision, old.revision + 1)
            self.assertEqual(service.get_note(context, old.note_id).status, NoteStatus.SUPERSEDED)
            with store.connection() as connection:
                self.assertEqual(old_ciphertext, bytes(connection.execute("SELECT ciphertext FROM memories WHERE id=?", (old.note_id,)).fetchone()[0]))
            retracted = service.retract_note(context, revised.note_id, "USER_REQUEST", revised.revision)
            self.assertEqual(retracted.status, NoteStatus.RETRACTED)
            self.assertNotIn(b"encrypted local storage", path.read_bytes())

    def test_expected_version_and_thread_scope_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, service, context = self._bound(Path(tmp))
            note = service.add_note(context, "bounded fact", MemoryScope.THREAD, NoteKind.FACT)
            with self.assertRaises(MemoryLifecycleConflict):
                service.retract_note(context, note.note_id, "USER_REQUEST", 99)
            foreign = replace(context, thread_id="foreign-thread")
            with self.assertRaises(MemoryAccessDenied):
                service.get_note(foreign, note.note_id)


if __name__ == "__main__":
    unittest.main()
