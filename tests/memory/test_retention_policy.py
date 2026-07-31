import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from secminiagent.memory.errors import MemoryNotFound, MemoryValidationError
from secminiagent.memory.models import MemoryScope, NoteKind, NoteStatus
from secminiagent.memory.retention import RetentionService
from tests.memory.m7_lifecycle_helpers import create_long_term_service


class RetentionPolicyTest(unittest.TestCase):
    def _note(self, root):
        _, _, lifecycle, _, service, context = create_long_term_service(root)
        thread = lifecycle.create_thread(context)
        bound = replace(context, thread_id=thread.thread_id)
        note = service.add_note(bound, "retention test body", MemoryScope.THREAD, NoteKind.FACT)
        return service, bound, note

    def test_explicit_expiry_blocks_recall_before_worker_even_when_pinned(self):
        with tempfile.TemporaryDirectory() as tmp:
            service, context, note = self._note(Path(tmp))
            retention = RetentionService(service.store)
            retention.pin(context, note.note_id, True)
            retention.set_expiry(context, note.note_id, datetime.now(timezone.utc) - timedelta(seconds=1))
            with self.assertRaises(MemoryNotFound):
                service.get_note(context, note.note_id)
            self.assertEqual(retention.scan_expired(context, dry_run=True), (note.note_id,))
            retention.scan_expired(context, dry_run=False)
            with service.store.connection() as connection:
                status = connection.execute("SELECT lifecycle_status FROM memories WHERE id=?", (note.note_id,)).fetchone()[0]
            self.assertEqual(status, NoteStatus.EXPIRED.value)

    def test_pin_blocks_default_ttl_expiry_but_not_explicit_deletion(self):
        with tempfile.TemporaryDirectory() as tmp:
            service, context, note = self._note(Path(tmp))
            retention = RetentionService(service.store)
            retention.set_expiry(
                context, note.note_id, datetime.now(timezone.utc) - timedelta(seconds=1),
                policy_id="default:test",
            )
            retention.pin(context, note.note_id, True)
            self.assertEqual(service.get_note(context, note.note_id).note_id, note.note_id)
            self.assertEqual(retention.scan_expired(context, dry_run=True), ())

    def test_default_ttl_has_bounded_configuration(self):
        with tempfile.TemporaryDirectory() as tmp:
            service, context, note = self._note(Path(tmp))
            retention = RetentionService(service.store)
            with self.assertRaises(MemoryValidationError):
                retention.apply_default_ttl(context, note.note_id, 1)


if __name__ == "__main__":
    unittest.main()
