import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

from secminiagent.memory.errors import MemoryLifecycleConflict
from secminiagent.memory.models import MemoryScope, NoteKind, NoteStatus, VerificationStatus
from tests.memory.m7_lifecycle_helpers import create_long_term_service


class NoteConfirmationTest(unittest.TestCase):
    def test_candidate_confirmation_reencrypts_aad_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, lifecycle, _, service, context = create_long_term_service(Path(tmp))
            thread = lifecycle.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            candidate = service.notes.add_candidate(bound, kind=NoteKind.FACT, content="candidate fact")
            confirmed = service.confirm_note(bound, candidate.note_id, candidate.revision)
            self.assertEqual((confirmed.status, confirmed.verification), (NoteStatus.ACTIVE, VerificationStatus.USER_CONFIRMED))
            self.assertEqual(service.get_note(bound, candidate.note_id).content, "candidate fact")
            self.assertEqual(service.confirm_note(bound, candidate.note_id, candidate.revision), confirmed)
            with self.assertRaises(MemoryLifecycleConflict):
                service.confirm_note(bound, candidate.note_id, candidate.revision + 1)

    def test_concurrent_revision_has_one_winner(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, lifecycle, _, service, context = create_long_term_service(Path(tmp))
            thread = lifecycle.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            old = service.add_note(bound, "original decision", MemoryScope.THREAD, NoteKind.DECISION)

            def revise(value):
                try:
                    return service.revise_note(bound, old.note_id, value, old.revision).note_id
                except MemoryLifecycleConflict:
                    return None

            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(revise, ("replacement one", "replacement two")))
            self.assertEqual(sum(item is not None for item in results), 1)


if __name__ == "__main__":
    unittest.main()
