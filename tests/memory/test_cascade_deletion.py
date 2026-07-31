import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from secminiagent.memory.cascade_delete import CascadeDeletionService
from secminiagent.memory.errors import MemoryConfirmationRequired, MemoryIntegrityError
from secminiagent.memory.models import MemoryRelationType, MemoryScope, NoteKind, NoteStatus
from tests.memory.m7_lifecycle_helpers import create_long_term_service


class CascadeDeletionTest(unittest.TestCase):
    def _service(self, root, index=None):
        path, store, lifecycle, transcript, long_term, context = create_long_term_service(root, index=index)
        deletion = CascadeDeletionService(
            long_term, deletion_key=store.key_provider.derive_key(context.workspace_id, "deletion")[0], index=index,
        )
        return path, store, lifecycle, transcript, long_term, deletion, context

    def test_clear_run_tombstones_direct_memory_and_retracts_derived_note(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, store, lifecycle, transcript, long_term, deletion, context = self._service(Path(tmp))
            thread = lifecycle.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            run = lifecycle.begin_run(bound, thread.thread_id)
            source = transcript.append(bound, run.run_id, {"role": "user", "content": "delete source"})
            lifecycle.complete_run(bound, run.run_id)
            candidate = long_term.notes.add_candidate(bound, kind=NoteKind.FACT, content="derived fact", source_refs=(source.message_id,), created_by="model")
            derived = long_term.confirm_note(bound, candidate.note_id, candidate.revision)
            preview = deletion.preview(bound, "run", run.run_id)
            self.assertEqual((preview.direct_memory_count, preview.derived_memory_count), (1, 1))
            with self.assertRaises(MemoryConfirmationRequired):
                deletion.execute(bound, "thread", thread.thread_id, preview.confirmation_token)
            receipt = deletion.execute(bound, "run", run.run_id, preview.confirmation_token)
            self.assertTrue(receipt.authoritative_access_revoked)
            self.assertTrue(receipt.index_deletions_complete)
            self.assertFalse(receipt.physical_overwrite_claimed)
            with store.connection() as connection:
                source_row = connection.execute("SELECT lifecycle_status,deleted_at FROM memories WHERE id=?", (source.message_id,)).fetchone()
                derived_status = connection.execute("SELECT lifecycle_status FROM memories WHERE id=?", (derived.note_id,)).fetchone()[0]
            self.assertEqual(source_row[0], NoteStatus.DELETED.value)
            self.assertIsNotNone(source_row[1])
            self.assertEqual(derived_status, NoteStatus.RETRACTED.value)
            with self.assertRaises(MemoryIntegrityError):
                long_term.get_note(bound, derived.note_id)

    def test_explicit_delete_ignores_pin(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, store, lifecycle, transcript, _, deletion, context = self._service(Path(tmp))
            thread = lifecycle.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            run = lifecycle.begin_run(bound, thread.thread_id)
            message = transcript.append(bound, run.run_id, {"role": "user", "content": "pinned source"})
            lifecycle.complete_run(bound, run.run_id)
            from secminiagent.memory.retention import RetentionService
            RetentionService(store).pin(bound, message.message_id, True)
            preview = deletion.preview(bound, "run", run.run_id)
            deletion.execute(bound, "run", run.run_id, preview.confirmation_token)
            with store.connection() as connection:
                self.assertIsNotNone(connection.execute("SELECT deleted_at FROM memories WHERE id=?", (message.message_id,)).fetchone()[0])

    def test_promoted_workspace_note_requires_explicit_independent_retention_choice(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, lifecycle, _, long_term, deletion, context = self._service(Path(tmp))
            thread = lifecycle.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            source = long_term.add_note(bound, "workspace retention body", MemoryScope.THREAD, NoteKind.FACT)
            promotion = long_term.preview_promotion(bound, source.note_id, MemoryScope.WORKSPACE)
            promoted = long_term.promote_note(bound, source.note_id, MemoryScope.WORKSPACE, promotion.confirmation_token)
            preview = deletion.preview(bound, "thread", thread.thread_id)
            self.assertEqual(preview.promoted_workspace_count, 1)
            receipt = deletion.execute(
                bound, "thread", thread.thread_id, preview.confirmation_token,
                independent_retention_tokens=(preview.retention_confirmations[0].confirmation_token,),
            )
            self.assertEqual(receipt.independent_records_created, 1)
            active = long_term.list_notes(bound, scope=MemoryScope.WORKSPACE)
            self.assertEqual(len(active), 1)
            self.assertNotEqual(active[0].note_id, promoted.note_id)
            self.assertEqual(active[0].source_refs, ())

    def test_authenticated_provenance_cycle_and_limit_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, store, lifecycle, _, long_term, deletion, context = self._service(Path(tmp))
            thread = lifecycle.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            first = long_term.add_note(bound, "first cycle note", MemoryScope.THREAD, NoteKind.FACT)
            second = long_term.add_note(bound, "second cycle note", MemoryScope.THREAD, NoteKind.FACT)
            with store.connection(immediate=True) as connection:
                long_term.notes._relation(connection, context.workspace_id, first.note_id, second.note_id, MemoryRelationType.SUPPORTS)
                long_term.notes._relation(connection, context.workspace_id, second.note_id, first.note_id, MemoryRelationType.SUPPORTS)
            from secminiagent.memory.errors import MemoryIntegrityError, MemoryLifecycleConflict
            with self.assertRaises(MemoryIntegrityError):
                deletion.preview(bound, "thread", thread.thread_id)
            bounded = CascadeDeletionService(long_term, deletion_key=store.key_provider.derive_key(context.workspace_id, "deletion")[0], max_nodes=1)
            with self.assertRaises(MemoryLifecycleConflict):
                bounded.preview(bound, "thread", thread.thread_id)


if __name__ == "__main__":
    unittest.main()
