import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from secminiagent.memory.cascade_delete import CascadeDeletionService
from secminiagent.memory.models import MemoryScope, NoteKind
from tests.memory.m7_lifecycle_helpers import create_long_term_service


class FlakyDeleteIndex:
    def __init__(self):
        self.fail = True
        self.deleted = []

    def index(self, metadata, content):
        pass

    def delete(self, memory_id, context):
        self.deleted.append(memory_id)
        if self.fail:
            raise RuntimeError("offline")


class DeletionChromaSyncTest(unittest.TestCase):
    def test_sqlite_revocation_survives_index_failure_and_resume_completes(self):
        with tempfile.TemporaryDirectory() as tmp:
            index = FlakyDeleteIndex()
            _, store, lifecycle, _, long_term, context = create_long_term_service(Path(tmp), index=index)
            thread = lifecycle.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            source = long_term.add_note(bound, "promoted deletion source", MemoryScope.THREAD, NoteKind.FACT)
            preview_promotion = long_term.preview_promotion(bound, source.note_id, MemoryScope.WORKSPACE)
            workspace = long_term.promote_note(bound, source.note_id, MemoryScope.WORKSPACE, preview_promotion.confirmation_token)
            deletion = CascadeDeletionService(long_term, deletion_key=store.key_provider.derive_key(context.workspace_id, "deletion")[0], index=index)
            preview = deletion.preview(bound, "thread", thread.thread_id)
            receipt = deletion.execute(bound, "thread", thread.thread_id, preview.confirmation_token)
            self.assertTrue(receipt.authoritative_access_revoked)
            self.assertTrue(receipt.cleanup_pending)
            index.fail = False
            completed = deletion.resume(bound, receipt.job_id)
            self.assertTrue(completed.index_deletions_complete)
            self.assertIn(workspace.note_id, index.deleted)


if __name__ == "__main__":
    unittest.main()
