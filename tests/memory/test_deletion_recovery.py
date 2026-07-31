import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from secminiagent.memory.cascade_delete import CascadeDeletionService
from tests.memory.m7_lifecycle_helpers import create_long_term_service


class DeletionRecoveryTest(unittest.TestCase):
    def _setup(self, root):
        _, store, lifecycle, transcript, long_term, context = create_long_term_service(root)
        thread = lifecycle.create_thread(context)
        bound = replace(context, thread_id=thread.thread_id)
        run = lifecycle.begin_run(bound, thread.thread_id)
        transcript.append(bound, run.run_id, {"role": "user", "content": "recovery source"})
        lifecycle.complete_run(bound, run.run_id)
        deletion = CascadeDeletionService(long_term, deletion_key=store.key_provider.derive_key(context.workspace_id, "deletion")[0])
        return store, deletion, bound, run

    def test_resume_after_planned_failpoint_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, deletion, context, run = self._setup(Path(tmp))
            preview = deletion.preview(context, "run", run.run_id)
            with self.assertRaisesRegex(RuntimeError, "AFTER_PLANNED"):
                deletion.execute(context, "run", run.run_id, preview.confirmation_token, fail_at="after_planned")
            job_id = __import__("hashlib").sha256(("delete:" + deletion.confirmation.verify(preview.confirmation_token, context.workspace_id, "run", run.run_id, preview.snapshot_digest)).encode()).hexdigest()
            receipt = deletion.resume(context, job_id)
            again = deletion.resume(context, job_id)
            self.assertEqual(receipt, again)
            with store.connection() as connection:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM deletion_items WHERE job_id=?", (job_id,)).fetchone()[0], 1)

    def test_resume_after_sqlite_failpoint_only_moves_forward(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, deletion, context, run = self._setup(Path(tmp))
            preview = deletion.preview(context, "run", run.run_id)
            with self.assertRaisesRegex(RuntimeError, "AFTER_SQLITE"):
                deletion.execute(context, "run", run.run_id, preview.confirmation_token, fail_at="after_sqlite")
            # Replaying the same authorized operation returns/resumes the same job.
            receipt = deletion.execute(context, "run", run.run_id, preview.confirmation_token)
            self.assertTrue(receipt.index_deletions_complete)


if __name__ == "__main__":
    unittest.main()
