import io
import logging
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from secminiagent.memory.cascade_delete import CascadeDeletionService
from tests.memory.m7_lifecycle_helpers import create_long_term_service


class DeletionLeakageTest(unittest.TestCase):
    def test_job_receipt_audit_logs_and_errors_contain_no_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, store, lifecycle, transcript, long_term, context = create_long_term_service(Path(tmp))
            thread = lifecycle.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            run = lifecycle.begin_run(bound, thread.thread_id)
            body = "CANARY_CASCADE_DELETE_PRIVATE_BODY"
            transcript.append(bound, run.run_id, {"role": "user", "content": body})
            lifecycle.complete_run(bound, run.run_id)
            deletion = CascadeDeletionService(long_term, deletion_key=store.key_provider.derive_key(context.workspace_id, "deletion")[0])
            preview = deletion.preview(bound, "run", run.run_id)
            stream = io.StringIO()
            handler = logging.StreamHandler(stream)
            root = logging.getLogger()
            root.addHandler(handler)
            try:
                receipt = deletion.execute(bound, "run", run.run_id, preview.confirmation_token)
            finally:
                root.removeHandler(handler)
            with store.connection() as connection:
                metadata = " ".join(str(tuple(row)) for table in ("deletion_jobs", "deletion_items", "memory_audit") for row in connection.execute(f"SELECT * FROM {table}"))
            combined = stream.getvalue() + metadata + repr(receipt)
            self.assertNotIn(body, combined)
            self.assertNotIn(preview.confirmation_token, combined)
            self.assertNotIn("ciphertext", combined.lower())


if __name__ == "__main__":
    unittest.main()
