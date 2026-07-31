import contextlib
import io
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from secminiagent.cli import run_memory_command
from secminiagent.memory.cascade_delete import CascadeDeletionService
from secminiagent.memory.retention import RetentionService
from tests.memory.m7_lifecycle_helpers import create_long_term_service


class M7DeletionCLITest(unittest.TestCase):
    def _runtime(self, root):
        _, store, lifecycle, transcript, long_term, context = create_long_term_service(root)
        thread = lifecycle.create_thread(context)
        bound = replace(context, thread_id=thread.thread_id)
        run = lifecycle.begin_run(bound, thread.thread_id)
        transcript.append(bound, run.run_id, {"role": "user", "content": "CANARY_DELETE_CLI_BODY"})
        lifecycle.complete_run(bound, run.run_id)
        retention = RetentionService(store)
        deletion = CascadeDeletionService(long_term, deletion_key=store.key_provider.derive_key(context.workspace_id, "deletion")[0])
        return (long_term, retention, deletion, bound), run

    def test_preview_and_confirmed_clear_run_emit_safe_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, run = self._runtime(Path(tmp))
            output = io.StringIO()
            with patch("secminiagent.memory.factory.create_retention_deletion_runtime", return_value=runtime), contextlib.redirect_stdout(output):
                result = run_memory_command(["--cwd", tmp, "clear-run", run.run_id, "--session", runtime[3].session_id, "--thread", runtime[3].thread_id, "--preview"])
            self.assertEqual(result, 0)
            self.assertNotIn("CANARY_DELETE_CLI_BODY", output.getvalue())
            preview = json.loads(output.getvalue())
            completed = io.StringIO()
            with patch("secminiagent.memory.factory.create_retention_deletion_runtime", return_value=runtime), contextlib.redirect_stdout(completed):
                result = run_memory_command(["--cwd", tmp, "clear-run", run.run_id, "--session", runtime[3].session_id, "--thread", runtime[3].thread_id, "--yes", "--confirmation-token", preview["confirmation_token"]])
            self.assertEqual(result, 0)
            self.assertTrue(json.loads(completed.getvalue())["authoritative_access_revoked"])

    def test_execute_without_preview_token_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, run = self._runtime(Path(tmp))
            error = io.StringIO()
            with patch("secminiagent.memory.factory.create_retention_deletion_runtime", return_value=runtime), contextlib.redirect_stderr(error):
                result = run_memory_command(["--cwd", tmp, "clear-run", run.run_id, "--session", runtime[3].session_id, "--thread", runtime[3].thread_id, "--yes"])
            self.assertEqual(result, 1)
            self.assertIn("DELETION_PREVIEW_CONFIRMATION_REQUIRED", error.getvalue())


if __name__ == "__main__":
    unittest.main()
