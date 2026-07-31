import contextlib
import io
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from secminiagent.cli import run_memory_command
from secminiagent.memory.candidate_extractor import ControlledCandidateService
from secminiagent.memory.models import CandidateProposal, MemoryScope, NoteKind
from secminiagent.memory.search import HybridMemorySearch
from tests.memory.m7_lifecycle_helpers import create_long_term_service


class AdvancedMemoryCLITest(unittest.TestCase):
    def _runtime(self, root):
        _, store, lifecycle, transcript, service, context = create_long_term_service(root)
        thread = lifecycle.create_thread(context)
        bound = replace(context, thread_id=thread.thread_id, provider="local")
        search = HybridMemorySearch(store, service.lifecycle_store)
        candidates = ControlledCandidateService(service, dedup_key=store.key_provider.derive_key(context.workspace_id, "dedup")[0])
        return store, lifecycle, transcript, service, search, candidates, bound

    def test_search_accepts_stdin_and_defaults_to_metadata_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, _, service, search, candidates, context = self._runtime(Path(tmp))
            body = "CANARY_SEARCH_CLI_BODY turbine"
            service.add_note(context, body, MemoryScope.THREAD, NoteKind.FACT)
            output = io.StringIO()
            runtime = (service, search, candidates, context)
            with patch("secminiagent.memory.factory.create_advanced_memory_runtime", return_value=runtime), patch("sys.stdin", io.StringIO("turbine")), contextlib.redirect_stdout(output):
                result = run_memory_command(["--cwd", tmp, "search", "--session", context.session_id, "--thread", context.thread_id, "--explain"])
            self.assertEqual(result, 0)
            self.assertNotIn(body, output.getvalue())
            value = json.loads(output.getvalue())
            self.assertIn("features", value)
            self.assertNotIn("fingerprint", output.getvalue().lower())

    def test_candidate_cli_can_list_and_reject_without_body_leakage(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, lifecycle, transcript, service, search, candidates, context = self._runtime(Path(tmp))
            run = lifecycle.begin_run(context, context.thread_id)
            source = transcript.append(context, run.run_id, {"role": "user", "content": "candidate source"})
            lifecycle.complete_run(context, run.run_id)
            body = "CANARY_CANDIDATE_CLI_BODY"
            candidate = candidates.submit(context, CandidateProposal(NoteKind.FACT, body, (source.message_id,), 0.8))
            runtime = (service, search, candidates, context)
            output = io.StringIO()
            with patch("secminiagent.memory.factory.create_advanced_memory_runtime", return_value=runtime), contextlib.redirect_stdout(output):
                result = run_memory_command(["--cwd", tmp, "candidate", "reject", candidate.note_id, "--session", context.session_id, "--thread", context.thread_id, "--expected-version", "1"])
            self.assertEqual(result, 0)
            self.assertNotIn(body, output.getvalue())
            self.assertEqual(json.loads(output.getvalue())["status"], "rejected")


if __name__ == "__main__":
    unittest.main()
