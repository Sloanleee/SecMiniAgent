import contextlib
import io
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from secminiagent.cli import run_memory_command
from secminiagent.memory.models import MemoryScope, NoteKind
from tests.memory.m7_lifecycle_helpers import create_long_term_service


class LongTermMemoryCLITest(unittest.TestCase):
    def _runtime(self, root):
        _, _, lifecycle, _, service, context = create_long_term_service(root)
        thread = lifecycle.create_thread(context)
        return service, replace(context, thread_id=thread.thread_id)

    def test_add_reads_content_from_stdin_and_emits_metadata_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            service, context = self._runtime(Path(tmp))
            output = io.StringIO()
            secret = "CANARY_NOTE_BODY_NOT_FOR_STDOUT"
            with patch("secminiagent.memory.factory.create_long_term_runtime", return_value=(service, context)), patch("sys.stdin", io.StringIO(secret)), contextlib.redirect_stdout(output):
                result = run_memory_command([
                    "--cwd", tmp, "note", "add", "--session", context.session_id,
                    "--thread", context.thread_id, "--kind", "decision",
                ])
            self.assertEqual(result, 0)
            self.assertNotIn(secret, output.getvalue())
            self.assertEqual(json.loads(output.getvalue())["status"], "active")

    def test_show_defaults_to_metadata_and_requires_explicit_content_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            service, context = self._runtime(Path(tmp))
            body = "CANARY_EXPLICIT_SHOW"
            note = service.add_note(context, body, MemoryScope.THREAD, NoteKind.FACT)
            with patch("secminiagent.memory.factory.create_long_term_runtime", return_value=(service, context)):
                safe = io.StringIO()
                with contextlib.redirect_stdout(safe):
                    self.assertEqual(run_memory_command(["--cwd", tmp, "note", "show", note.note_id, "--session", context.session_id, "--thread", context.thread_id]), 0)
                explicit = io.StringIO()
                with contextlib.redirect_stdout(explicit):
                    self.assertEqual(run_memory_command(["--cwd", tmp, "note", "show", note.note_id, "--session", context.session_id, "--thread", context.thread_id, "--show-content"]), 0)
            self.assertNotIn(body, safe.getvalue())
            self.assertEqual(json.loads(explicit.getvalue())["content"], body)

    def test_promotion_preview_contains_no_note_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            service, context = self._runtime(Path(tmp))
            body = "CANARY_PREVIEW_BODY"
            note = service.add_note(context, body, MemoryScope.THREAD, NoteKind.FACT)
            output = io.StringIO()
            with patch("secminiagent.memory.factory.create_long_term_runtime", return_value=(service, context)), contextlib.redirect_stdout(output):
                result = run_memory_command(["--cwd", tmp, "note", "promote-preview", note.note_id, "--session", context.session_id, "--thread", context.thread_id, "--to", "session"])
            self.assertEqual(result, 0)
            self.assertNotIn(body, output.getvalue())
            self.assertTrue(json.loads(output.getvalue())["requires_confirmation"])


if __name__ == "__main__":
    unittest.main()
