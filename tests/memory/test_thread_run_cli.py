import contextlib
import io
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from secminiagent.cli import run_memory_command
from tests.memory.m7_lifecycle_helpers import create_lifecycle_service


class ThreadRunCLITest(unittest.TestCase):
    def test_thread_commands_emit_only_safe_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, service, context = create_lifecycle_service(Path(tmp))
            output = io.StringIO()
            with patch("secminiagent.cli.create_thread_run_runtime", return_value=(service, context)):
                with contextlib.redirect_stdout(output):
                    result = run_memory_command([
                        "--cwd", tmp, "thread", "create", "--session", context.session_id,
                        "--title", "CANARY_PRIVATE_TITLE", "--goal", "CANARY_PRIVATE_GOAL",
                    ])
            self.assertEqual(result, 0)
            data = json.loads(output.getvalue())
            self.assertEqual(data["status"], "active")
            self.assertNotIn("CANARY_PRIVATE_TITLE", output.getvalue())
            self.assertNotIn("CANARY_PRIVATE_GOAL", output.getvalue())

    def test_run_list_and_interrupt_emit_safe_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, service, context = create_lifecycle_service(Path(tmp))
            thread = service.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            run = service.begin_run(bound, thread.thread_id)
            output = io.StringIO()
            with patch("secminiagent.cli.create_thread_run_runtime", return_value=(service, bound)):
                with contextlib.redirect_stdout(output):
                    result = run_memory_command([
                        "--cwd", tmp, "run", "interrupt", run.run_id,
                        "--session", context.session_id, "--thread", thread.thread_id,
                    ])
            self.assertEqual(result, 0)
            self.assertEqual(json.loads(output.getvalue())["status"], "interrupted")

    def test_thread_cli_on_uninitialized_workspace_has_no_side_effects(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            error = io.StringIO()
            with contextlib.redirect_stderr(error):
                result = run_memory_command(["--cwd", tmp, "thread", "list", "--session", "s"])
            self.assertEqual(result, 1)
            self.assertIn("M7_THREAD_RUNTIME_REQUIRES_SCHEMA_V2", error.getvalue())
            self.assertFalse((root / ".secminiagent").exists())

    def test_transcript_metadata_only_does_not_print_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            from tests.memory.m7_lifecycle_helpers import create_transcript_service
            _, _, service, transcript, context = create_transcript_service(Path(tmp))
            thread = service.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            run = service.begin_run(bound, thread.thread_id)
            transcript.append(bound, run.run_id, {"role": "user", "content": "CANARY_TRANSCRIPT_CONTENT"})
            output = io.StringIO()
            with patch("secminiagent.memory.factory.create_thread_transcript_runtime", return_value=(service, transcript, bound)):
                with contextlib.redirect_stdout(output):
                    result = run_memory_command([
                        "--cwd", tmp, "transcript", "inspect", "--session", context.session_id,
                        "--thread", thread.thread_id, "--metadata-only",
                    ])
            self.assertEqual(result, 0)
            self.assertNotIn("CANARY_TRANSCRIPT_CONTENT", output.getvalue())
            self.assertEqual(json.loads(output.getvalue())["role"], "user")

    def test_summary_build_outputs_metadata_without_summary_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            from tests.memory.m7_lifecycle_helpers import create_note_summary_services
            _, _, service, transcript, notes, summaries, context = create_note_summary_services(Path(tmp))
            thread = service.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            run = service.begin_run(bound, thread.thread_id)
            transcript.append(bound, run.run_id, {"role": "user", "content": "CANARY_SUMMARY_SOURCE"})
            service.complete_run(bound, run.run_id)
            output = io.StringIO()
            with patch("secminiagent.memory.factory.create_note_summary_runtime", return_value=(service, transcript, notes, summaries, bound)):
                with contextlib.redirect_stdout(output):
                    result = run_memory_command([
                        "--cwd", tmp, "summary", "build", "--session", context.session_id,
                        "--thread", thread.thread_id,
                    ])
            self.assertEqual(result, 0)
            self.assertNotIn("CANARY_SUMMARY_SOURCE", output.getvalue())
            self.assertEqual(json.loads(output.getvalue())["version"], 1)


if __name__ == "__main__":
    unittest.main()
