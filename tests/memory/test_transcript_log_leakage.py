import contextlib
import io
import logging
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from tests.memory.m7_lifecycle_helpers import create_transcript_service


class TranscriptLogLeakageTest(unittest.TestCase):
    def test_transcript_plaintext_and_tool_arguments_do_not_reach_database_logs_or_errors(self):
        canaries = ("CANARY_MESSAGE_BODY", "CANARY_TOOL_ARGUMENT", "CANARY_TOOL_OUTPUT")
        with tempfile.TemporaryDirectory() as tmp:
            path, _, lifecycle, transcript, context = create_transcript_service(Path(tmp))
            thread = lifecycle.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            run = lifecycle.begin_run(bound, thread.thread_id)
            captured = io.StringIO()
            handler = logging.StreamHandler(captured)
            logger = logging.getLogger()
            logger.addHandler(handler)
            try:
                transcript.append(bound, run.run_id, {"role": "user", "content": canaries[0]})
                transcript.append(bound, run.run_id, {
                    "role": "assistant", "content": None,
                    "tool_calls": [{"id": "call-canary", "type": "function", "function": {"name": "read", "arguments": canaries[1]}}],
                })
                transcript.append(bound, run.run_id, {"role": "tool", "tool_call_id": "call-canary", "content": canaries[2]})
            finally:
                logger.removeHandler(handler)
            visible = captured.getvalue()
            raw = path.read_bytes()
            for canary in canaries:
                self.assertNotIn(canary, visible)
                self.assertNotIn(canary.encode(), raw)


if __name__ == "__main__":
    unittest.main()
