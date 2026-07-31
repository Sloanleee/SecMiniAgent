import logging
import io
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from secminiagent.memory.models import NoteKind
from tests.memory.m7_lifecycle_helpers import create_note_summary_services


class NoteSummaryLeakageTest(unittest.TestCase):
    def test_note_summary_and_sources_are_encrypted_and_not_logged(self):
        canaries = ("CANARY_NOTE_CONTENT", "CANARY_SUMMARY_SOURCE")
        with tempfile.TemporaryDirectory() as tmp:
            path, _, lifecycle, transcript, notes, summaries, context = create_note_summary_services(Path(tmp))
            thread = lifecycle.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            run = lifecycle.begin_run(bound, thread.thread_id)
            source = transcript.append(bound, run.run_id, {"role": "user", "content": canaries[1]})
            lifecycle.complete_run(bound, run.run_id)
            captured = io.StringIO()
            handler = logging.StreamHandler(captured)
            logger = logging.getLogger()
            logger.addHandler(handler)
            try:
                notes.add_candidate(bound, kind=NoteKind.TODO, content=canaries[0], source_refs=(source.message_id,))
                summaries.build(bound)
            finally:
                logger.removeHandler(handler)
            raw = path.read_bytes()
            for canary in canaries:
                self.assertNotIn(canary, captured.getvalue())
                self.assertNotIn(canary.encode(), raw)


if __name__ == "__main__":
    unittest.main()
