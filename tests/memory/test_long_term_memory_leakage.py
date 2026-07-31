import io
import logging
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from secminiagent.memory.errors import MemoryConfirmationRequired
from secminiagent.memory.models import MemoryScope, NoteKind
from tests.memory.m7_lifecycle_helpers import create_long_term_service


class LongTermMemoryLeakageTest(unittest.TestCase):
    def test_failures_and_logs_do_not_expose_note_content_or_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, lifecycle, _, service, context = create_long_term_service(Path(tmp))
            thread = lifecycle.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            canary = "CANARY_LONG_TERM_PRIVATE_CONTENT"
            note = service.add_note(bound, canary, MemoryScope.THREAD, NoteKind.FACT)
            preview = service.preview_promotion(bound, note.note_id, MemoryScope.SESSION)
            stream = io.StringIO()
            handler = logging.StreamHandler(stream)
            root = logging.getLogger()
            root.addHandler(handler)
            try:
                with self.assertRaises(MemoryConfirmationRequired) as captured:
                    service.promote_note(bound, note.note_id, MemoryScope.WORKSPACE, preview.confirmation_token)
                logging.getLogger(__name__).exception("promotion rejected", exc_info=captured.exception)
            finally:
                root.removeHandler(handler)
            combined = stream.getvalue() + str(captured.exception)
            self.assertNotIn(canary, combined)
            self.assertNotIn(preview.confirmation_token, combined)


if __name__ == "__main__":
    unittest.main()
