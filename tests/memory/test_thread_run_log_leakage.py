import contextlib
import io
import logging
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from secminiagent.memory.errors import MemoryLifecycleConflict
from tests.memory.m7_lifecycle_helpers import create_lifecycle_service


class ThreadRunLogLeakageTest(unittest.TestCase):
    def test_titles_goals_and_paths_do_not_appear_in_lifecycle_errors_or_logs(self):
        canaries = ("CANARY_THREAD_TITLE", "CANARY_THREAD_GOAL", "CANARY_LOCAL_PATH")
        with tempfile.TemporaryDirectory(prefix=canaries[2]) as tmp:
            _, _, service, context = create_lifecycle_service(Path(tmp))
            thread = service.create_thread(context, canaries[0], canaries[1])
            bound = replace(context, thread_id=thread.thread_id)
            service.begin_run(bound, thread.thread_id)
            captured = io.StringIO()
            handler = logging.StreamHandler(captured)
            root = logging.getLogger()
            root.addHandler(handler)
            try:
                with self.assertRaises(MemoryLifecycleConflict) as raised:
                    service.archive_thread(bound, thread.thread_id)
            finally:
                root.removeHandler(handler)
            visible = captured.getvalue() + str(raised.exception)
            for canary in canaries:
                self.assertNotIn(canary, visible)


if __name__ == "__main__":
    unittest.main()
