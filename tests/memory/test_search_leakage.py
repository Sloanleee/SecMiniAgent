import io
import logging
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from secminiagent.memory.models import MemoryScope, NoteKind
from secminiagent.memory.search import HybridMemorySearch
from tests.memory.m7_lifecycle_helpers import create_long_term_service


class SearchLeakageTest(unittest.TestCase):
    def test_query_hit_and_fingerprint_do_not_enter_logs_or_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, store, lifecycle, _, service, context = create_long_term_service(Path(tmp))
            thread = lifecycle.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id, provider="local")
            body = "CANARY_SEARCH_PRIVATE_BODY"
            query = "CANARY_SEARCH_PRIVATE_QUERY"
            service.add_note(bound, body + " " + query, MemoryScope.THREAD, NoteKind.FACT)
            stream = io.StringIO()
            handler = logging.StreamHandler(stream)
            root = logging.getLogger()
            root.addHandler(handler)
            try:
                hits = HybridMemorySearch(store, service.lifecycle_store).search(bound, query)
            finally:
                root.removeHandler(handler)
            self.assertEqual(len(hits), 1)
            with store.connection() as connection:
                audit_text = " ".join(str(tuple(row)) for row in connection.execute("SELECT * FROM memory_audit"))
            combined = stream.getvalue() + audit_text
            self.assertNotIn(body, combined)
            self.assertNotIn(query, combined)


if __name__ == "__main__":
    unittest.main()
