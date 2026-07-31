import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from secminiagent.memory.models import MemoryScope, NoteKind
from secminiagent.memory.search import HybridMemorySearch
from tests.memory.m7_lifecycle_helpers import create_long_term_service


class FakeCandidates:
    def __init__(self, ids=()):
        self.ids = ids
        self.deleted = []

    def candidate_ids(self, query, context):
        return self.ids

    def delete(self, memory_id, context):
        self.deleted.append(memory_id)


class HybridSearchTest(unittest.TestCase):
    def test_lexical_search_degrades_without_chroma_and_scores_are_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, lifecycle, _, service, context = create_long_term_service(Path(tmp))
            thread = lifecycle.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id, provider="local")
            note = service.add_note(bound, "PLC maintenance requires an offline backup", MemoryScope.THREAD, NoteKind.FACT)
            search = HybridMemorySearch(service.store, service.lifecycle_store)
            hits = search.search(bound, "PLC backup")
            self.assertEqual(hits[0].memory_id, note.note_id)
            self.assertTrue(0 <= hits[0].score_millis <= 1000)
            self.assertIn("SEARCH_SQLITE_AUTHORITY_VERIFIED", hits[0].reason_codes)
            self.assertTrue(all(0 <= item.contribution_millis <= 1000 for item in hits[0].features))

    def test_semantic_candidate_can_recall_authorized_workspace_note(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, lifecycle, _, service, context = create_long_term_service(Path(tmp))
            thread = lifecycle.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            source = service.add_note(bound, "unrelated exact words", MemoryScope.THREAD, NoteKind.FACT)
            preview = service.preview_promotion(bound, source.note_id, MemoryScope.WORKSPACE)
            workspace = service.promote_note(bound, source.note_id, MemoryScope.WORKSPACE, preview.confirmation_token)
            search = HybridMemorySearch(service.store, service.lifecycle_store, index=FakeCandidates((workspace.note_id,)))
            hits = search.search(bound, "semantic only query")
            self.assertEqual(tuple(item.memory_id for item in hits), (workspace.note_id,))


if __name__ == "__main__":
    unittest.main()
