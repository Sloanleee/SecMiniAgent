import tempfile
import unittest
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

from secminiagent.memory.models import MemoryScope, NoteKind
from secminiagent.memory.search import HybridMemorySearch
from tests.memory.m7_lifecycle_helpers import create_long_term_service


class BrokenIndex:
    def candidate_ids(self, query, context):
        raise RuntimeError("offline")


class M7OfflineDegradationTest(unittest.TestCase):
    def test_broken_or_missing_chroma_degrades_to_authority_search(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, lifecycle, _, long_term, context = create_long_term_service(Path(tmp))
            thread = lifecycle.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id, provider="local")
            note = long_term.add_note(bound, "offline lexical fallback", MemoryScope.THREAD, NoteKind.FACT)
            for index in (None, BrokenIndex()):
                hits = HybridMemorySearch(long_term.store, long_term.lifecycle_store, index=index).search(bound, "offline fallback")
                self.assertEqual(hits[0].memory_id, note.note_id)

    def test_benchmark_refuses_user_memory_output_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / ".secminiagent" / "reports"
            root = Path(__file__).resolve().parents[2]
            result = subprocess.run(
                [sys.executable, str(root / "benchmarks" / "memory" / "run_retrieval.py"), "--output-dir", str(target)],
                cwd=root, capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 2)
            self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
