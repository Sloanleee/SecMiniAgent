import tempfile
import unittest
from pathlib import Path

from secminiagent.memory.cascade_delete import CascadeDeletionService
from secminiagent.memory.context_assembler import ContextBudgets
from secminiagent.memory.errors import MemoryValidationError
from secminiagent.memory.search import HybridMemorySearch
from tests.memory.m7_lifecycle_helpers import create_long_term_service


class M7ResourceBoundsTest(unittest.TestCase):
    def test_search_context_and_closure_limits_are_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, store, _, _, long_term, context = create_long_term_service(Path(tmp))
            with self.assertRaises(MemoryValidationError):
                HybridMemorySearch(store, long_term.lifecycle_store, candidate_limit=1001)
            with self.assertRaises(MemoryValidationError):
                HybridMemorySearch(store, long_term.lifecycle_store, candidate_limit=10, decrypt_limit=11)
            with self.assertRaises(MemoryValidationError):
                ContextBudgets(total_chars=100, retrieval_chars=0)
            deletion = CascadeDeletionService(long_term, deletion_key=store.key_provider.derive_key(context.workspace_id, "deletion")[0], max_nodes=1, max_depth=1)
            self.assertEqual((deletion.max_nodes, deletion.max_depth), (1, 1))


if __name__ == "__main__":
    unittest.main()
