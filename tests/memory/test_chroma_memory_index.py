import tempfile
import unittest
from pathlib import Path

from secminiagent.memory import (
    MemoryAccessContext,
    MemoryCandidate,
    MemoryQuery,
    MemoryScope,
    MemorySource,
    MemoryType,
)
from secminiagent.memory.errors import MemoryPolicyDenied
from secminiagent.memory.vector_index import ChromaMemoryIndex

from tests.memory.helpers import build_test_service


WORKSPACE_A = "d" * 64
WORKSPACE_B = "e" * 64
CONTEXT_A = MemoryAccessContext(WORKSPACE_A, "session-a", "local")
CONTEXT_B = MemoryAccessContext(WORKSPACE_B, "session-b", "local")


def workspace_candidate(content, *, confirmed=True):
    return MemoryCandidate(
        MemoryType.PROJECT_FACT,
        content,
        MemoryScope.WORKSPACE,
        MemorySource("unit_test", user_confirmed=confirmed),
    )


class ChromaMemoryIndexTest(unittest.TestCase):
    def test_index_search_workspace_filter_delete_and_rebuild(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with ChromaMemoryIndex(root / "chroma") as index:
                service, _, _ = build_test_service(root, index=index)
                alpha = service.remember(workspace_candidate("alpha turbine maintenance policy"), CONTEXT_A)
                service.remember(workspace_candidate("beta substation inspection"), CONTEXT_B)

                results = service.search(
                    MemoryQuery(text="alpha turbine"),
                    CONTEXT_A,
                )
                self.assertIn(alpha.id, [item.metadata.id for item in results])
                self.assertTrue(all(item.metadata.workspace_id == WORKSPACE_A for item in results))

                service.forget(alpha.id, CONTEXT_A)
                after_delete = service.search(
                    MemoryQuery(text="alpha turbine"),
                    CONTEXT_A,
                )
                self.assertNotIn(alpha.id, [item.metadata.id for item in after_delete])

                replacement = service.remember(workspace_candidate("gamma control procedure"), CONTEXT_A)
                index.reset()
                self.assertEqual(index.count(), 0)
                rebuilt = service.rebuild_index(CONTEXT_A)
                self.assertGreaterEqual(rebuilt, 1)
                self.assertGreaterEqual(index.count(WORKSPACE_A), 1)
                recalled = service.search(
                    MemoryQuery(text="gamma control"),
                    CONTEXT_A,
                )
                self.assertIn(replacement.id, [item.metadata.id for item in recalled])

    def test_confidential_index_contains_only_sanitized_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with ChromaMemoryIndex(root / "chroma") as index:
                service, _, _ = build_test_service(root, index=index)
                raw = "PLC-01 is the critical controller at 172.16.20.10."
                metadata = service.remember(workspace_candidate(raw), CONTEXT_A)
                indexed = index.collection.get(ids=[metadata.id], include=["documents"])
                document = indexed["documents"][0]
                self.assertNotIn("PLC-01", document)
                self.assertNotIn("172.16.20.10", document)
                self.assertIn("Sensitive", document)
                for index_file in (root / "chroma").rglob("*"):
                    if index_file.is_file():
                        self.assertNotIn(raw.encode(), index_file.read_bytes(), str(index_file))

    def test_secret_never_enters_chroma(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with ChromaMemoryIndex(root / "chroma") as index:
                service, _, _ = build_test_service(root, index=index)
                before = index.count()
                with self.assertRaises(MemoryPolicyDenied):
                    service.remember(workspace_candidate('password = "Synthet1c-Only-Value"'), CONTEXT_A)
                self.assertEqual(index.count(), before)


if __name__ == "__main__":
    unittest.main()
