import tempfile
import unittest
from pathlib import Path

from secminiagent.rag.backends import LocalRagBackend, create_backend


class RagBackendTest(unittest.TestCase):
    def test_create_local_backend(self):
        backend = create_backend("local")

        self.assertIsInstance(backend, LocalRagBackend)

    def test_unknown_backend_raises(self):
        with self.assertRaisesRegex(ValueError, "Unknown RAG backend"):
            create_backend("missing")

    def test_local_backend_ingests_and_searches(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "protocols").mkdir()
            (root / "protocols" / "modbus.md").write_text(
                "# Modbus\n\nModbus commonly uses TCP port 502 for PLC communication.\n",
                encoding="utf-8",
            )
            backend = create_backend("local")

            count = backend.ingest_path(root)
            results = backend.search("PLC Modbus TCP 502", top_k=1)

            self.assertEqual(count, 1)
            self.assertEqual(len(results), 1)
            self.assertTrue(results[0].doc_id.endswith("protocols/modbus.md"))
            self.assertIn("Modbus", results[0].text)


if __name__ == "__main__":
    unittest.main()
