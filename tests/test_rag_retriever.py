import tempfile
import unittest
from pathlib import Path

from secminiagent.rag.retriever import KnowledgeRetriever


class RagRetrieverTest(unittest.TestCase):
    def test_retrieves_modbus_knowledge(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "protocols").mkdir()
            (root / "protocols" / "modbus.md").write_text(
                "# Modbus\n\nModbus uses TCP port 502 for PLC communication.\n",
                encoding="utf-8",
            )
            (root / "protocols" / "opcua.md").write_text(
                "# OPC UA\n\nOPC UA often uses TCP port 4840.\n",
                encoding="utf-8",
            )
            retriever = KnowledgeRetriever()

            count = retriever.ingest_path(root)
            results = retriever.search("PLC Modbus TCP port 502", top_k=1)

            self.assertEqual(count, 2)
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].chunk.metadata["protocol"], "Modbus")

    def test_metadata_filter_limits_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "protocols").mkdir()
            (root / "playbooks").mkdir()
            (root / "protocols" / "modbus.md").write_text("# Modbus\n\nTCP 502.\n", encoding="utf-8")
            (root / "playbooks" / "response.md").write_text("# Response\n\nContain suspicious access.\n", encoding="utf-8")
            retriever = KnowledgeRetriever()

            retriever.ingest_path(root)
            results = retriever.search("suspicious access", top_k=5, filters={"source_type": "playbook"})

            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].chunk.metadata["source_type"], "playbook")


if __name__ == "__main__":
    unittest.main()
