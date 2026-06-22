import tempfile
import unittest
from pathlib import Path

from secminiagent.rag.chunker import chunk_document, load_markdown_documents
from secminiagent.rag.documents import KnowledgeDocument


class RagChunkerTest(unittest.TestCase):
    def test_load_markdown_documents_recursively(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "protocols").mkdir()
            (root / "protocols" / "modbus.md").write_text(
                "# Modbus\n\nPort: 502\n\nModbus is used by PLC communication.\n",
                encoding="utf-8",
            )

            docs = load_markdown_documents(root)

            self.assertEqual(len(docs), 1)
            self.assertEqual(docs[0].doc_id, "protocols/modbus")
            self.assertEqual(docs[0].metadata["source_type"], "protocol")
            self.assertEqual(docs[0].metadata["protocol"], "Modbus")
            self.assertEqual(docs[0].metadata["port"], 502)

    def test_chunk_document_preserves_title_and_metadata(self):
        document = KnowledgeDocument(
            doc_id="protocols/modbus",
            source_path="knowledge/protocols/modbus.md",
            title="Modbus",
            text="# Modbus\n\n## Risk\n\nUnexpected access to TCP/502 should be reviewed.\n",
            metadata={"source_type": "protocol", "protocol": "Modbus", "port": 502},
        )

        chunks = chunk_document(document, max_chars=80, overlap_chars=10)

        self.assertGreaterEqual(len(chunks), 1)
        self.assertEqual(chunks[0].doc_id, "protocols/modbus")
        self.assertEqual(chunks[0].metadata["protocol"], "Modbus")
        self.assertIn("Modbus", chunks[0].text)


if __name__ == "__main__":
    unittest.main()
