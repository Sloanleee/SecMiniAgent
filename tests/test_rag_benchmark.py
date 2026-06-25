import json
import tempfile
import unittest
from pathlib import Path

from secminiagent.rag.backends import LocalRagBackend, create_backend
from secminiagent.rag.benchmark import render_benchmark_markdown, run_rag_benchmark


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

    def test_chroma_backend_without_dependency_has_friendly_error(self):
        import importlib.util

        if importlib.util.find_spec("chromadb") is not None:
            self.skipTest("chromadb is installed; missing dependency path is not applicable")

        with self.assertRaisesRegex(RuntimeError, "Chroma backend requires chromadb"):
            create_backend("chroma", persist_path=Path(".secminiagent/rag/chroma"))

    def test_chroma_backend_ingests_and_searches_when_installed(self):
        import importlib.util

        if importlib.util.find_spec("chromadb") is None:
            self.skipTest("chromadb is not installed")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            knowledge = root / "knowledge"
            (knowledge / "protocols").mkdir(parents=True)
            (knowledge / "protocols" / "modbus.md").write_text(
                "# Modbus\n\nModbus commonly uses TCP port 502 for PLC communication.\n",
                encoding="utf-8",
            )
            backend = create_backend("chroma", persist_path=root / ".secminiagent" / "rag" / "chroma")

            count = backend.ingest_path(knowledge)
            results = backend.search("PLC Modbus TCP 502", top_k=1)

            self.assertEqual(count, 1)
            self.assertEqual(len(results), 1)
            self.assertTrue(results[0].doc_id.endswith("protocols/modbus.md"))


class RagBenchmarkEngineTest(unittest.TestCase):
    def test_run_local_benchmark(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            knowledge = root / "knowledge"
            (knowledge / "protocols").mkdir(parents=True)
            (knowledge / "protocols" / "modbus.md").write_text(
                "# Modbus\n\nModbus commonly uses TCP port 502 for PLC communication.\n",
                encoding="utf-8",
            )
            eval_path = root / "rag_eval.json"
            eval_path.write_text(
                json.dumps(
                    [
                        {
                            "id": "modbus",
                            "description": "PLC Modbus service access.",
                            "destination_port": 502,
                            "expected_doc_ids": ["knowledge/protocols/modbus.md"],
                        }
                    ]
                ),
                encoding="utf-8",
            )

            rows = run_rag_benchmark(
                eval_path=eval_path,
                knowledge_path=knowledge,
                backends=["local"],
                top_k_values=[1, 3],
                query_strategies=["description_port_hint"],
            )

            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0].backend, "local")
            self.assertEqual(rows[0].query_strategy, "description_port_hint")
            self.assertEqual(rows[0].top_k, 1)
            self.assertGreaterEqual(rows[0].recall_at_k, 0.0)
            self.assertGreaterEqual(rows[0].precision_at_k, 0.0)

    def test_render_benchmark_markdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            knowledge = root / "knowledge"
            (knowledge / "protocols").mkdir(parents=True)
            (knowledge / "protocols" / "modbus.md").write_text("# Modbus\n\nTCP 502.\n", encoding="utf-8")
            eval_path = root / "rag_eval.json"
            eval_path.write_text(
                json.dumps(
                    [
                        {
                            "id": "modbus",
                            "description": "Modbus TCP 502",
                            "destination_port": 502,
                            "expected_doc_ids": ["knowledge/protocols/modbus.md"],
                        }
                    ]
                ),
                encoding="utf-8",
            )
            rows = run_rag_benchmark(
                eval_path=eval_path,
                knowledge_path=knowledge,
                backends=["local"],
                top_k_values=[1],
                query_strategies=["description_port_hint"],
            )

            markdown = render_benchmark_markdown(
                rows,
                eval_path=str(eval_path),
                knowledge_path=str(knowledge),
            )

            self.assertIn("# RAG Evaluation Report", markdown)
            self.assertIn("| Backend | Query Strategy | Top-K | Recall@K | Precision@K | MRR | Hit Rate |", markdown)
            self.assertIn("| local | description_port_hint | 1 |", markdown)


if __name__ == "__main__":
    unittest.main()
