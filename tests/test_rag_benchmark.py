import json
import sys
import tempfile
import types
import unittest
from pathlib import Path

from secminiagent.llm.fake import FakeLLMClient
from secminiagent.rag.backends import ChromaRagBackend, LocalRagBackend, create_backend
from secminiagent.rag.benchmark import BenchmarkRow, render_benchmark_markdown, run_rag_benchmark


class FakeLLMRagBenchmarkRoutingTest(unittest.IsolatedAsyncioTestCase):
    async def test_rag_benchmark_prompt_routes_to_local_backend_by_default(self):
        client = FakeLLMClient()

        response = await client.complete(
            messages=[client.user_message("evaluate rag benchmark")],
            tools=[],
            system_prompt="",
        )

        self.assertEqual(response.tool_calls[0].name, "evaluate_rag")
        self.assertEqual(response.tool_calls[0].arguments["backend"], "local")

    async def test_rag_benchmark_chroma_prompt_routes_to_chroma_backend(self):
        client = FakeLLMClient()

        response = await client.complete(
            messages=[client.user_message("evaluate rag benchmark with chroma")],
            tools=[],
            system_prompt="",
        )

        self.assertEqual(response.tool_calls[0].name, "evaluate_rag")
        self.assertEqual(response.tool_calls[0].arguments["backend"], "chroma")

    async def test_rag_benchmark_all_prompt_routes_to_all_backends(self):
        client = FakeLLMClient()

        response = await client.complete(
            messages=[client.user_message("evaluate rag benchmark all")],
            tools=[],
            system_prompt="",
        )

        self.assertEqual(response.tool_calls[0].name, "evaluate_rag")
        self.assertEqual(response.tool_calls[0].arguments["backend"], "all")


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

    def test_chroma_backend_resets_existing_collection_before_use(self):
        original_chromadb = sys.modules.get("chromadb")

        class FakeClient:
            def __init__(self, path):
                self.path = path
                self.deleted_names = []
                self.collection = object()
                fake_module.client = self

            def delete_collection(self, name):
                self.deleted_names.append(name)

            def get_or_create_collection(self, name):
                self.created_name = name
                return self.collection

        fake_module = types.SimpleNamespace(PersistentClient=FakeClient)
        sys.modules["chromadb"] = fake_module
        try:
            backend = ChromaRagBackend(persist_path=Path("fake-store"), collection_name="existing")
        finally:
            if original_chromadb is None:
                sys.modules.pop("chromadb", None)
            else:
                sys.modules["chromadb"] = original_chromadb

        self.assertEqual(fake_module.client.deleted_names, ["existing"])
        self.assertEqual(fake_module.client.created_name, "existing")
        self.assertIs(backend.collection, fake_module.client.collection)

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
            self.assertIn("- Backends: local", markdown)
            self.assertIn("- Top-K values: 1", markdown)
            self.assertIn("- Query strategies: description_port_hint", markdown)
            self.assertIn("| Backend | Query Strategy | Top-K | Recall@K | Precision@K | MRR | Hit Rate |", markdown)
            self.assertIn("| local | description_port_hint | 1 |", markdown)

    def test_render_benchmark_markdown_lists_unique_metadata_values_in_row_order(self):
        rows = [
            BenchmarkRow("local", "description_only", 1, 1.0, 1.0, 1.0, 1.0, 2),
            BenchmarkRow("chroma", "description_only", 1, 1.0, 1.0, 1.0, 1.0, 2),
            BenchmarkRow("local", "description_port", 3, 1.0, 1.0, 1.0, 1.0, 2),
        ]

        markdown = render_benchmark_markdown(rows, eval_path="eval.json", knowledge_path="knowledge")

        self.assertIn("- Backends: local, chroma", markdown)
        self.assertIn("- Top-K values: 1, 3", markdown)
        self.assertIn("- Query strategies: description_only, description_port", markdown)


if __name__ == "__main__":
    unittest.main()
