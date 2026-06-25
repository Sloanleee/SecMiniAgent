import tempfile
import unittest
from pathlib import Path

from secminiagent.tools.base import ToolContext
from secminiagent.tools.file_tools import ReadFileTool
from secminiagent.tools.registry import ToolRegistry


class RegistryTest(unittest.IsolatedAsyncioTestCase):
    async def test_executes_registered_tool(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.txt").write_text("hello", encoding="utf-8")
            registry = ToolRegistry()
            registry.register(ReadFileTool())
            result = await registry.execute("read_file", {"file_path": "a.txt"}, ToolContext(cwd=root, max_output_chars=2000))
            self.assertTrue(result.success)
            self.assertIn("hello", result.output)

    async def test_cli_registry_includes_rag_tools(self):
        from secminiagent.cli import build_registry

        registry = build_registry()
        names = set(registry.names())

        self.assertIn("ingest_knowledge", names)
        self.assertIn("search_knowledge", names)
        self.assertIn("explain_alert_with_rag", names)
        self.assertIn("generate_rag_threat_report", names)

    async def test_cli_registry_includes_rag_eval_tool(self):
        from secminiagent.cli import build_registry

        registry = build_registry()
        names = set(registry.names())

        self.assertIn("evaluate_rag", names)


if __name__ == "__main__":
    unittest.main()
