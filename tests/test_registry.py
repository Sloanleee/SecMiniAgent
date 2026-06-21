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


if __name__ == "__main__":
    unittest.main()
