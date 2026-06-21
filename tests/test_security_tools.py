import tempfile
import unittest
from pathlib import Path

from secminiagent.tools.base import ToolContext
from secminiagent.tools.security_tools import GenerateSecurityReportTool, ScanSecretsTool


class SecurityToolsTest(unittest.IsolatedAsyncioTestCase):
    async def test_scan_secrets_tool_returns_findings_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "settings.py").write_text('token = "abcdef1234567890"\n', encoding="utf-8")
            result = await ScanSecretsTool().execute({}, ToolContext(cwd=root, max_output_chars=4000))
            self.assertTrue(result.success)
            self.assertGreaterEqual(len(result.metadata["findings"]), 1)

    async def test_generate_report_tool_outputs_markdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("eval(user_input)\n", encoding="utf-8")
            result = await GenerateSecurityReportTool().execute({}, ToolContext(cwd=root, max_output_chars=4000))
            self.assertTrue(result.success)
            self.assertIn("# Security Review Report", result.output)
            self.assertIn("PY_EVAL_EXEC", result.output)

    async def test_generate_report_tool_can_write_markdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("eval(user_input)\n", encoding="utf-8")
            result = await GenerateSecurityReportTool().execute(
                {"write_file": True, "output_path": ".secminiagent/reports/report.md"},
                ToolContext(cwd=root, max_output_chars=4000),
            )
            self.assertTrue(result.success)
            self.assertTrue((root / ".secminiagent" / "reports" / "report.md").exists())
            self.assertEqual(result.metadata["report_path"], ".secminiagent\\reports\\report.md" if "\\" in result.metadata["report_path"] else ".secminiagent/reports/report.md")


if __name__ == "__main__":
    unittest.main()
