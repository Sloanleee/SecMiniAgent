import tempfile
import unittest
from pathlib import Path

from secminiagent.tools.base import ToolContext
from secminiagent.tools.rag_tools import (
    ExplainAlertWithRagTool,
    GenerateRagThreatReportTool,
    IngestKnowledgeTool,
    SearchKnowledgeTool,
)


def write_knowledge(root: Path) -> None:
    (root / "knowledge" / "protocols").mkdir(parents=True)
    (root / "knowledge" / "playbooks").mkdir(parents=True)
    (root / "knowledge" / "protocols" / "modbus.md").write_text(
        "# Modbus\n\nModbus commonly uses TCP port 502 for PLC communication.\n",
        encoding="utf-8",
    )
    (root / "knowledge" / "playbooks" / "suspicious_ot_access.md").write_text(
        "# Suspicious OT Access Response\n\nVerify authorization and review segmentation.\n",
        encoding="utf-8",
    )


class RagToolsTest(unittest.IsolatedAsyncioTestCase):
    async def test_ingest_and_search_knowledge(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_knowledge(root)
            context = ToolContext(cwd=root, max_output_chars=8000)

            ingest = await IngestKnowledgeTool().execute({"path": "knowledge"}, context)
            search = await SearchKnowledgeTool().execute(
                {"path": "knowledge", "query": "PLC Modbus TCP 502", "top_k": 1},
                context,
            )

            self.assertTrue(ingest.success)
            self.assertGreaterEqual(ingest.metadata["chunk_count"], 2)
            self.assertTrue(search.success)
            self.assertIn("Modbus", search.output)

    async def test_explain_alert_with_rag(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_knowledge(root)
            context = ToolContext(cwd=root, max_output_chars=8000)

            result = await ExplainAlertWithRagTool().execute(
                {
                    "knowledge_path": "knowledge",
                    "source_ip": "10.10.5.23",
                    "destination_ip": "172.16.20.10",
                    "destination_port": 502,
                    "protocol": "tcp",
                    "action": "allow",
                    "severity": "high",
                    "description": "Office host accessed PLC Modbus service.",
                },
                context,
            )

            self.assertTrue(result.success)
            self.assertIn("Knowledge Evidence", result.output)
            self.assertIn("Modbus", result.output)

    async def test_generate_rag_threat_report_from_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_knowledge(root)
            (root / "examples").mkdir()
            (root / "examples" / "alerts.csv").write_text(
                "鏃堕棿,婧怚P,鐩殑IP,鐩殑绔彛,鍗忚,鍔ㄤ綔,绾у埆,鎻忚堪\n"
                "2026-06-22T10:00:00Z,10.10.5.23,172.16.20.10,502,tcp,allow,high,Office host accessed PLC Modbus service.\n",
                encoding="utf-8",
            )
            context = ToolContext(cwd=root, max_output_chars=12000)

            result = await GenerateRagThreatReportTool().execute(
                {
                    "alerts_path": "examples/alerts.csv",
                    "knowledge_path": "knowledge",
                    "top_k": 3,
                    "write_file": True,
                    "output_path": ".secminiagent/reports/rag.md",
                },
                context,
            )

            self.assertTrue(result.success)
            self.assertIn("# RAG-Enhanced Industrial Threat Report", result.output)
            self.assertIn("Knowledge Evidence", result.output)
            self.assertTrue((root / ".secminiagent" / "reports" / "rag.md").exists())


if __name__ == "__main__":
    unittest.main()
