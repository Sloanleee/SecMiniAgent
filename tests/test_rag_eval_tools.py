import json
import tempfile
import unittest
from pathlib import Path

from secminiagent.tools.base import ToolContext
from secminiagent.tools.rag_eval_tools import EvaluateRagTool


class RagEvalToolsTest(unittest.IsolatedAsyncioTestCase):
    async def test_evaluate_rag_tool_outputs_markdown(self):
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
            context = ToolContext(cwd=root, max_output_chars=12000)

            result = await EvaluateRagTool().execute(
                {
                    "eval_path": "rag_eval.json",
                    "knowledge_path": "knowledge",
                    "backend": "local",
                    "top_k_values": [1, 3],
                    "query_strategies": ["description_port_hint"],
                },
                context,
            )

            self.assertTrue(result.success)
            self.assertIn("# RAG Evaluation Report", result.output)
            self.assertIn("| local | description_port_hint | 1 |", result.output)

    async def test_evaluate_rag_tool_can_write_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            knowledge = root / "knowledge"
            (knowledge / "protocols").mkdir(parents=True)
            (knowledge / "protocols" / "modbus.md").write_text("# Modbus\n\nTCP 502.\n", encoding="utf-8")
            (root / "rag_eval.json").write_text(
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
            context = ToolContext(cwd=root, max_output_chars=12000)

            result = await EvaluateRagTool().execute(
                {
                    "eval_path": "rag_eval.json",
                    "knowledge_path": "knowledge",
                    "backend": "local",
                    "write_file": True,
                    "output_path": ".secminiagent/reports/rag-evaluation.md",
                },
                context,
            )

            self.assertTrue(result.success)
            self.assertTrue((root / ".secminiagent" / "reports" / "rag-evaluation.md").exists())


if __name__ == "__main__":
    unittest.main()
