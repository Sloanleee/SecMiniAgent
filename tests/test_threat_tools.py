import tempfile
import unittest
from pathlib import Path

from secminiagent.tools.base import ToolContext
from secminiagent.tools.threat_tools import (
    AnalyzeAssetRiskTool,
    DetectBruteforceTool,
    GenerateThreatReportTool,
    MatchIocsTool,
    ParseAssetsTool,
)


def write_demo_files(root: Path) -> None:
    (root / "assets.csv").write_text(
        "asset_id,name,ip,asset_type,zone,criticality,protocols\n"
        "plc-1,Line PLC,172.16.20.10,PLC,production,high,Modbus\n"
        "jump-1,Jump Host,172.16.10.5,SERVER,dmz,medium,RDP\n"
        "office-1,Office PC,10.10.5.23,WORKSTATION,office,medium,HTTP\n",
        encoding="utf-8",
    )
    (root / "alerts.json").write_text(
        """
{
  "alerts": [
    {"alert_id":"a1","timestamp":"2026-06-21T09:00:00Z","source_ip":"10.10.5.23","destination_ip":"172.16.20.10","destination_port":502,"protocol":"tcp","rule_name":"modbus_write_attempt","severity":"high"},
    {"alert_id":"a2","timestamp":"2026-06-21T09:10:00Z","source_ip":"203.0.113.50","destination_ip":"172.16.10.5","destination_port":3389,"protocol":"tcp","rule_name":"rdp_failed_login","severity":"high"},
    {"alert_id":"a3","timestamp":"2026-06-21T09:10:10Z","source_ip":"203.0.113.50","destination_ip":"172.16.10.5","destination_port":3389,"protocol":"tcp","rule_name":"rdp_failed_login","severity":"high"},
    {"alert_id":"a4","timestamp":"2026-06-21T09:10:20Z","source_ip":"203.0.113.50","destination_ip":"172.16.10.5","destination_port":3389,"protocol":"tcp","rule_name":"rdp_failed_login","severity":"high"}
  ]
}
""".strip(),
        encoding="utf-8",
    )
    (root / "ioc.txt").write_text("203.0.113.50\n", encoding="utf-8")
    (root / "vulns.json").write_text(
        '{"vulnerabilities":[{"asset_id":"plc-1","severity":"high","cve":"CVE-2024-demo"}]}',
        encoding="utf-8",
    )


class ThreatToolsTest(unittest.IsolatedAsyncioTestCase):
    async def test_parse_assets_tool_returns_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_demo_files(root)
            result = await ParseAssetsTool().execute(
                {"assets_path": "assets.csv"},
                ToolContext(cwd=root, max_output_chars=8000),
            )
            self.assertTrue(result.success)
            self.assertEqual(len(result.metadata["assets"]), 3)

    async def test_match_iocs_and_detect_bruteforce(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_demo_files(root)
            context = ToolContext(cwd=root, max_output_chars=8000)

            ioc_result = await MatchIocsTool().execute(
                {"alerts_path": "alerts.json", "ioc_path": "ioc.txt"},
                context,
            )
            brute_result = await DetectBruteforceTool().execute(
                {"alerts_path": "alerts.json", "threshold": 3},
                context,
            )

            self.assertTrue(ioc_result.success)
            self.assertGreaterEqual(ioc_result.metadata["match_count"], 1)
            self.assertTrue(brute_result.success)
            self.assertEqual(brute_result.metadata["finding_count"], 1)

    async def test_analyze_risk_and_generate_threat_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_demo_files(root)
            context = ToolContext(cwd=root, max_output_chars=12000)

            risk_result = await AnalyzeAssetRiskTool().execute(
                {"assets_path": "assets.csv", "alerts_path": "alerts.json"},
                context,
            )
            report_result = await GenerateThreatReportTool().execute(
                {
                    "assets_path": "assets.csv",
                    "alerts_path": "alerts.json",
                    "ioc_path": "ioc.txt",
                    "vuln_path": "vulns.json",
                    "write_file": True,
                    "output_path": ".secminiagent/reports/threat.md",
                },
                context,
            )

            self.assertTrue(risk_result.success)
            plc_risk = next(item for item in risk_result.metadata["risks"] if item["asset_id"] == "plc-1")
            self.assertEqual(plc_risk["risk_level"], "high")
            self.assertTrue(report_result.success)
            self.assertIn("# Industrial Threat Analysis Report", report_result.output)
            self.assertGreaterEqual(len(report_result.metadata["incidents"]), 1)
            self.assertTrue((root / ".secminiagent" / "reports" / "threat.md").exists())


if __name__ == "__main__":
    unittest.main()
