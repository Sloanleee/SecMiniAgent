import tempfile
import unittest
from pathlib import Path

from secminiagent.parsers.alert_json_parser import parse_alerts_json
from secminiagent.parsers.asset_csv_parser import parse_assets_csv
from secminiagent.parsers.firewall_parser import parse_firewall_log
from secminiagent.parsers.ioc_parser import parse_iocs
from secminiagent.parsers.vuln_parser import parse_vulns_json


class ThreatParsersTest(unittest.TestCase):
    def test_parse_industrial_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "assets.csv").write_text(
                "asset_id,name,ip,asset_type,zone,criticality,protocols\n"
                "plc-1,Line PLC,172.16.20.10,PLC,production,high,\"Modbus,S7comm\"\n",
                encoding="utf-8",
            )
            (root / "alerts.json").write_text(
                '{"alerts":[{"id":"a1","src":"10.10.5.23","dst":"172.16.20.10","port":502,"severity":"high"}]}',
                encoding="utf-8",
            )
            (root / "firewall.log").write_text(
                "2026-06-21T09:00:00Z fw01 src=10.10.5.23 dst=172.16.20.10 dpt=502 proto=tcp action=allow\n",
                encoding="utf-8",
            )
            (root / "ioc.txt").write_text("203.0.113.50\nexample.org\n", encoding="utf-8")
            (root / "vulns.json").write_text(
                '{"vulnerabilities":[{"asset_id":"plc-1","severity":"high"}]}',
                encoding="utf-8",
            )

            assets = parse_assets_csv(root / "assets.csv")
            alerts = parse_alerts_json(root / "alerts.json")
            firewall_alerts = parse_firewall_log(root / "firewall.log")
            iocs = parse_iocs(root / "ioc.txt")
            vulns = parse_vulns_json(root / "vulns.json")

            self.assertEqual(assets[0].asset_id, "plc-1")
            self.assertTrue(assets[0].is_critical_ot)
            self.assertEqual(alerts[0].destination_port, 502)
            self.assertEqual(firewall_alerts[0].source_ip, "10.10.5.23")
            self.assertEqual(iocs[0].indicator_type, "ip")
            self.assertEqual(vulns[0]["asset_id"], "plc-1")


if __name__ == "__main__":
    unittest.main()
