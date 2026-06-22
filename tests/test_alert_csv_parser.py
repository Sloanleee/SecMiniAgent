import tempfile
import unittest
from pathlib import Path

from secminiagent.parsers.alert_csv_parser import parse_alerts_csv


class AlertCsvParserTest(unittest.TestCase):
    def test_parse_chinese_csv_columns(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "alerts.csv"
            path.write_text(
                "\u65f6\u95f4,\u6e90IP,\u76ee\u7684IP,\u76ee\u7684\u7aef\u53e3,\u534f\u8bae,\u52a8\u4f5c,\u7ea7\u522b,\u63cf\u8ff0\n"
                "2026-06-22T10:00:00Z,10.10.5.23,172.16.20.10,502,tcp,allow,high,Office host accessed PLC Modbus service.\n",
                encoding="utf-8",
            )

            alerts = parse_alerts_csv(path)

            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0].alert_id, "csv-1")
            self.assertEqual(alerts[0].timestamp, "2026-06-22T10:00:00Z")
            self.assertEqual(alerts[0].source_ip, "10.10.5.23")
            self.assertEqual(alerts[0].destination_ip, "172.16.20.10")
            self.assertEqual(alerts[0].destination_port, 502)
            self.assertEqual(alerts[0].protocol, "tcp")
            self.assertEqual(alerts[0].severity, "high")
            self.assertIn("allow", alerts[0].rule_name)
            self.assertIn("Modbus", alerts[0].message)

    def test_parse_english_csv_aliases(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "alerts.csv"
            path.write_text(
                "timestamp,source_ip,destination_ip,destination_port,protocol,action,severity,description\n"
                "2026-06-22T10:00:00Z,10.10.5.23,172.16.20.10,4840,tcp,deny,medium,OPC UA access attempt.\n",
                encoding="utf-8",
            )

            alerts = parse_alerts_csv(path)

            self.assertEqual(alerts[0].destination_port, 4840)
            self.assertEqual(alerts[0].rule_name, "csv_deny")
            self.assertEqual(alerts[0].message, "OPC UA access attempt.")


if __name__ == "__main__":
    unittest.main()
