import unittest

from secminiagent.security.ot_rules import evaluate_ot_rules
from secminiagent.threat.alerts import SecurityAlert
from secminiagent.threat.assets import IndustrialAsset


class OTRulesTest(unittest.TestCase):
    def test_evaluate_ot_rules_detects_office_to_plc_and_ioc(self):
        assets = [
            IndustrialAsset(
                asset_id="plc-1",
                name="Line PLC",
                ip="172.16.20.10",
                asset_type="PLC",
                zone="production",
                criticality="high",
            ),
            IndustrialAsset(
                asset_id="office-1",
                name="Office PC",
                ip="10.10.5.23",
                asset_type="WORKSTATION",
                zone="office",
            ),
        ]
        alerts = [
            SecurityAlert(
                alert_id="a1",
                timestamp="2026-06-21T09:00:00Z",
                source_ip="10.10.5.23",
                destination_ip="172.16.20.10",
                destination_port=502,
                protocol="tcp",
                rule_name="modbus_write_attempt",
                severity="high",
            )
        ]

        matches = evaluate_ot_rules(assets=assets, alerts=alerts, iocs={"10.10.5.23"})
        rule_ids = {match.rule_id for match in matches}

        self.assertIn("OT_SUSPICIOUS_OT_PORT_ACCESS", rule_ids)
        self.assertIn("OT_OFFICE_TO_CRITICAL_ASSET", rule_ids)
        self.assertIn("OT_IOC_MATCH", rule_ids)


if __name__ == "__main__":
    unittest.main()
