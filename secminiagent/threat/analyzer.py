from __future__ import annotations

from collections import defaultdict

from secminiagent.security.ot_rules import OTRuleMatch, evaluate_ot_rules
from secminiagent.threat.alerts import SecurityAlert
from secminiagent.threat.assets import IndustrialAsset
from secminiagent.threat.incidents import ThreatIncident
from secminiagent.threat.indicators import Indicator
from secminiagent.threat.risk_score import score_asset_risk


def correlate_alerts_by_asset(
    assets: list[IndustrialAsset],
    alerts: list[SecurityAlert],
    *,
    iocs: list[Indicator] | None = None,
    vulns: list[dict[str, object]] | None = None,
) -> tuple[list[ThreatIncident], list[OTRuleMatch], list[dict[str, object]]]:
    ioc_values = {ioc.value for ioc in iocs or []}
    matches = evaluate_ot_rules(assets=assets, alerts=alerts, iocs=ioc_values, vulns=vulns or [])
    incidents = [match.to_incident(index) for index, match in enumerate(matches, start=1)]

    alerts_by_asset_ip: dict[str, list[SecurityAlert]] = defaultdict(list)
    for alert in alerts:
        alerts_by_asset_ip[alert.destination_ip].append(alert)

    asset_risks: list[dict[str, object]] = []
    for asset in assets:
        score, label = score_asset_risk(asset, alerts_by_asset_ip.get(asset.ip, []))
        asset_risks.append(
            {
                "asset_id": asset.asset_id,
                "name": asset.name,
                "ip": asset.ip,
                "asset_type": asset.asset_type,
                "zone": asset.zone,
                "risk_score": score,
                "risk_level": label,
                "alert_count": len(alerts_by_asset_ip.get(asset.ip, [])),
            }
        )
    asset_risks.sort(key=lambda item: int(item["risk_score"]), reverse=True)
    return incidents, matches, asset_risks
