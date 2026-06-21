from __future__ import annotations

from secminiagent.threat.assets import IndustrialAsset
from secminiagent.threat.alerts import SecurityAlert


SEVERITY_POINTS = {
    "critical": 40,
    "high": 30,
    "medium": 15,
    "low": 5,
    "info": 1,
}


def score_asset_risk(asset: IndustrialAsset, alerts: list[SecurityAlert]) -> tuple[int, str]:
    score = 10
    if asset.criticality.lower() == "high" or asset.is_critical_ot:
        score += 30
    if asset.zone.lower() in {"production", "control", "ot", "process"}:
        score += 10
    for alert in alerts:
        score += SEVERITY_POINTS.get(alert.severity.lower(), 5)
        if alert.destination_port in {102, 502, 2404, 20000, 44818, 4840}:
            score += 10
    score = min(score, 100)
    if score >= 75:
        label = "high"
    elif score >= 40:
        label = "medium"
    else:
        label = "low"
    return score, label
