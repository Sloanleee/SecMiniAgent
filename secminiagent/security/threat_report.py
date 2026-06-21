from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from secminiagent.threat.alerts import SecurityAlert
from secminiagent.threat.assets import IndustrialAsset
from secminiagent.threat.attack_chain import render_attack_chain_hypothesis
from secminiagent.threat.incidents import ThreatIncident
from secminiagent.threat.indicators import Indicator


def render_threat_report(
    *,
    assets: list[IndustrialAsset],
    alerts: list[SecurityAlert],
    incidents: list[ThreatIncident],
    asset_risks: list[dict[str, object]],
    iocs: list[Indicator] | None = None,
    data_sources: list[str] | None = None,
) -> str:
    iocs = iocs or []
    data_sources = data_sources or []
    severity_counts = Counter(incident.severity for incident in incidents)
    asset_type_counts = Counter(asset.asset_type for asset in assets)
    now = datetime.now(timezone.utc).isoformat()

    lines: list[str] = [
        "# Industrial Threat Analysis Report",
        "",
        f"Generated: {now}",
        "",
        "## Executive Summary",
        "",
        f"- Assets analyzed: {len(assets)}",
        f"- Alerts analyzed: {len(alerts)}",
        f"- Suspected incidents: {len(incidents)}",
        f"- High severity incidents: {severity_counts.get('high', 0)}",
        f"- IOC entries loaded: {len(iocs)}",
        "",
        "## Data Sources",
        "",
    ]
    if data_sources:
        lines.extend(f"- `{source}`" for source in data_sources)
    else:
        lines.append("- No explicit data source paths were provided.")

    lines.extend(["", "## Asset Overview", ""])
    if asset_type_counts:
        for asset_type, count in asset_type_counts.most_common():
            lines.append(f"- {asset_type}: {count}")
    else:
        lines.append("No assets were parsed.")

    lines.extend(["", "## Risk Ranking", ""])
    if asset_risks:
        lines.append("| Asset | IP | Type | Zone | Risk | Alerts |")
        lines.append("|---|---|---|---|---:|---:|")
        for item in asset_risks[:10]:
            lines.append(
                f"| {item['name']} | {item['ip']} | {item['asset_type']} | {item['zone']} | "
                f"{item['risk_level']} ({item['risk_score']}) | {item['alert_count']} |"
            )
    else:
        lines.append("No asset risk scores were generated.")

    lines.extend(["", "## Suspected Incidents", ""])
    if incidents:
        for incident in incidents:
            lines.extend(
                [
                    f"### {incident.incident_id}: {incident.title}",
                    "",
                    f"- Severity: {incident.severity}",
                    f"- Affected assets: {', '.join(incident.affected_assets) or 'unknown'}",
                    f"- Related alerts: {', '.join(incident.related_alerts) or 'none'}",
                    f"- Evidence: {'; '.join(incident.evidence)}",
                    f"- Recommended action: {incident.recommendation}",
                    "",
                ]
            )
    else:
        lines.append("No suspected incidents were generated from the available evidence.")

    lines.extend(["", "## Attack Chain Hypothesis", "", render_attack_chain_hypothesis(incidents), ""])
    lines.extend(["## Recommended Actions", ""])
    if incidents:
        lines.extend(
            [
                "- Validate whether the source hosts are authorized for OT access.",
                "- Review network segmentation between office, DMZ, and production zones.",
                "- Block or monitor IOC-matched sources and destinations.",
                "- Prioritize high-risk OT assets for containment and patch planning.",
                "- Preserve firewall, IDS, endpoint, and asset evidence for incident response.",
            ]
        )
    else:
        lines.append("- Continue monitoring and keep asset inventory, IOC lists, and vulnerability data current.")
    return "\n".join(lines).rstrip() + "\n"
