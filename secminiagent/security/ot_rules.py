from __future__ import annotations

from dataclasses import dataclass

from secminiagent.threat.alerts import SecurityAlert
from secminiagent.threat.assets import IndustrialAsset
from secminiagent.threat.incidents import ThreatIncident


OT_PORTS = {102: "S7comm", 502: "Modbus", 20000: "DNP3", 2404: "IEC-104", 44818: "EtherNet/IP", 4840: "OPC UA"}
OFFICE_ZONE_NAMES = {"office", "it", "corp", "enterprise"}
OT_ZONE_NAMES = {"ot", "production", "control", "process", "scada"}


@dataclass(frozen=True, slots=True)
class OTRuleMatch:
    rule_id: str
    title: str
    severity: str
    asset: IndustrialAsset | None
    alert: SecurityAlert | None
    evidence: str
    recommendation: str

    def to_incident(self, index: int) -> ThreatIncident:
        asset_ids = [self.asset.asset_id] if self.asset else []
        alert_ids = [self.alert.alert_id] if self.alert else []
        return ThreatIncident(
            incident_id=f"incident-{index}",
            title=f"{self.rule_id}: {self.title}",
            severity=self.severity,
            affected_assets=asset_ids,
            related_alerts=alert_ids,
            evidence=[self.evidence],
            recommendation=self.recommendation,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "asset": self.asset.to_dict() if self.asset else None,
            "alert": self.alert.to_dict() if self.alert else None,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }


def evaluate_ot_rules(
    *,
    assets: list[IndustrialAsset],
    alerts: list[SecurityAlert],
    iocs: set[str] | None = None,
    vulns: list[dict[str, object]] | None = None,
) -> list[OTRuleMatch]:
    iocs = iocs or set()
    vulns = vulns or []
    assets_by_ip = {asset.ip: asset for asset in assets if asset.ip}
    matches: list[OTRuleMatch] = []

    source_to_assets: dict[str, set[str]] = {}
    for alert in alerts:
        asset = assets_by_ip.get(alert.destination_ip)
        if asset is None:
            continue
        source_to_assets.setdefault(alert.source_ip, set()).add(asset.asset_id)

        if asset.is_critical_ot and alert.destination_port in OT_PORTS:
            matches.append(
                OTRuleMatch(
                    rule_id="OT_SUSPICIOUS_OT_PORT_ACCESS",
                    title=f"Access to {OT_PORTS[alert.destination_port]} service on critical OT asset",
                    severity="high",
                    asset=asset,
                    alert=alert,
                    evidence=f"{alert.source_ip} -> {asset.ip}:{alert.destination_port} ({OT_PORTS[alert.destination_port]})",
                    recommendation="Verify the source host is authorized for OT protocol access. Isolate or block unauthorized traffic.",
                )
            )

        if _is_office_source(alert.source_ip, assets) and asset.is_critical_ot:
            matches.append(
                OTRuleMatch(
                    rule_id="OT_OFFICE_TO_CRITICAL_ASSET",
                    title="Office or IT source accessed critical OT asset",
                    severity="high",
                    asset=asset,
                    alert=alert,
                    evidence=f"{alert.source_ip} accessed {asset.name} ({asset.asset_type}) at {asset.ip}",
                    recommendation="Check segmentation policy. Office-to-OT access should be routed through controlled jump hosts.",
                )
            )

        if _is_cross_zone(alert.source_ip, asset, assets):
            matches.append(
                OTRuleMatch(
                    rule_id="OT_CROSS_ZONE_ACCESS",
                    title="Cross-zone access to OT asset",
                    severity="medium",
                    asset=asset,
                    alert=alert,
                    evidence=f"{alert.source_ip} accessed {asset.ip} in zone {asset.zone}",
                    recommendation="Validate firewall policy and confirm whether this cross-zone flow is expected.",
                )
            )

        if alert.source_ip in iocs or alert.destination_ip in iocs:
            matches.append(
                OTRuleMatch(
                    rule_id="OT_IOC_MATCH",
                    title="Alert matched local IOC list",
                    severity="high",
                    asset=asset,
                    alert=alert,
                    evidence=f"IOC match in alert {alert.alert_id}: {alert.source_ip} -> {alert.destination_ip}",
                    recommendation="Escalate for incident response. Block the IOC and collect host/network evidence.",
                )
            )

    for source_ip, asset_ids in source_to_assets.items():
        if len(asset_ids) >= 3:
            matches.append(
                OTRuleMatch(
                    rule_id="OT_MULTIPLE_ASSET_PROBING",
                    title="Single source accessed multiple OT assets",
                    severity="medium",
                    asset=None,
                    alert=None,
                    evidence=f"{source_ip} accessed {len(asset_ids)} OT assets: {', '.join(sorted(asset_ids))}",
                    recommendation="Investigate whether the source is scanning or performing unauthorized discovery.",
                )
            )

    for vuln in vulns:
        asset_id = str(vuln.get("asset_id") or "")
        severity = str(vuln.get("severity") or "").lower()
        if severity not in {"critical", "high"}:
            continue
        asset = next((item for item in assets if item.asset_id == asset_id), None)
        if asset is None:
            continue
        asset_alerts = [alert for alert in alerts if alert.destination_ip == asset.ip]
        if asset_alerts:
            matches.append(
                OTRuleMatch(
                    rule_id="OT_HIGH_RISK_CVE_EXPOSED",
                    title="High-risk vulnerability asset has recent alerts",
                    severity="high",
                    asset=asset,
                    alert=asset_alerts[0],
                    evidence=f"{asset.name} has {vuln.get('cve', 'high-risk vulnerability')} and {len(asset_alerts)} related alert(s)",
                    recommendation="Prioritize patching or compensating controls. Restrict access until exposure is remediated.",
                )
            )
    return matches


def _is_office_source(source_ip: str, assets: list[IndustrialAsset]) -> bool:
    source_asset = next((asset for asset in assets if asset.ip == source_ip), None)
    if source_asset:
        return source_asset.zone.lower() in OFFICE_ZONE_NAMES or source_asset.normalized_type in {"WORKSTATION", "SERVER"}
    return source_ip.startswith("10.10.") or source_ip.startswith("192.168.10.")


def _is_cross_zone(source_ip: str, destination_asset: IndustrialAsset, assets: list[IndustrialAsset]) -> bool:
    source_asset = next((asset for asset in assets if asset.ip == source_ip), None)
    if source_asset is None:
        return False
    return source_asset.zone.lower() != destination_asset.zone.lower() and destination_asset.zone.lower() in OT_ZONE_NAMES
