from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from secminiagent.parsers.alert_json_parser import parse_alerts_json
from secminiagent.parsers.asset_csv_parser import parse_assets_csv
from secminiagent.parsers.firewall_parser import parse_firewall_log
from secminiagent.parsers.ioc_parser import parse_iocs
from secminiagent.parsers.vuln_parser import parse_vulns_json
from secminiagent.security.ot_rules import evaluate_ot_rules
from secminiagent.security.threat_report import render_threat_report
from secminiagent.threat.alerts import SecurityAlert
from secminiagent.threat.analyzer import correlate_alerts_by_asset
from secminiagent.threat.assets import IndustrialAsset
from secminiagent.threat.indicators import Indicator
from secminiagent.threat.risk_score import score_asset_risk

from .base import BaseTool, ToolContext, ToolResult, truncate_text
from .file_tools import resolve_workspace_path


def _json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2)


def _resolve_existing_file(context: ToolContext, raw_path: str) -> Path:
    path = resolve_workspace_path(context.cwd, raw_path)
    if not path.exists():
        raise FileNotFoundError(f"File does not exist: {path.relative_to(context.cwd)}")
    if not path.is_file():
        raise IsADirectoryError(f"Not a file: {path.relative_to(context.cwd)}")
    return path


def _parse_alerts(path: Path, file_format: str = "auto") -> list[SecurityAlert]:
    normalized = file_format.lower().strip()
    if normalized == "json" or (normalized == "auto" and path.suffix.lower() == ".json"):
        return parse_alerts_json(path)
    if normalized in {"auto", "firewall", "log", "syslog"}:
        return parse_firewall_log(path)
    raise ValueError(f"Unsupported alert format: {file_format}")


def _load_assets(context: ToolContext, raw_path: str) -> list[IndustrialAsset]:
    return parse_assets_csv(_resolve_existing_file(context, raw_path))


def _load_alerts(context: ToolContext, raw_path: str, file_format: str = "auto") -> list[SecurityAlert]:
    return _parse_alerts(_resolve_existing_file(context, raw_path), file_format)


def _load_iocs(context: ToolContext, raw_path: str | None) -> list[Indicator]:
    if not raw_path:
        return []
    return parse_iocs(_resolve_existing_file(context, raw_path))


def _load_vulns(context: ToolContext, raw_path: str | None) -> list[dict[str, object]]:
    if not raw_path:
        return []
    return parse_vulns_json(_resolve_existing_file(context, raw_path))


def _alert_to_match(alert: SecurityAlert, iocs: set[str]) -> dict[str, object] | None:
    matched = []
    if alert.source_ip in iocs:
        matched.append(alert.source_ip)
    if alert.destination_ip in iocs:
        matched.append(alert.destination_ip)
    if not matched:
        return None
    return {"alert": alert.to_dict(), "matched_iocs": matched}


class ParseAssetsTool(BaseTool):
    name = "parse_assets"
    description = "Parse an industrial asset inventory CSV file into structured OT asset records."
    read_only = True
    input_schema = {
        "type": "object",
        "required": ["assets_path"],
        "properties": {
            "assets_path": {"type": "string", "description": "Workspace-relative CSV asset inventory path."},
            "max_items": {"type": "integer", "default": 50, "minimum": 1, "maximum": 500},
        },
    }

    async def execute(self, arguments: dict[str, Any], context: ToolContext) -> ToolResult:
        assets = _load_assets(context, str(arguments["assets_path"]))
        max_items = int(arguments.get("max_items") or 50)
        payload = {
            "asset_count": len(assets),
            "assets": [asset.to_dict() for asset in assets[:max_items]],
        }
        return ToolResult(
            True,
            truncate_text(_json(payload), context.max_output_chars),
            {"assets": [asset.to_dict() for asset in assets]},
        )


class ParseAlertsTool(BaseTool):
    name = "parse_alerts"
    description = "Parse IDS alert JSON or firewall log data into structured security alerts."
    read_only = True
    input_schema = {
        "type": "object",
        "required": ["alerts_path"],
        "properties": {
            "alerts_path": {"type": "string", "description": "Workspace-relative alert JSON or firewall log path."},
            "format": {"type": "string", "enum": ["auto", "json", "firewall"], "default": "auto"},
            "max_items": {"type": "integer", "default": 50, "minimum": 1, "maximum": 500},
        },
    }

    async def execute(self, arguments: dict[str, Any], context: ToolContext) -> ToolResult:
        alerts = _load_alerts(
            context,
            str(arguments["alerts_path"]),
            str(arguments.get("format") or "auto"),
        )
        max_items = int(arguments.get("max_items") or 50)
        payload = {
            "alert_count": len(alerts),
            "alerts": [alert.to_dict() for alert in alerts[:max_items]],
        }
        return ToolResult(
            True,
            truncate_text(_json(payload), context.max_output_chars),
            {"alerts": [alert.to_dict() for alert in alerts]},
        )


class ExtractIocsTool(BaseTool):
    name = "extract_iocs"
    description = "Parse a local IOC text file and classify IP, domain, URL, and hash indicators."
    read_only = True
    input_schema = {
        "type": "object",
        "required": ["ioc_path"],
        "properties": {
            "ioc_path": {"type": "string", "description": "Workspace-relative IOC text file path."},
        },
    }

    async def execute(self, arguments: dict[str, Any], context: ToolContext) -> ToolResult:
        iocs = _load_iocs(context, str(arguments["ioc_path"]))
        payload = {"ioc_count": len(iocs), "iocs": [ioc.to_dict() for ioc in iocs]}
        return ToolResult(True, truncate_text(_json(payload), context.max_output_chars), payload)


class MatchIocsTool(BaseTool):
    name = "match_iocs"
    description = "Match local IOC values against parsed alert source and destination IPs."
    read_only = True
    input_schema = {
        "type": "object",
        "required": ["alerts_path", "ioc_path"],
        "properties": {
            "alerts_path": {"type": "string"},
            "ioc_path": {"type": "string"},
            "format": {"type": "string", "enum": ["auto", "json", "firewall"], "default": "auto"},
        },
    }

    async def execute(self, arguments: dict[str, Any], context: ToolContext) -> ToolResult:
        alerts = _load_alerts(context, str(arguments["alerts_path"]), str(arguments.get("format") or "auto"))
        iocs = _load_iocs(context, str(arguments["ioc_path"]))
        ioc_values = {ioc.value for ioc in iocs}
        matches = [match for alert in alerts if (match := _alert_to_match(alert, ioc_values))]
        payload = {"match_count": len(matches), "matches": matches}
        return ToolResult(True, truncate_text(_json(payload), context.max_output_chars), payload)


class AnalyzeAssetRiskTool(BaseTool):
    name = "analyze_asset_risk"
    description = "Score industrial assets by criticality, zone, alert severity, and OT protocol exposure."
    read_only = True
    input_schema = {
        "type": "object",
        "required": ["assets_path", "alerts_path"],
        "properties": {
            "assets_path": {"type": "string"},
            "alerts_path": {"type": "string"},
            "format": {"type": "string", "enum": ["auto", "json", "firewall"], "default": "auto"},
        },
    }

    async def execute(self, arguments: dict[str, Any], context: ToolContext) -> ToolResult:
        assets = _load_assets(context, str(arguments["assets_path"]))
        alerts = _load_alerts(context, str(arguments["alerts_path"]), str(arguments.get("format") or "auto"))
        alerts_by_ip: dict[str, list[SecurityAlert]] = defaultdict(list)
        for alert in alerts:
            alerts_by_ip[alert.destination_ip].append(alert)
        risks: list[dict[str, object]] = []
        for asset in assets:
            score, level = score_asset_risk(asset, alerts_by_ip.get(asset.ip, []))
            risks.append(
                {
                    "asset_id": asset.asset_id,
                    "name": asset.name,
                    "ip": asset.ip,
                    "asset_type": asset.asset_type,
                    "zone": asset.zone,
                    "risk_score": score,
                    "risk_level": level,
                    "alert_count": len(alerts_by_ip.get(asset.ip, [])),
                }
            )
        risks.sort(key=lambda item: int(item["risk_score"]), reverse=True)
        payload = {"asset_count": len(assets), "risks": risks}
        return ToolResult(True, truncate_text(_json(payload), context.max_output_chars), payload)


class CorrelateAlertsTool(BaseTool):
    name = "correlate_alerts"
    description = "Correlate OT assets, alerts, optional IOCs, and vulnerabilities into suspected incidents."
    read_only = True
    input_schema = {
        "type": "object",
        "required": ["assets_path", "alerts_path"],
        "properties": {
            "assets_path": {"type": "string"},
            "alerts_path": {"type": "string"},
            "format": {"type": "string", "enum": ["auto", "json", "firewall"], "default": "auto"},
            "ioc_path": {"type": "string"},
            "vuln_path": {"type": "string"},
        },
    }

    async def execute(self, arguments: dict[str, Any], context: ToolContext) -> ToolResult:
        assets = _load_assets(context, str(arguments["assets_path"]))
        alerts = _load_alerts(context, str(arguments["alerts_path"]), str(arguments.get("format") or "auto"))
        iocs = _load_iocs(context, arguments.get("ioc_path"))
        vulns = _load_vulns(context, arguments.get("vuln_path"))
        incidents, matches, asset_risks = correlate_alerts_by_asset(
            assets,
            alerts,
            iocs=iocs,
            vulns=vulns,
        )
        payload = {
            "incident_count": len(incidents),
            "incidents": [incident.to_dict() for incident in incidents],
            "rule_matches": [match.to_dict() for match in matches],
            "asset_risks": asset_risks,
        }
        return ToolResult(True, truncate_text(_json(payload), context.max_output_chars), payload)


class DetectSuspiciousOtAccessTool(BaseTool):
    name = "detect_suspicious_ot_access"
    description = "Detect office-to-OT, cross-zone, IOC, and industrial protocol access to critical OT assets."
    read_only = True
    input_schema = {
        "type": "object",
        "required": ["assets_path", "alerts_path"],
        "properties": {
            "assets_path": {"type": "string"},
            "alerts_path": {"type": "string"},
            "format": {"type": "string", "enum": ["auto", "json", "firewall"], "default": "auto"},
            "ioc_path": {"type": "string"},
        },
    }

    async def execute(self, arguments: dict[str, Any], context: ToolContext) -> ToolResult:
        assets = _load_assets(context, str(arguments["assets_path"]))
        alerts = _load_alerts(context, str(arguments["alerts_path"]), str(arguments.get("format") or "auto"))
        iocs = {ioc.value for ioc in _load_iocs(context, arguments.get("ioc_path"))}
        matches = evaluate_ot_rules(assets=assets, alerts=alerts, iocs=iocs)
        interesting = [
            match
            for match in matches
            if match.rule_id
            in {
                "OT_SUSPICIOUS_OT_PORT_ACCESS",
                "OT_OFFICE_TO_CRITICAL_ASSET",
                "OT_CROSS_ZONE_ACCESS",
                "OT_IOC_MATCH",
            }
        ]
        payload = {"match_count": len(interesting), "matches": [match.to_dict() for match in interesting]}
        return ToolResult(True, truncate_text(_json(payload), context.max_output_chars), payload)


class DetectBruteforceTool(BaseTool):
    name = "detect_bruteforce"
    description = "Detect repeated login-like alerts from the same source to the same destination."
    read_only = True
    input_schema = {
        "type": "object",
        "required": ["alerts_path"],
        "properties": {
            "alerts_path": {"type": "string"},
            "format": {"type": "string", "enum": ["auto", "json", "firewall"], "default": "auto"},
            "threshold": {"type": "integer", "default": 5, "minimum": 2, "maximum": 100},
        },
    }

    async def execute(self, arguments: dict[str, Any], context: ToolContext) -> ToolResult:
        alerts = _load_alerts(context, str(arguments["alerts_path"]), str(arguments.get("format") or "auto"))
        threshold = int(arguments.get("threshold") or 5)
        grouped: dict[tuple[str, str, int], list[SecurityAlert]] = defaultdict(list)
        for alert in alerts:
            text = f"{alert.rule_name} {alert.message}".lower()
            if alert.destination_port in {22, 23, 3389, 445, 5900} or any(
                marker in text for marker in ["login", "auth", "fail", "password", "ssh", "rdp"]
            ):
                grouped[(alert.source_ip, alert.destination_ip, alert.destination_port)].append(alert)
        findings = []
        for (source, destination, port), items in grouped.items():
            if len(items) >= threshold:
                findings.append(
                    {
                        "source_ip": source,
                        "destination_ip": destination,
                        "destination_port": port,
                        "alert_count": len(items),
                        "alert_ids": [item.alert_id for item in items],
                        "recommendation": "Review authentication logs and block or rate-limit repeated login attempts.",
                    }
                )
        payload = {"finding_count": len(findings), "findings": findings}
        return ToolResult(True, truncate_text(_json(payload), context.max_output_chars), payload)


class DetectLateralMovementTool(BaseTool):
    name = "detect_lateral_movement"
    description = "Detect one source reaching many destination assets, a common lateral movement signal."
    read_only = True
    input_schema = {
        "type": "object",
        "required": ["alerts_path"],
        "properties": {
            "alerts_path": {"type": "string"},
            "assets_path": {"type": "string"},
            "format": {"type": "string", "enum": ["auto", "json", "firewall"], "default": "auto"},
            "threshold": {"type": "integer", "default": 3, "minimum": 2, "maximum": 100},
        },
    }

    async def execute(self, arguments: dict[str, Any], context: ToolContext) -> ToolResult:
        alerts = _load_alerts(context, str(arguments["alerts_path"]), str(arguments.get("format") or "auto"))
        assets = _load_assets(context, str(arguments["assets_path"])) if arguments.get("assets_path") else []
        assets_by_ip = {asset.ip: asset for asset in assets}
        threshold = int(arguments.get("threshold") or 3)
        destinations_by_source: dict[str, set[str]] = defaultdict(set)
        alerts_by_source: dict[str, list[SecurityAlert]] = defaultdict(list)
        for alert in alerts:
            destinations_by_source[alert.source_ip].add(alert.destination_ip)
            alerts_by_source[alert.source_ip].append(alert)
        findings = []
        for source, destinations in destinations_by_source.items():
            if len(destinations) < threshold:
                continue
            destination_assets = [
                assets_by_ip[ip].to_dict() if ip in assets_by_ip else {"ip": ip}
                for ip in sorted(destinations)
            ]
            findings.append(
                {
                    "source_ip": source,
                    "destination_count": len(destinations),
                    "destinations": destination_assets,
                    "alert_ids": [alert.alert_id for alert in alerts_by_source[source]],
                    "recommendation": "Check whether the source is an approved scanner or jump host. Investigate host activity if unexpected.",
                }
            )
        payload = {"finding_count": len(findings), "findings": findings}
        return ToolResult(True, truncate_text(_json(payload), context.max_output_chars), payload)


class GenerateThreatReportTool(BaseTool):
    name = "generate_threat_report"
    description = "Generate a Markdown industrial threat analysis report from assets, alerts, optional IOCs, and vulnerabilities."
    read_only = True
    input_schema = {
        "type": "object",
        "required": ["assets_path", "alerts_path"],
        "properties": {
            "assets_path": {"type": "string"},
            "alerts_path": {"type": "string"},
            "format": {"type": "string", "enum": ["auto", "json", "firewall"], "default": "auto"},
            "ioc_path": {"type": "string"},
            "vuln_path": {"type": "string"},
            "write_file": {"type": "boolean", "default": False},
            "output_path": {"type": "string"},
        },
    }

    async def execute(self, arguments: dict[str, Any], context: ToolContext) -> ToolResult:
        assets_path = str(arguments["assets_path"])
        alerts_path = str(arguments["alerts_path"])
        ioc_path = arguments.get("ioc_path")
        vuln_path = arguments.get("vuln_path")
        assets = _load_assets(context, assets_path)
        alerts = _load_alerts(context, alerts_path, str(arguments.get("format") or "auto"))
        iocs = _load_iocs(context, ioc_path)
        vulns = _load_vulns(context, vuln_path)
        incidents, matches, asset_risks = correlate_alerts_by_asset(
            assets,
            alerts,
            iocs=iocs,
            vulns=vulns,
        )
        data_sources = [assets_path, alerts_path]
        if ioc_path:
            data_sources.append(str(ioc_path))
        if vuln_path:
            data_sources.append(str(vuln_path))
        report = render_threat_report(
            assets=assets,
            alerts=alerts,
            incidents=incidents,
            asset_risks=asset_risks,
            iocs=iocs,
            data_sources=data_sources,
        )
        metadata: dict[str, Any] = {
            "assets": [asset.to_dict() for asset in assets],
            "alerts": [alert.to_dict() for alert in alerts],
            "iocs": [ioc.to_dict() for ioc in iocs],
            "rule_matches": [match.to_dict() for match in matches],
            "incidents": [incident.to_dict() for incident in incidents],
            "asset_risks": asset_risks,
        }
        if bool(arguments.get("write_file", False)):
            raw_output_path = str(arguments.get("output_path") or "").strip()
            if raw_output_path:
                output_path = resolve_workspace_path(context.cwd, raw_output_path)
            else:
                stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
                output_path = context.cwd / ".secminiagent" / "reports" / f"threat-report-{stamp}.md"
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(report, encoding="utf-8")
            metadata["report_path"] = str(output_path.relative_to(context.cwd))
            report += f"\nReport written to `{output_path.relative_to(context.cwd)}`.\n"
        return ToolResult(True, truncate_text(report, context.max_output_chars), metadata)
