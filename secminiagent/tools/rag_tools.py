from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from secminiagent.parsers.alert_csv_parser import parse_alerts_csv
from secminiagent.rag.retriever import KnowledgeRetriever
from secminiagent.threat.alerts import SecurityAlert

from .base import BaseTool, ToolContext, ToolResult, truncate_text
from .file_tools import resolve_workspace_path


OT_PORT_HINTS = {
    502: "Modbus PLC industrial control protocol suspicious OT access",
    102: "S7comm Siemens PLC industrial control protocol access",
    4840: "OPC UA industrial data exchange OT access",
}


def _json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2)


def build_alert_query(alert: SecurityAlert, action: str = "") -> str:
    parts = [
        alert.severity,
        alert.protocol,
        action,
        f"traffic to port {alert.destination_port}",
        alert.message,
    ]
    hint = OT_PORT_HINTS.get(alert.destination_port)
    if hint:
        parts.append(hint)
    return " ".join(part for part in parts if part).strip()


def _retriever_for(context: ToolContext, knowledge_path: str) -> KnowledgeRetriever:
    path = resolve_workspace_path(context.cwd, knowledge_path)
    retriever = KnowledgeRetriever()
    retriever.ingest_path(path)
    return retriever


class IngestKnowledgeTool(BaseTool):
    name = "ingest_knowledge"
    description = "Load local Markdown knowledge files into an in-memory RAG retriever."
    read_only = True
    input_schema = {
        "type": "object",
        "properties": {
            "path": {"type": "string", "default": "knowledge"},
            "collection": {"type": "string", "default": "secminiagent_knowledge"},
        },
    }

    async def execute(self, arguments: dict[str, Any], context: ToolContext) -> ToolResult:
        knowledge_path = str(arguments.get("path") or "knowledge")
        retriever = _retriever_for(context, knowledge_path)
        chunk_count = len(retriever.store._items)
        payload = {
            "collection": str(arguments.get("collection") or "secminiagent_knowledge"),
            "knowledge_path": knowledge_path,
            "chunk_count": chunk_count,
        }
        return ToolResult(True, _json(payload), payload)


class SearchKnowledgeTool(BaseTool):
    name = "search_knowledge"
    description = "Search local RAG knowledge with top-k retrieval."
    read_only = True
    input_schema = {
        "type": "object",
        "required": ["query"],
        "properties": {
            "path": {"type": "string", "default": "knowledge"},
            "query": {"type": "string"},
            "top_k": {"type": "integer", "default": 5, "minimum": 1, "maximum": 12},
            "filters": {"type": "object"},
        },
    }

    async def execute(self, arguments: dict[str, Any], context: ToolContext) -> ToolResult:
        retriever = _retriever_for(context, str(arguments.get("path") or "knowledge"))
        filters = arguments.get("filters")
        results = retriever.search(
            str(arguments["query"]),
            top_k=int(arguments.get("top_k") or 5),
            filters=filters if isinstance(filters, dict) else None,
        )
        payload = {"results": [result.to_dict() for result in results]}
        return ToolResult(True, truncate_text(_json(payload), context.max_output_chars), payload)


class ExplainAlertWithRagTool(BaseTool):
    name = "explain_alert_with_rag"
    description = "Explain one security alert with retrieved local knowledge evidence."
    read_only = True
    input_schema = {
        "type": "object",
        "required": ["destination_port"],
        "properties": {
            "knowledge_path": {"type": "string", "default": "knowledge"},
            "timestamp": {"type": "string"},
            "source_ip": {"type": "string"},
            "destination_ip": {"type": "string"},
            "destination_port": {"type": "integer"},
            "protocol": {"type": "string", "default": "tcp"},
            "action": {"type": "string", "default": "observed"},
            "severity": {"type": "string", "default": "medium"},
            "description": {"type": "string", "default": ""},
            "top_k": {"type": "integer", "default": 5, "minimum": 1, "maximum": 12},
        },
    }

    async def execute(self, arguments: dict[str, Any], context: ToolContext) -> ToolResult:
        alert = SecurityAlert(
            alert_id="input-alert",
            timestamp=str(arguments.get("timestamp") or ""),
            source_ip=str(arguments.get("source_ip") or ""),
            destination_ip=str(arguments.get("destination_ip") or ""),
            destination_port=int(arguments["destination_port"]),
            protocol=str(arguments.get("protocol") or "tcp"),
            rule_name=f"rag_{str(arguments.get('action') or 'observed').lower()}",
            severity=str(arguments.get("severity") or "medium"),
            message=str(arguments.get("description") or ""),
        )
        retriever = _retriever_for(context, str(arguments.get("knowledge_path") or "knowledge"))
        query = build_alert_query(alert, str(arguments.get("action") or ""))
        results = retriever.search(query, top_k=int(arguments.get("top_k") or 5))
        body = render_alert_explanation(alert, query, results)
        return ToolResult(
            True,
            truncate_text(body, context.max_output_chars),
            {"query": query, "results": [result.to_dict() for result in results]},
        )


class GenerateRagThreatReportTool(BaseTool):
    name = "generate_rag_threat_report"
    description = "Generate a RAG-enhanced Markdown threat report from CSV security alerts."
    read_only = True
    input_schema = {
        "type": "object",
        "required": ["alerts_path"],
        "properties": {
            "alerts_path": {"type": "string"},
            "knowledge_path": {"type": "string", "default": "knowledge"},
            "top_k": {"type": "integer", "default": 8, "minimum": 1, "maximum": 12},
            "write_file": {"type": "boolean", "default": False},
            "output_path": {"type": "string"},
        },
    }

    async def execute(self, arguments: dict[str, Any], context: ToolContext) -> ToolResult:
        alerts_path = resolve_workspace_path(context.cwd, str(arguments["alerts_path"]))
        alerts = parse_alerts_csv(alerts_path)
        retriever = _retriever_for(context, str(arguments.get("knowledge_path") or "knowledge"))
        evidence: list[dict[str, object]] = []
        top_k = int(arguments.get("top_k") or 8)
        for alert in alerts:
            action = _action_from_rule_name(alert.rule_name)
            query = build_alert_query(alert, action)
            results = retriever.search(query, top_k=top_k)
            evidence.append(
                {
                    "alert": alert.to_dict(),
                    "query": query,
                    "results": [result.to_dict() for result in results],
                }
            )
        report = render_rag_threat_report(alerts, evidence)
        metadata: dict[str, object] = {"alert_count": len(alerts), "evidence": evidence}
        if bool(arguments.get("write_file", False)):
            raw_output_path = str(arguments.get("output_path") or "").strip()
            if raw_output_path:
                output_path = resolve_workspace_path(context.cwd, raw_output_path)
            else:
                output_path = context.cwd / ".secminiagent" / "reports" / "rag-threat-report.md"
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(report, encoding="utf-8")
            metadata["report_path"] = str(output_path.relative_to(context.cwd))
            report += f"\nReport written to `{output_path.relative_to(context.cwd)}`.\n"
        return ToolResult(True, truncate_text(report, context.max_output_chars), metadata)


def render_alert_explanation(alert: SecurityAlert, query: str, results: list[Any]) -> str:
    lines = [
        "# RAG Alert Explanation",
        "",
        "## Alert Summary",
        "",
        f"- Source: {alert.source_ip or 'unknown'}",
        f"- Destination: {alert.destination_ip or 'unknown'}:{alert.destination_port}",
        f"- Protocol: {alert.protocol}",
        f"- Severity: {alert.severity}",
        f"- Description: {alert.message or 'none'}",
        "",
        "## Retrieval Query",
        "",
        query,
        "",
        "## Knowledge Evidence",
        "",
    ]
    if not results:
        lines.append("No related knowledge was retrieved.")
    for result in results:
        lines.extend(
            [
                f"### {result.chunk.title}",
                "",
                f"- Source: `{result.chunk.source_path}`",
                f"- Score: {result.score:.4f}",
                f"- Evidence: {result.chunk.text.strip()[:500]}",
                "",
            ]
        )
    lines.extend(
        [
            "## Recommended Checks",
            "",
            "- Verify whether the source host is authorized for this destination and port.",
            "- Review segmentation, remote maintenance, and jump-host records.",
            "- Preserve firewall, IDS, and access logs for follow-up analysis.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_rag_threat_report(alerts: list[SecurityAlert], evidence: list[dict[str, object]]) -> str:
    now = datetime.now(timezone.utc).isoformat()
    high_count = sum(1 for alert in alerts if alert.severity.lower() == "high")
    lines = [
        "# RAG-Enhanced Industrial Threat Report",
        "",
        f"Generated: {now}",
        "",
        "## Summary",
        "",
        f"- Alerts analyzed: {len(alerts)}",
        f"- High severity alerts: {high_count}",
        "",
        "## Alert Overview",
        "",
    ]
    for alert in alerts:
        lines.append(
            f"- {alert.alert_id}: {alert.source_ip} -> {alert.destination_ip}:{alert.destination_port} ({alert.severity})"
        )
    lines.extend(["", "## Knowledge Evidence", ""])
    for item in evidence:
        alert = item["alert"]
        lines.extend(
            [
                f"### {alert['alert_id']}: {alert['source_ip']} -> {alert['destination_ip']}:{alert['destination_port']}",
                "",
                f"- Query: {item['query']}",
            ]
        )
        for result in item["results"][:3]:
            lines.extend(
                [
                    f"- Source: `{result['source_path']}`",
                    f"  - Score: {float(result['score']):.4f}",
                    f"  - Evidence: {str(result['text']).strip()[:300]}",
                ]
            )
        lines.append("")
    lines.extend(
        [
            "## Recommended Actions",
            "",
            "- Prioritize high severity alerts involving industrial protocol ports.",
            "- Verify whether access paths match approved remote maintenance processes.",
            "- Review segmentation between office, DMZ, and OT networks.",
            "- Preserve evidence and compare repeated sources across alerts.",
            "",
            "## RAG Retrieval Metadata",
            "",
            f"- Evidence groups: {len(evidence)}",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def _action_from_rule_name(rule_name: str) -> str:
    if rule_name.startswith("csv_"):
        return rule_name[4:]
    return ""
