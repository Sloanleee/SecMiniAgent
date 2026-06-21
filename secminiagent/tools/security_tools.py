from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from secminiagent.security.report import render_markdown_report
from secminiagent.security.scanner import SecurityScanner

from .base import BaseTool, ToolContext, ToolResult, truncate_text
from .file_tools import resolve_workspace_path


def findings_to_text(findings) -> str:
    if not findings:
        return "No findings detected."
    return json.dumps([finding.to_dict() for finding in findings], ensure_ascii=False, indent=2)


class ScanSecretsTool(BaseTool):
    name = "scan_secrets"
    description = "Scan workspace files for hardcoded secrets and credential-like assignments."
    read_only = True
    input_schema = {
        "type": "object",
        "properties": {
            "path": {"type": "string", "default": "."},
            "max_findings": {"type": "integer", "default": 100, "minimum": 1, "maximum": 1000},
        },
    }

    async def execute(self, arguments: dict[str, Any], context: ToolContext) -> ToolResult:
        scanner = SecurityScanner(cwd=context.cwd)
        findings = scanner.scan_secrets(
            path=str(arguments.get("path") or "."),
            max_findings=int(arguments.get("max_findings") or 100),
        )
        return ToolResult(
            True,
            truncate_text(findings_to_text(findings), context.max_output_chars),
            {"findings": [finding.to_dict() for finding in findings]},
        )


class ScanInsecurePatternsTool(BaseTool):
    name = "scan_insecure_patterns"
    description = "Scan code for insecure patterns such as eval, shell=True, pickle, weak hashes, and HTTP URLs."
    read_only = True
    input_schema = {
        "type": "object",
        "properties": {
            "path": {"type": "string", "default": "."},
            "max_findings": {"type": "integer", "default": 100, "minimum": 1, "maximum": 1000},
        },
    }

    async def execute(self, arguments: dict[str, Any], context: ToolContext) -> ToolResult:
        scanner = SecurityScanner(cwd=context.cwd)
        findings = scanner.scan_insecure_patterns(
            path=str(arguments.get("path") or "."),
            max_findings=int(arguments.get("max_findings") or 100),
        )
        return ToolResult(
            True,
            truncate_text(findings_to_text(findings), context.max_output_chars),
            {"findings": [finding.to_dict() for finding in findings]},
        )


class GenerateSecurityReportTool(BaseTool):
    name = "generate_security_report"
    description = "Run local security scans and generate a Markdown security report."
    read_only = True
    input_schema = {
        "type": "object",
        "properties": {
            "path": {"type": "string", "default": "."},
            "max_findings": {"type": "integer", "default": 200, "minimum": 1, "maximum": 1000},
            "write_file": {"type": "boolean", "default": False},
            "output_path": {"type": "string", "description": "Optional workspace-relative report path."},
        },
    }

    async def execute(self, arguments: dict[str, Any], context: ToolContext) -> ToolResult:
        scanner = SecurityScanner(cwd=context.cwd)
        findings = scanner.scan_all(
            path=str(arguments.get("path") or "."),
            max_findings=int(arguments.get("max_findings") or 200),
        )
        report = render_markdown_report(findings)
        metadata = {"findings": [finding.to_dict() for finding in findings]}
        if bool(arguments.get("write_file", False)):
            raw_output_path = str(arguments.get("output_path") or "").strip()
            if raw_output_path:
                output_path = resolve_workspace_path(context.cwd, raw_output_path)
            else:
                stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
                output_path = context.cwd / ".secminiagent" / "reports" / f"security-report-{stamp}.md"
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(report, encoding="utf-8")
            metadata["report_path"] = str(output_path.relative_to(context.cwd))
            report += f"\n\nReport written to `{output_path.relative_to(context.cwd)}`.\n"
        return ToolResult(
            True,
            truncate_text(report, context.max_output_chars),
            metadata,
        )


class ScanDependencyFilesTool(BaseTool):
    name = "scan_dependency_files"
    description = "Locate dependency manifests that should be reviewed with dedicated audit tools."
    read_only = True
    input_schema = {
        "type": "object",
        "properties": {
            "path": {"type": "string", "default": "."},
        },
    }

    async def execute(self, arguments: dict[str, Any], context: ToolContext) -> ToolResult:
        root = resolve_workspace_path(context.cwd, str(arguments.get("path") or "."))
        names = {
            "requirements.txt",
            "pyproject.toml",
            "Pipfile",
            "poetry.lock",
            "package.json",
            "package-lock.json",
            "pnpm-lock.yaml",
            "yarn.lock",
            "go.mod",
            "Cargo.toml",
            "Gemfile",
        }
        paths = [root] if root.is_file() else sorted(root.rglob("*"))
        matches = [str(path.relative_to(context.cwd)) for path in paths if path.is_file() and path.name in names]
        if not matches:
            return ToolResult(True, "No common dependency manifests found.")
        body = "\n".join(
            [
                "Dependency manifests found:",
                *[f"- {match}" for match in matches],
                "",
                "Recommendation: run ecosystem-specific audit tools such as pip-audit, npm audit, cargo audit, or govulncheck in CI.",
            ]
        )
        return ToolResult(True, truncate_text(body, context.max_output_chars), {"files": matches})
