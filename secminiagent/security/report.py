from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone

from .findings import Finding


def render_markdown_report(findings: list[Finding], *, title: str = "Security Review Report") -> str:
    now = datetime.now(timezone.utc).isoformat()
    lines: list[str] = [
        f"# {title}",
        "",
        f"Generated: {now}",
        "",
        "## Summary",
        "",
    ]
    if not findings:
        lines.extend(["No findings were detected by the configured local rules.", ""])
        return "\n".join(lines)

    counts = Counter(finding.severity for finding in findings)
    lines.extend(
        [
            f"- Total findings: {len(findings)}",
            f"- High: {counts.get('high', 0)}",
            f"- Medium: {counts.get('medium', 0)}",
            f"- Low: {counts.get('low', 0)}",
            "",
            "## Findings",
            "",
        ]
    )

    grouped: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        grouped[finding.severity].append(finding)

    for severity in ["high", "medium", "low"]:
        items = grouped.get(severity, [])
        if not items:
            continue
        lines.extend([f"### {severity.title()} Risk", ""])
        for item in items:
            lines.extend(
                [
                    f"#### {item.rule_id}: {item.title}",
                    "",
                    f"- Location: `{item.file_path}:{item.line}`",
                    f"- Evidence: `{item.snippet}`",
                    f"- Recommendation: {item.recommendation}",
                    "",
                ]
            )
    return "\n".join(lines).rstrip() + "\n"
