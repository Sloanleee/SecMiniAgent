from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    file_path: str
    line: int
    snippet: str
    recommendation: str

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "file_path": self.file_path,
            "line": self.line,
            "snippet": self.snippet,
            "recommendation": self.recommendation,
        }

    def render_one_line(self) -> str:
        return f"{self.severity.upper()} {self.file_path}:{self.line} {self.rule_id} - {self.title}"
