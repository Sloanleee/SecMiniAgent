from __future__ import annotations

from pathlib import Path
from typing import Iterable

from secminiagent.tools.file_tools import SKIP_DIRS, resolve_workspace_path

from .findings import Finding
from .rules import ALL_RULES, INSECURE_PATTERN_RULES, SECRET_RULES, SecurityRule


TEXT_SUFFIXES = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".java",
    ".go",
    ".rs",
    ".rb",
    ".php",
    ".cs",
    ".c",
    ".cpp",
    ".h",
    ".hpp",
    ".sh",
    ".ps1",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".ini",
    ".cfg",
    ".env",
    ".md",
    ".txt",
}


class SecurityScanner:
    def __init__(self, *, cwd: Path) -> None:
        self.cwd = cwd.resolve()

    def scan_secrets(self, path: str = ".", max_findings: int = 100) -> list[Finding]:
        return self.scan(path=path, rules=SECRET_RULES, max_findings=max_findings)

    def scan_insecure_patterns(self, path: str = ".", max_findings: int = 100) -> list[Finding]:
        return self.scan(path=path, rules=INSECURE_PATTERN_RULES, max_findings=max_findings)

    def scan_all(self, path: str = ".", max_findings: int = 200) -> list[Finding]:
        return self.scan(path=path, rules=ALL_RULES, max_findings=max_findings)

    def scan(self, *, path: str, rules: Iterable[SecurityRule], max_findings: int) -> list[Finding]:
        root = resolve_workspace_path(self.cwd, path)
        findings: list[Finding] = []
        for file_path in self._iter_files(root):
            try:
                text = file_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for line_no, line in enumerate(text.splitlines(), start=1):
                for rule in rules:
                    if rule.pattern.search(line):
                        findings.append(
                            Finding(
                                rule_id=rule.rule_id,
                                title=rule.title,
                                severity=rule.severity,
                                file_path=str(file_path.relative_to(self.cwd)),
                                line=line_no,
                                snippet=line.strip()[:240],
                                recommendation=rule.recommendation,
                            )
                        )
                        if len(findings) >= max_findings:
                            return findings
        return findings

    def _iter_files(self, root: Path) -> Iterable[Path]:
        paths = [root] if root.is_file() else sorted(root.rglob("*"))
        for path in paths:
            if not path.is_file():
                continue
            rel_parts = path.relative_to(self.cwd).parts
            if any(part in SKIP_DIRS for part in rel_parts):
                continue
            if path.suffix.lower() not in TEXT_SUFFIXES and path.name != ".env":
                continue
            yield path
