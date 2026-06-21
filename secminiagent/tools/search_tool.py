from __future__ import annotations

import re
from typing import Any

from .base import BaseTool, ToolContext, ToolResult, truncate_text
from .file_tools import SKIP_DIRS, resolve_workspace_path


class SearchCodeTool(BaseTool):
    name = "search_code"
    description = "Search text or regex patterns in workspace files."
    read_only = True
    input_schema = {
        "type": "object",
        "required": ["query"],
        "properties": {
            "query": {"type": "string"},
            "path": {"type": "string", "default": "."},
            "regex": {"type": "boolean", "default": False},
            "max_matches": {"type": "integer", "default": 100, "minimum": 1, "maximum": 1000},
        },
    }

    async def execute(self, arguments: dict[str, Any], context: ToolContext) -> ToolResult:
        query = str(arguments["query"])
        root = resolve_workspace_path(context.cwd, str(arguments.get("path") or "."))
        regex = bool(arguments.get("regex", False))
        max_matches = int(arguments.get("max_matches") or 100)
        pattern = re.compile(query) if regex else None
        rows: list[str] = []

        paths = [root] if root.is_file() else sorted(root.rglob("*"))
        for path in paths:
            if len(rows) >= max_matches:
                rows.append(f"... truncated after {max_matches} matches")
                break
            if not path.is_file():
                continue
            if any(part in SKIP_DIRS for part in path.relative_to(context.cwd).parts):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for line_no, line in enumerate(text.splitlines(), start=1):
                matched = bool(pattern.search(line)) if pattern else query in line
                if matched:
                    rel = path.relative_to(context.cwd)
                    rows.append(f"{rel}:{line_no}: {line.strip()}")
                    if len(rows) >= max_matches:
                        break
        return ToolResult(True, truncate_text("\n".join(rows) or "(no matches)", context.max_output_chars))
