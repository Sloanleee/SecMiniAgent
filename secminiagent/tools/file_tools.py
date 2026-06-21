from __future__ import annotations

from pathlib import Path
from typing import Any

from .base import BaseTool, ToolContext, ToolError, ToolResult, truncate_text


SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".venv",
    "venv",
    "node_modules",
    ".mypy_cache",
    ".pytest_cache",
    ".secminiagent",
}


def resolve_workspace_path(cwd: Path, raw_path: str) -> Path:
    target = Path(raw_path)
    if not target.is_absolute():
        target = cwd / target
    resolved = target.resolve()
    root = cwd.resolve()
    if not resolved.is_relative_to(root):
        raise ToolError(f"Path escapes workspace: {raw_path}")
    return resolved


class ListDirTool(BaseTool):
    name = "list_dir"
    description = "List files and directories under a workspace path."
    read_only = True
    input_schema = {
        "type": "object",
        "properties": {
            "path": {"type": "string", "default": "."},
            "max_entries": {"type": "integer", "default": 200, "minimum": 1, "maximum": 1000},
        },
    }

    async def execute(self, arguments: dict[str, Any], context: ToolContext) -> ToolResult:
        path = resolve_workspace_path(context.cwd, str(arguments.get("path") or "."))
        if not path.exists():
            return ToolResult(False, f"Directory does not exist: {path}")
        if not path.is_dir():
            return ToolResult(False, f"Not a directory: {path}")
        max_entries = int(arguments.get("max_entries") or 200)
        rows: list[str] = []
        for index, child in enumerate(sorted(path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))):
            if index >= max_entries:
                rows.append(f"... truncated after {max_entries} entries")
                break
            suffix = "/" if child.is_dir() else ""
            rows.append(f"{child.relative_to(context.cwd)}{suffix}")
        return ToolResult(True, "\n".join(rows) or "(empty)")


class ReadFileTool(BaseTool):
    name = "read_file"
    description = "Read a text file with line numbers. Supports offset and line limit."
    read_only = True
    input_schema = {
        "type": "object",
        "required": ["file_path"],
        "properties": {
            "file_path": {"type": "string"},
            "offset": {"type": "integer", "default": 1, "minimum": 1},
            "limit": {"type": "integer", "default": 200, "minimum": 1, "maximum": 1000},
        },
    }

    async def execute(self, arguments: dict[str, Any], context: ToolContext) -> ToolResult:
        path = resolve_workspace_path(context.cwd, str(arguments["file_path"]))
        if not path.exists():
            return ToolResult(False, f"File does not exist: {path}")
        if not path.is_file():
            return ToolResult(False, f"Not a file: {path}")
        offset = max(1, int(arguments.get("offset") or 1))
        limit = max(1, int(arguments.get("limit") or 200))
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        selected = lines[offset - 1 : offset - 1 + limit]
        rendered = "\n".join(f"{idx:>6}  {line}" for idx, line in enumerate(selected, start=offset))
        if offset - 1 + limit < len(lines):
            rendered += f"\n... file has {len(lines)} total lines"
        return ToolResult(True, truncate_text(rendered or "(empty file)", context.max_output_chars))


class WriteFileTool(BaseTool):
    name = "write_file"
    description = "Create or overwrite a text file inside the workspace."
    read_only = False
    input_schema = {
        "type": "object",
        "required": ["file_path", "content"],
        "properties": {
            "file_path": {"type": "string"},
            "content": {"type": "string"},
            "overwrite": {"type": "boolean", "default": False},
        },
    }

    async def execute(self, arguments: dict[str, Any], context: ToolContext) -> ToolResult:
        path = resolve_workspace_path(context.cwd, str(arguments["file_path"]))
        overwrite = bool(arguments.get("overwrite", False))
        if path.exists() and not overwrite:
            return ToolResult(False, "File exists. Set overwrite=true to replace it.")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(str(arguments["content"]), encoding="utf-8")
        return ToolResult(True, f"Wrote {path.relative_to(context.cwd)} ({path.stat().st_size} bytes).")
