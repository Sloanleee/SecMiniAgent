from __future__ import annotations

import asyncio
from typing import Any

from .base import BaseTool, ToolContext, ToolResult, truncate_text
from .file_tools import resolve_workspace_path


async def run_git(args: list[str], context: ToolContext, *, timeout: int = 30) -> ToolResult:
    proc = await asyncio.create_subprocess_exec(
        "git",
        *args,
        cwd=str(context.cwd),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return ToolResult(False, f"git {' '.join(args)} timed out after {timeout}s.")

    out = stdout.decode("utf-8", errors="replace").strip()
    err = stderr.decode("utf-8", errors="replace").strip()
    parts: list[str] = []
    if out:
        parts.append(out)
    if err:
        parts.append("[stderr]\n" + err)
    body = "\n\n".join(parts) or "(no output)"
    return ToolResult(proc.returncode == 0, truncate_text(body, context.max_output_chars), {"returncode": proc.returncode})


def optional_path_arg(arguments: dict[str, Any], context: ToolContext) -> list[str]:
    raw_path = str(arguments.get("path") or "").strip()
    if not raw_path:
        return []
    path = resolve_workspace_path(context.cwd, raw_path)
    return ["--", str(path.relative_to(context.cwd))]


class GitStatusTool(BaseTool):
    name = "git_status"
    description = "Show concise git branch and worktree status."
    read_only = True

    async def execute(self, arguments: dict[str, Any], context: ToolContext) -> ToolResult:
        return await run_git(["status", "--short", "--branch"], context)


class GitDiffTool(BaseTool):
    name = "git_diff"
    description = "Show git diff for the worktree or index."
    read_only = True
    input_schema = {
        "type": "object",
        "properties": {
            "staged": {"type": "boolean", "default": False},
            "path": {"type": "string"},
        },
    }

    async def execute(self, arguments: dict[str, Any], context: ToolContext) -> ToolResult:
        args = ["diff", "--no-ext-diff"]
        if bool(arguments.get("staged", False)):
            args.append("--cached")
        args.extend(optional_path_arg(arguments, context))
        return await run_git(args, context)


class GitLogTool(BaseTool):
    name = "git_log"
    description = "Show recent git commits in one-line format."
    read_only = True
    input_schema = {
        "type": "object",
        "properties": {
            "limit": {"type": "integer", "default": 10, "minimum": 1, "maximum": 50},
        },
    }

    async def execute(self, arguments: dict[str, Any], context: ToolContext) -> ToolResult:
        limit = min(50, max(1, int(arguments.get("limit") or 10)))
        return await run_git(["log", "--oneline", f"-n{limit}"], context)
