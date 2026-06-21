from __future__ import annotations

import asyncio
from typing import Any

from secminiagent.safety.command_policy import CommandPolicy

from .base import BaseTool, ToolContext, ToolResult, truncate_text


class RunShellTool(BaseTool):
    name = "run_shell"
    description = "Run a local shell command after safety checks. Intended for tests and read-only inspection."
    read_only = False
    input_schema = {
        "type": "object",
        "required": ["command"],
        "properties": {
            "command": {"type": "string"},
            "timeout": {"type": "integer", "default": 30, "minimum": 1, "maximum": 600},
        },
    }

    def __init__(self, policy: CommandPolicy | None = None) -> None:
        self.policy = policy or CommandPolicy()

    async def execute(self, arguments: dict[str, Any], context: ToolContext) -> ToolResult:
        command = str(arguments["command"])
        timeout = int(arguments.get("timeout") or 30)
        decision = self.policy.classify(command)
        if context.permission_manager:
            approved = await context.permission_manager.approve_shell_command(command, decision)
        else:
            approved = decision.action.value == "allow"
        if not approved:
            return ToolResult(False, f"Command rejected by policy: {decision.reason}")

        proc = await asyncio.create_subprocess_shell(
            command,
            cwd=str(context.cwd),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return ToolResult(False, f"Command timed out after {timeout}s: {command}")

        out = stdout.decode("utf-8", errors="replace")
        err = stderr.decode("utf-8", errors="replace")
        parts: list[str] = []
        if out:
            parts.append("[stdout]\n" + out.rstrip())
        if err:
            parts.append("[stderr]\n" + err.rstrip())
        body = "\n\n".join(parts) or "(no output)"
        return ToolResult(proc.returncode == 0, truncate_text(body, context.max_output_chars), {"returncode": proc.returncode})
