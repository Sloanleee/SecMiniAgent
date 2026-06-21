from __future__ import annotations

import asyncio

from .command_policy import CommandAction, CommandDecision


class PermissionManager:
    def __init__(self, *, auto_approve: bool = False, interactive: bool = True) -> None:
        self.auto_approve = auto_approve
        self.interactive = interactive

    async def approve_shell_command(self, command: str, decision: CommandDecision) -> bool:
        if decision.action == CommandAction.ALLOW:
            return True
        if decision.action == CommandAction.DENY:
            return False
        if self.auto_approve:
            return True
        if not self.interactive:
            return False
        prompt = (
            "\nShell command needs approval:\n"
            f"  {command}\n"
            f"Reason: {decision.reason}\n"
            "Run it? [y/N] "
        )
        answer = await asyncio.to_thread(input, prompt)
        return answer.strip().lower() in {"y", "yes"}
