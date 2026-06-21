from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class CommandAction(str, Enum):
    ALLOW = "allow"
    ASK = "ask"
    DENY = "deny"


@dataclass(slots=True)
class CommandDecision:
    action: CommandAction
    reason: str
    matched: str | None = None


class CommandPolicy:
    deny_patterns = [
        (re.compile(r"\bsudo\b|\bsu\s+-"), "Privilege escalation is disabled."),
        (re.compile(r"\bgit\s+reset\s+--hard\b"), "git reset --hard can destroy local work."),
        (re.compile(r"\bgit\s+clean\s+-[^\n]*f"), "git clean -f can remove untracked work."),
        (re.compile(r"\bchmod\s+-R\s+777\b"), "chmod -R 777 is unsafe."),
        (re.compile(r"\brm\s+(-[^\n]*[rf][^\n]*|-[^\n]*[fr][^\n]*)\s+(/|\*|[a-zA-Z]:\\)(\s|$)"), "Broad recursive delete is blocked."),
        (re.compile(r"\bRemove-Item\b.*\b-Recurse\b.*\b-Force\b.*([a-zA-Z]:\\|/|\*)", re.I), "Broad recursive Remove-Item is blocked."),
    ]
    ask_patterns = [
        (re.compile(r"\brm\b|\bdel\b|\bRemove-Item\b", re.I), "Delete commands require confirmation."),
        (re.compile(r"\bgit\s+(reset|rebase|checkout|switch|clean)\b"), "Git worktree changes require confirmation."),
        (re.compile(r"\b(pip|pip3)\s+install\b|\bpython\s+-m\s+pip\s+install\b"), "Package installation requires confirmation."),
        (re.compile(r"\b(npm|pnpm|yarn)\s+(install|add)\b"), "Package installation requires confirmation."),
        (re.compile(r"\b(curl|wget|Invoke-WebRequest|iwr)\b.*(\|\s*(sh|bash|powershell)|-o\s+)", re.I), "Network download/execution requires confirmation."),
    ]

    def classify(self, command: str) -> CommandDecision:
        normalized = " ".join(command.strip().split())
        if not normalized:
            return CommandDecision(CommandAction.DENY, "Empty command.")
        for pattern, reason in self.deny_patterns:
            if pattern.search(normalized):
                return CommandDecision(CommandAction.DENY, reason, pattern.pattern)
        for pattern, reason in self.ask_patterns:
            if pattern.search(normalized):
                return CommandDecision(CommandAction.ASK, reason, pattern.pattern)
        return CommandDecision(CommandAction.ALLOW, "Command is allowed by default.")
