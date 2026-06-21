from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol


JsonSchema = dict[str, Any]


@dataclass(slots=True)
class ToolResult:
    success: bool
    output: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_text(self) -> str:
        prefix = "OK" if self.success else "ERROR"
        return f"[{prefix}]\n{self.output}"


@dataclass(slots=True)
class ToolContext:
    cwd: Path
    max_output_chars: int
    auto_approve: bool = False
    permission_manager: Any = None
    plan_state: Any = None


class Tool(Protocol):
    name: str
    description: str
    input_schema: JsonSchema
    read_only: bool

    async def execute(self, arguments: dict[str, Any], context: ToolContext) -> ToolResult:
        ...

    def to_openai_schema(self) -> dict[str, Any]:
        ...


class BaseTool:
    name = ""
    description = ""
    input_schema: JsonSchema = {"type": "object", "properties": {}}
    read_only = True

    def to_openai_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.input_schema,
            },
        }


class ToolError(RuntimeError):
    pass


def truncate_text(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    head = text[: limit // 2]
    tail = text[-limit // 2 :]
    omitted = len(text) - len(head) - len(tail)
    return f"{head}\n...[truncated {omitted} chars]...\n{tail}"
