from __future__ import annotations

from collections import OrderedDict

from .base import Tool, ToolContext, ToolResult


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: OrderedDict[str, Tool] = OrderedDict()

    def register(self, tool: Tool) -> Tool:
        if tool.name in self._tools:
            raise ValueError(f"Tool already registered: {tool.name}")
        self._tools[tool.name] = tool
        return tool

    def get(self, name: str) -> Tool:
        try:
            return self._tools[name]
        except KeyError as exc:
            raise KeyError(f"Unknown tool: {name}") from exc

    def list(self) -> list[Tool]:
        return list(self._tools.values())

    def names(self) -> list[str]:
        return list(self._tools)

    async def execute(
        self,
        name: str,
        arguments: dict,
        context: ToolContext,
    ) -> ToolResult:
        try:
            return await self.get(name).execute(arguments, context)
        except Exception as exc:
            return ToolResult(False, f"{type(exc).__name__}: {exc}")
