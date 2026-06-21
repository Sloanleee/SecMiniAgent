from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol


Message = dict[str, Any]


@dataclass(slots=True)
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass(slots=True)
class LLMResponse:
    content: str
    tool_calls: list[ToolCall]
    assistant_message: Message
    raw: dict[str, Any]


class LLMClient(Protocol):
    provider: str

    async def complete(
        self,
        *,
        messages: list[Message],
        tools: list[Any],
        system_prompt: str,
    ) -> LLMResponse:
        ...

    def user_message(self, content: str) -> Message:
        ...

    def tool_result_message(self, call: ToolCall, content: str) -> Message:
        ...


def parse_json_object(raw: str | dict[str, Any] | None) -> dict[str, Any]:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {"raw": raw}
    return parsed if isinstance(parsed, dict) else {"value": parsed}
