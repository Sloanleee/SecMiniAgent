from __future__ import annotations

from typing import Any


def compact_message(message: dict[str, Any], max_chars: int) -> dict[str, Any]:
    content = message.get("content")
    if isinstance(content, str) and len(content) > max_chars:
        half = max_chars // 2
        omitted = len(content) - half * 2
        compacted = f"{content[:half]}\n...[truncated {omitted} chars]...\n{content[-half:]}"
        return {**message, "content": compacted}
    return message
