from __future__ import annotations

from typing import Any

from .compressor import compact_message


class ContextManager:
    def __init__(self, *, max_chars: int = 80_000, keep_recent: int = 10) -> None:
        self.max_chars = max_chars
        self.keep_recent = keep_recent

    def prepare(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        compacted = [compact_message(message, 12_000) for message in messages]
        rendered_size = sum(len(str(message)) for message in compacted)
        if rendered_size <= self.max_chars:
            return compacted
        recent = compacted[-self.keep_recent :]
        summary = {
            "role": "system",
            "content": f"Earlier conversation compacted. Omitted approximately {rendered_size - self.max_chars} chars.",
        }
        return [summary, *recent]
