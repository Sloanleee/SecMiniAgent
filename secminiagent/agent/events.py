from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable


@dataclass(slots=True)
class AgentEvent:
    type: str
    payload: dict[str, Any] = field(default_factory=dict)


AgentEventHandler = Callable[[AgentEvent], Awaitable[None]]
