from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class AuditEvent:
    event_id: str
    action: str
    outcome: str
    workspace_id: str
    memory_id_hash: str | None
    reason_code: str
    created_at: datetime
