from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class SessionState:
    id: str
    cwd: Path
    path: Path
    messages: list[dict[str, Any]] = field(default_factory=list)

    def record(self, event_type: str, payload: dict[str, Any]) -> None:
        event = {"ts": utc_now(), "type": event_type, **payload}
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")

    def record_message(self, message: dict[str, Any]) -> None:
        self.messages.append(message)
        self.record("message", {"message": message})


class TranscriptStore:
    def __init__(self, cwd: Path) -> None:
        self.cwd = cwd
        self.sessions_dir = cwd / ".secminiagent" / "sessions"
        self.sessions_dir.mkdir(parents=True, exist_ok=True)

    def create(self) -> SessionState:
        session_id = str(uuid.uuid4())
        path = self.sessions_dir / f"{session_id}.jsonl"
        state = SessionState(id=session_id, cwd=self.cwd, path=path)
        state.record("meta", {"session_id": session_id, "cwd": str(self.cwd)})
        return state

    def load(self, session_id: str) -> SessionState:
        path = self.sessions_dir / f"{session_id}.jsonl"
        if not path.exists():
            raise FileNotFoundError(f"Session not found: {session_id}")
        state = SessionState(id=session_id, cwd=self.cwd, path=path)
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                event = json.loads(line)
                if event.get("type") == "message":
                    state.messages.append(event["message"])
        return state
