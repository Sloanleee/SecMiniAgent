from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from secminiagent.memory.errors import MemoryConfirmationRequired, MemoryPolicyDenied
from secminiagent.memory.factory import create_local_memory, create_note_summary_runtime
from secminiagent.memory.models import (
    MemoryAccessContext,
    MemoryCandidate,
    MemoryQuery,
    MemoryScope,
    MemorySource,
    MemoryType,
)
from secminiagent.memory.context_assembler import ContextAssembler, ContextBudgets


@dataclass(slots=True)
class SessionState:
    id: str
    cwd: Path
    path: Path
    _store: "SecureTranscriptStore" = field(repr=False)
    messages: list[dict[str, Any]] = field(default_factory=list)
    _sequence: int = 0

    def record(self, event_type: str, payload: dict[str, Any]) -> None:
        self._store.record_event(self, event_type, payload)

    def record_message(self, message: dict[str, Any]) -> None:
        self.messages.append(message)
        self._store.record_message(self, message)


@dataclass(frozen=True, slots=True)
class MigrationReport:
    scanned_files: int
    migrated_sessions: int
    skipped_sessions: int
    migrated_messages: int
    redacted_messages: int
    source_files_deleted: int


class SecureTranscriptStore:
    """Encrypted transcript adapter backed exclusively by MemoryService."""

    def __init__(self, cwd: Path) -> None:
        self.cwd = cwd.resolve()
        self.service, self.base_context = create_local_memory(
            self.cwd,
            provider="local",
            enable_chroma=False,
        )
        self.database_path = self.cwd / ".secminiagent" / "memory" / "memory.db"
        self.legacy_sessions_dir = self.cwd / ".secminiagent" / "sessions"

    def create(self) -> SessionState:
        return self._create_with_id(str(uuid.uuid4()))

    def _create_with_id(self, session_id: str) -> SessionState:
        context = self._context(session_id)
        state = SessionState(session_id, self.cwd, self.database_path, self)
        candidate = MemoryCandidate(
            memory_type=MemoryType.SESSION_META,
            content=json.dumps({"session_id": session_id}, separators=(",", ":")),
            requested_scope=MemoryScope.SESSION,
            source=MemorySource("session_meta", user_confirmed=True),
            attributes={"_sequence_no": 0, "event_type": "meta"},
        )
        self.service.remember(candidate, context)
        state._sequence = 1
        return state

    def load(self, session_id: str) -> SessionState:
        context = self._context(session_id)
        metadata = self.service.list_metadata(MemoryQuery(limit=10_000), context)
        session_records = [
            item
            for item in metadata
            if item.scope is MemoryScope.SESSION and item.session_id == session_id
        ]
        if not any(item.memory_type is MemoryType.SESSION_META for item in session_records):
            raise FileNotFoundError(f"Session not found: {session_id}")
        session_records.sort(key=lambda item: (item.sequence_no if item.sequence_no is not None else 2**31, item.created_at))
        messages: list[dict[str, Any]] = []
        for item in session_records:
            if item.memory_type is not MemoryType.MESSAGE:
                continue
            record = self.service.recall(item.id, context)
            try:
                message = json.loads(record.content)
            except json.JSONDecodeError:
                continue
            if isinstance(message, dict):
                messages.append(message)
        next_sequence = max((item.sequence_no or 0 for item in session_records), default=0) + 1
        return SessionState(session_id, self.cwd, self.database_path, self, messages, next_sequence)

    def record_message(self, state: SessionState, message: dict[str, Any]) -> None:
        serialized = json.dumps(message, ensure_ascii=False, separators=(",", ":"), default=str)
        self._remember_or_redact(
            state,
            MemoryType.MESSAGE,
            serialized,
            {"event_type": "message"},
            fallback=json.dumps(self._safe_message_shape(message), separators=(",", ":")),
        )

    def record_event(self, state: SessionState, event_type: str, payload: dict[str, Any]) -> None:
        serialized = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str)
        self._remember_or_redact(
            state,
            MemoryType.TOOL_RESULT,
            serialized,
            {"event_type": event_type},
            fallback=json.dumps({"redacted": True, "event_type": event_type}, separators=(",", ":")),
        )

    def migrate_legacy_sessions(self, *, delete_source: bool = False) -> MigrationReport:
        if not self.legacy_sessions_dir.exists():
            return MigrationReport(0, 0, 0, 0, 0, 0)
        scanned = migrated_sessions = skipped = migrated_messages = redacted = deleted = 0
        for path in sorted(self.legacy_sessions_dir.glob("*.jsonl")):
            scanned += 1
            session_id = path.stem
            try:
                self.load(session_id)
            except FileNotFoundError:
                pass
            else:
                skipped += 1
                continue

            state = self._create_with_id(session_id)
            session_redacted = 0
            session_messages = 0
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get("type") == "message" and isinstance(event.get("message"), dict):
                    self.record_message(state, event["message"])
                    session_messages += 1
                    # Policy-denied messages persist only a fixed redacted marker.
                    context = self._context(session_id)
                    message_meta = [
                        item
                        for item in self.service.list_metadata(MemoryQuery(limit=10_000), context)
                        if item.memory_type is MemoryType.MESSAGE and item.session_id == session_id
                    ]
                    if message_meta and self.service.recall(message_meta[-1].id, context).content.find(
                        "[REDACTED:SECRET]"
                    ) >= 0:
                        session_redacted += 1
                elif event.get("type") not in {"meta", "message"}:
                    payload = {key: value for key, value in event.items() if key not in {"ts", "type"}}
                    self.record_event(state, str(event.get("type") or "legacy_event"), payload)
            migrated_sessions += 1
            migrated_messages += session_messages
            redacted += session_redacted
            if delete_source:
                path.unlink()
                deleted += 1
        return MigrationReport(scanned, migrated_sessions, skipped, migrated_messages, redacted, deleted)

    def _remember_or_redact(
        self,
        state: SessionState,
        memory_type: MemoryType,
        content: str,
        attributes: dict[str, Any],
        *,
        fallback: str,
    ) -> None:
        sequence = state._sequence
        state._sequence += 1
        context = self._context(state.id)
        candidate = MemoryCandidate(
            memory_type=memory_type,
            content=content,
            requested_scope=MemoryScope.SESSION,
            source=MemorySource("transcript", user_confirmed=True),
            attributes={**attributes, "_sequence_no": sequence},
        )
        try:
            self.service.remember(candidate, context)
        except (MemoryPolicyDenied, MemoryConfirmationRequired):
            safe = MemoryCandidate(
                memory_type=memory_type,
                content=fallback,
                requested_scope=MemoryScope.SESSION,
                source=MemorySource("transcript_redaction", user_confirmed=True),
                attributes={**attributes, "_sequence_no": sequence, "redacted": True},
            )
            self.service.remember(safe, context)

    def _context(self, session_id: str) -> MemoryAccessContext:
        return MemoryAccessContext(self.base_context.workspace_id, session_id, "local")

    @staticmethod
    def _safe_message_shape(message: dict[str, Any]) -> dict[str, Any]:
        safe: dict[str, Any] = {
            "role": str(message.get("role") or "unknown"),
            "content": "[REDACTED:SECRET]",
        }
        for key in ("tool_call_id", "name"):
            if message.get(key) is not None:
                safe[key] = str(message[key])
        if isinstance(message.get("tool_calls"), list):
            calls = []
            for item in message["tool_calls"]:
                if not isinstance(item, dict):
                    continue
                function = item.get("function") if isinstance(item.get("function"), dict) else {}
                calls.append(
                    {
                        "id": str(item.get("id") or ""),
                        "type": str(item.get("type") or "function"),
                        "function": {
                            "name": str(function.get("name") or ""),
                            "arguments": '{"redacted":true}',
                        },
                    }
                )
            safe["tool_calls"] = calls
        return safe


@dataclass(slots=True)
class ThreadSessionState:
    id: str
    cwd: Path
    path: Path
    thread_id: str
    _store: "ThreadAwareTranscriptStore" = field(repr=False)
    messages: list[dict[str, Any]] = field(default_factory=list)
    run_id: str | None = None
    _last_message_id: str | None = None

    def begin_run(self) -> str:
        if self.run_id is None:
            run = self._store.lifecycle.begin_run(self._store.context(self.id, self.thread_id), self.thread_id)
            self.run_id = run.run_id
        return self.run_id

    def complete_run(self) -> None:
        if self.run_id is not None:
            self._store.lifecycle.complete_run(
                self._store.context(self.id, self.thread_id), self.run_id, self._last_message_id,
            )
            self.run_id = None
            try:
                self._store.summaries.maybe_build(self._store.context(self.id, self.thread_id))
            except Exception:
                # Summary is derived and must never make an authoritative transcript run fail.
                pass

    def fail_run(self, reason_code: str = "AGENT_RUN_FAILED") -> None:
        if self.run_id is not None:
            self._store.lifecycle.fail_run(self._store.context(self.id, self.thread_id), self.run_id, reason_code)
            self.run_id = None

    def record(self, event_type: str, payload: dict[str, Any]) -> None:
        # Tool events are operational telemetry; the corresponding tool message is the transcript authority.
        _ = event_type, payload

    def record_message(self, message: dict[str, Any]) -> None:
        run_id = self.begin_run()
        envelope = self._store.transcript.append(self._store.context(self.id, self.thread_id), run_id, message)
        self._last_message_id = envelope.message_id
        self.messages.append(message)

    def prepare_context(self, max_chars: int) -> tuple[list[dict[str, Any]], str]:
        if self.run_id is None:
            self.begin_run()
        total = max(1, max_chars)
        single = min(12_000, total)
        assembler = ContextAssembler(ContextBudgets(
            total_chars=total,
            current_run_chars=max(1, total * 3 // 5),
            history_chars=max(1, total * 3 // 10),
            single_message_chars=single,
            tool_group_chars=min(24_000, total),
        ))
        items = self._store.transcript.resume(self._store.context(self.id, self.thread_id))
        context = self._store.context(self.id, self.thread_id)
        result = assembler.assemble(
            items, current_run_id=self.run_id or "", provider=self._store.provider,
            summary=self._store.summaries.active(context),
            notes=self._store.notes.list_notes(context),
        )
        return [dict(message) for message in result.messages], result.memory_directive


class ThreadAwareTranscriptStore:
    """Schema-v2 Session facade backed by ThreadTranscriptService."""

    def __init__(self, cwd: Path, *, thread_id: str | None = None, provider: str = "local") -> None:
        self.cwd = cwd.resolve()
        self.database_path = self.cwd / ".secminiagent" / "memory" / "memory.db"
        self.requested_thread_id = thread_id
        self.provider = provider
        # Runtime objects are session-bound and are opened lazily by create/load.
        self.lifecycle = None
        self.transcript = None
        self.notes = None
        self.summaries = None
        self._base_context = None

    def _open(self, session_id: str, thread_id: str | None = None) -> None:
        (
            self.lifecycle, self.transcript, self.notes, self.summaries, self._base_context,
        ) = create_note_summary_runtime(
            self.cwd, session_id=session_id, thread_id=thread_id or self.requested_thread_id,
            provider=self.provider,
        )

    def context(self, session_id: str, thread_id: str) -> MemoryAccessContext:
        if self._base_context is None or self._base_context.session_id != session_id:
            self._open(session_id, thread_id)
        return MemoryAccessContext(self._base_context.workspace_id, session_id, self.provider, thread_id=thread_id)

    def create(self) -> ThreadSessionState:
        if self.requested_thread_id is not None:
            raise MemoryPolicyDenied("THREAD_SELECTION_REQUIRES_RESUME")
        session_id = str(uuid.uuid4())
        self._open(session_id)
        self.lifecycle.store.create_session(self._base_context.workspace_id, session_id)
        thread = self.lifecycle.ensure_main_thread(self._base_context)
        return ThreadSessionState(session_id, self.cwd, self.database_path, thread.thread_id, self)

    def load(self, session_id: str) -> ThreadSessionState:
        self._open(session_id, self.requested_thread_id)
        if self.requested_thread_id is None:
            thread = self.lifecycle.ensure_main_thread(self._base_context)
        else:
            thread = self.lifecycle.activate_thread(self._base_context, self.requested_thread_id)
        bound = MemoryAccessContext(self._base_context.workspace_id, session_id, self.provider, thread_id=thread.thread_id)
        messages = [dict(item.message) for item in self.transcript.resume(bound)]
        return ThreadSessionState(session_id, self.cwd, self.database_path, thread.thread_id, self, messages)

    def migrate_legacy_sessions(self, *, delete_source: bool = False) -> MigrationReport:
        _ = delete_source
        raise MemoryPolicyDenied("LEGACY_IMPORT_REQUIRES_SCHEMA_V1_RUNTIME")


class TranscriptStore:
    """Runtime adapter: v1 remains default; an activated v2 database uses Thread-aware storage."""

    def __new__(cls, cwd: Path, *, thread_id: str | None = None, provider: str = "local"):
        from secminiagent.memory.schema import SchemaState, inspect_database_path

        root = cwd.resolve()
        database = root / ".secminiagent" / "memory" / "memory.db"
        if inspect_database_path(database).state is SchemaState.V2:
            return ThreadAwareTranscriptStore(root, thread_id=thread_id, provider=provider)
        return SecureTranscriptStore(root)
