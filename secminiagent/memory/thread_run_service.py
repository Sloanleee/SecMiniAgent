from __future__ import annotations

import hmac
import re
import secrets

from .errors import MemoryAccessDenied, MemoryLifecycleConflict, MemoryNotFound, MemoryValidationError
from .models import MemoryAccessContext, RunMetadata, RunStatus, ThreadMetadata, ThreadStatus
from .thread_run_store import ThreadRunStore
from .migration_v1_v2 import legacy_main_thread_id


class ThreadRunService:
    """Policy boundary for authenticated Thread/Run lifecycle operations."""

    def __init__(self, store: ThreadRunStore, *, id_key: bytes) -> None:
        if len(id_key) < 32:
            raise MemoryValidationError("lifecycle id key is invalid")
        self.store = store
        self._id_key = id_key

    def _require_session(self, context: MemoryAccessContext) -> str:
        if context.session_id is None:
            raise MemoryAccessDenied("thread lifecycle requires a session context")
        return context.session_id

    @staticmethod
    def _reason_code(value: str) -> str:
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", value):
            raise MemoryValidationError("lifecycle reason code is invalid")
        return value

    def _thread_context(self, context: MemoryAccessContext, thread_id: str) -> None:
        if context.thread_id is not None and not hmac.compare_digest(context.thread_id, thread_id):
            raise MemoryAccessDenied("thread belongs to another access context")

    def main_thread_id(self, context: MemoryAccessContext) -> str:
        session_id = self._require_session(context)
        return legacy_main_thread_id(self._id_key, session_id)

    def ensure_main_thread(self, context: MemoryAccessContext) -> ThreadMetadata:
        thread_id = self.main_thread_id(context)
        try:
            return self.store.get_thread(context.workspace_id, self._require_session(context), thread_id)
        except MemoryNotFound:
            pass
        try:
            return self.store.create_thread(context.workspace_id, self._require_session(context), thread_id, title=None, goal=None)
        except MemoryLifecycleConflict:
            return self.store.get_thread(context.workspace_id, self._require_session(context), thread_id)

    def create_thread(self, context: MemoryAccessContext, title: str | None = None, goal: str | None = None) -> ThreadMetadata:
        return self.store.create_thread(
            context.workspace_id, self._require_session(context), secrets.token_hex(32), title=title, goal=goal,
        )

    def list_threads(self, context: MemoryAccessContext, include_archived: bool = False) -> tuple[ThreadMetadata, ...]:
        return self.store.list_threads(context.workspace_id, self._require_session(context), include_archived=include_archived)

    def get_thread(self, context: MemoryAccessContext, thread_id: str) -> ThreadMetadata:
        self._thread_context(context, thread_id)
        return self.store.get_thread(context.workspace_id, self._require_session(context), thread_id)

    def activate_thread(self, context: MemoryAccessContext, thread_id: str) -> ThreadMetadata:
        thread = self.get_thread(context, thread_id)
        if thread.status is not ThreadStatus.ACTIVE:
            raise MemoryLifecycleConflict("THREAD_NOT_ACTIVE")
        return thread

    def archive_thread(self, context: MemoryAccessContext, thread_id: str) -> ThreadMetadata:
        self._thread_context(context, thread_id)
        return self.store.archive_thread(context.workspace_id, self._require_session(context), thread_id)

    def begin_run(self, context: MemoryAccessContext, thread_id: str) -> RunMetadata:
        self._thread_context(context, thread_id)
        return self.store.begin_run(
            context.workspace_id, self._require_session(context), thread_id, secrets.token_hex(32),
        )

    def list_runs(self, context: MemoryAccessContext, thread_id: str) -> tuple[RunMetadata, ...]:
        self._thread_context(context, thread_id)
        return self.store.list_runs(context.workspace_id, self._require_session(context), thread_id)

    def _transition(
        self, context: MemoryAccessContext, run_id: str, status: RunStatus,
        reason_code: str | None, final_message_id: str | None = None,
    ) -> RunMetadata:
        if context.thread_id is None:
            raise MemoryAccessDenied("run lifecycle requires a thread context")
        return self.store.transition_run(
            context.workspace_id, self._require_session(context), context.thread_id, run_id, status,
            reason_code=reason_code, final_message_id=final_message_id,
        )

    def complete_run(self, context: MemoryAccessContext, run_id: str, final_message_id: str | None = None) -> RunMetadata:
        return self._transition(context, run_id, RunStatus.COMPLETED, None, final_message_id)

    def fail_run(self, context: MemoryAccessContext, run_id: str, reason_code: str) -> RunMetadata:
        return self._transition(context, run_id, RunStatus.FAILED, self._reason_code(reason_code))

    def interrupt_run(self, context: MemoryAccessContext, run_id: str, reason_code: str = "USER_INTERRUPTED") -> RunMetadata:
        return self._transition(context, run_id, RunStatus.INTERRUPTED, self._reason_code(reason_code))

    def recover_running_runs(self, context: MemoryAccessContext, thread_id: str | None = None) -> tuple[RunMetadata, ...]:
        selected = thread_id or context.thread_id
        if selected is not None:
            self._thread_context(context, selected)
        return self.store.recover_running(context.workspace_id, self._require_session(context), selected)
