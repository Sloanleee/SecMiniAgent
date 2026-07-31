from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

from .canonical import canonical_timestamp
from .errors import MemoryLifecycleConflict, MemoryNotFound
from .models import RunMetadata, RunStatus, SessionStatus, ThreadMetadata, ThreadStatus
from .store_v2 import SQLiteV2Store, run_state_fields, session_state_fields, thread_state_fields


def _now() -> str:
    return canonical_timestamp(datetime.now(timezone.utc)) or ""


def _dt(value: object | None) -> datetime | None:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")) if value else None


class ThreadRunStore:
    """Authenticated Schema-v2 lifecycle persistence; no policy or CLI concerns."""

    def __init__(self, store: SQLiteV2Store) -> None:
        self.store = store

    def create_session(self, workspace_id: str, session_id: str) -> None:
        now = _now()
        with self.store.connection(immediate=True) as connection:
            existing = connection.execute(
                f"SELECT * FROM {self.store.table('sessions')} WHERE workspace_id=? AND session_id=?",
                (workspace_id, session_id),
            ).fetchone()
            if existing is not None:
                self.store.authenticator.verify_session(bytes(existing["state_mac"]), session_state_fields(dict(existing)))
                raise MemoryLifecycleConflict("SESSION_ALREADY_EXISTS")
            self.store.insert_session(connection, {
                "workspace_id": workspace_id, "session_id": session_id, "schema_version": 2,
                "status": SessionStatus.ACTIVE.value, "revision": 1, "state_version": 1,
                "created_at": now, "updated_at": now, "deleted_at": None,
            })

    def create_thread(
        self, workspace_id: str, session_id: str, thread_id: str, *, title: str | None, goal: str | None,
    ) -> ThreadMetadata:
        now = _now()
        row = {
            "workspace_id": workspace_id, "session_id": session_id, "thread_id": thread_id,
            "schema_version": 2, "status": ThreadStatus.ACTIVE.value, "revision": 1,
            "next_run_no": 1, "next_thread_sequence": 1, "state_version": 1,
            "created_at": now, "updated_at": now, "deleted_at": None,
        }
        payload = json.dumps({"title": title, "goal": goal}, ensure_ascii=False, separators=(",", ":")).encode()
        try:
            with self.store.connection(immediate=True) as connection:
                self._session(connection, workspace_id, session_id)
                self.store.insert_thread(connection, row, payload)
                created = self._thread(connection, workspace_id, session_id, thread_id)
                return self._thread_metadata(created)
        except sqlite3.IntegrityError as exc:
            raise MemoryLifecycleConflict("THREAD_CREATE_CONFLICT") from exc

    def verify_ancestry(
        self, connection: sqlite3.Connection, workspace_id: str, session_id: str,
        thread_id: str, run_id: str | None = None, *, require_running: bool = False,
    ) -> tuple[sqlite3.Row, sqlite3.Row | None]:
        self._session(connection, workspace_id, session_id)
        thread = self._thread(connection, workspace_id, session_id, thread_id)
        if thread["status"] != ThreadStatus.ACTIVE.value:
            raise MemoryLifecycleConflict("THREAD_NOT_ACTIVE")
        run = None
        if run_id is not None:
            run = self._run(connection, workspace_id, session_id, thread_id, run_id)
            if require_running and run["status"] != RunStatus.RUNNING.value:
                raise MemoryLifecycleConflict("RUN_NOT_RUNNING")
        return thread, run

    def get_thread(self, workspace_id: str, session_id: str, thread_id: str) -> ThreadMetadata:
        with self.store.connection() as connection:
            self._session(connection, workspace_id, session_id)
            return self._thread_metadata(self._thread(connection, workspace_id, session_id, thread_id))

    def list_threads(self, workspace_id: str, session_id: str, *, include_archived: bool) -> tuple[ThreadMetadata, ...]:
        with self.store.connection() as connection:
            self._session(connection, workspace_id, session_id)
            sql = f"SELECT * FROM {self.store.table('threads')} WHERE workspace_id=? AND session_id=? AND deleted_at IS NULL"
            params: list[object] = [workspace_id, session_id]
            if not include_archived:
                sql += " AND status='active'"
            sql += " ORDER BY created_at,thread_id"
            return tuple(self._thread_metadata(self._verified_thread(row)) for row in connection.execute(sql, params))

    def archive_thread(self, workspace_id: str, session_id: str, thread_id: str) -> ThreadMetadata:
        with self.store.connection(immediate=True) as connection:
            self._session(connection, workspace_id, session_id)
            row = self._thread(connection, workspace_id, session_id, thread_id)
            if row["status"] == ThreadStatus.ARCHIVED.value:
                return self._thread_metadata(row)
            if row["status"] != ThreadStatus.ACTIVE.value:
                raise MemoryLifecycleConflict("THREAD_NOT_ACTIVE")
            running = connection.execute(
                f"SELECT 1 FROM {self.store.table('runs')} WHERE workspace_id=? AND session_id=? AND thread_id=? AND status='running' AND deleted_at IS NULL",
                (workspace_id, session_id, thread_id),
            ).fetchone()
            if running:
                raise MemoryLifecycleConflict("THREAD_HAS_RUNNING_RUN")
            self._update_thread_state(connection, row, status=ThreadStatus.ARCHIVED.value)
            return self._thread_metadata(self._thread(connection, workspace_id, session_id, thread_id))

    def begin_run(self, workspace_id: str, session_id: str, thread_id: str, run_id: str) -> RunMetadata:
        try:
            with self.store.connection(immediate=True) as connection:
                self._session(connection, workspace_id, session_id)
                thread = self._thread(connection, workspace_id, session_id, thread_id)
                if thread["status"] != ThreadStatus.ACTIVE.value:
                    raise MemoryLifecycleConflict("THREAD_NOT_ACTIVE")
                if connection.execute(
                    f"SELECT 1 FROM {self.store.table('runs')} WHERE workspace_id=? AND session_id=? AND thread_id=? AND status='running' AND deleted_at IS NULL",
                    (workspace_id, session_id, thread_id),
                ).fetchone():
                    raise MemoryLifecycleConflict("RUN_ALREADY_RUNNING")
                run_no = int(thread["next_run_no"])
                self._update_thread_state(connection, thread, next_run_no=run_no + 1)
                row = {
                    "workspace_id": workspace_id, "session_id": session_id, "thread_id": thread_id,
                    "run_id": run_id, "run_no": run_no, "status": RunStatus.RUNNING.value,
                    "next_run_sequence": 1, "state_version": 1, "input_message_id": None,
                    "final_message_id": None, "turn_count": 0, "started_at": _now(),
                    "completed_at": None, "interruption_reason_code": None,
                    "migration_origin": None, "deleted_at": None,
                }
                self.store.insert_run(connection, row)
                return self._run_metadata(self._run(connection, workspace_id, session_id, thread_id, run_id))
        except sqlite3.IntegrityError as exc:
            raise MemoryLifecycleConflict("RUN_CREATE_CONFLICT") from exc
        except sqlite3.OperationalError as exc:
            raise MemoryLifecycleConflict("LIFECYCLE_DATABASE_BUSY") from exc

    def list_runs(self, workspace_id: str, session_id: str, thread_id: str) -> tuple[RunMetadata, ...]:
        with self.store.connection() as connection:
            self._session(connection, workspace_id, session_id)
            self._thread(connection, workspace_id, session_id, thread_id)
            rows = connection.execute(
                f"SELECT * FROM {self.store.table('runs')} WHERE workspace_id=? AND session_id=? AND thread_id=? AND deleted_at IS NULL ORDER BY run_no",
                (workspace_id, session_id, thread_id),
            )
            return tuple(self._run_metadata(self._verified_run(row)) for row in rows)

    def transition_run(
        self, workspace_id: str, session_id: str, thread_id: str, run_id: str,
        target: RunStatus, *, reason_code: str | None = None, final_message_id: str | None = None,
    ) -> RunMetadata:
        if target not in {RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.INTERRUPTED}:
            raise MemoryLifecycleConflict("RUN_TARGET_STATUS_INVALID")
        with self.store.connection(immediate=True) as connection:
            self._session(connection, workspace_id, session_id)
            self._thread(connection, workspace_id, session_id, thread_id)
            row = self._run(connection, workspace_id, session_id, thread_id, run_id)
            if row["status"] == target.value:
                same_final = target is not RunStatus.COMPLETED or row["final_message_id"] == final_message_id
                if row["interruption_reason_code"] == reason_code and same_final:
                    return self._run_metadata(row)
                raise MemoryLifecycleConflict("RUN_IDEMPOTENCY_CONFLICT")
            if row["status"] != RunStatus.RUNNING.value:
                raise MemoryLifecycleConflict("RUN_ALREADY_TERMINAL")
            if final_message_id is not None and connection.execute(
                f"SELECT 1 FROM {self.store.table('memories')} WHERE workspace_id=? AND session_id=? AND thread_id=? AND run_id=? AND id=? AND memory_type='message' AND deleted_at IS NULL",
                (workspace_id, session_id, thread_id, run_id, final_message_id),
            ).fetchone() is None:
                raise MemoryLifecycleConflict("RUN_FINAL_MESSAGE_INVALID")
            current = dict(row)
            current.update(
                status=target.value, completed_at=_now(),
                interruption_reason_code=reason_code if target in {RunStatus.FAILED, RunStatus.INTERRUPTED} else None,
                final_message_id=final_message_id if target is RunStatus.COMPLETED else row["final_message_id"],
                state_version=int(row["state_version"]) + 1,
            )
            current["state_mac"] = self.store.authenticator.sign_run(run_state_fields(current))
            result = connection.execute(
                f"UPDATE {self.store.table('runs')} SET status=?,completed_at=?,interruption_reason_code=?,final_message_id=?,state_version=?,state_mac=? "
                "WHERE workspace_id=? AND session_id=? AND thread_id=? AND run_id=? AND state_version=? AND status='running'",
                (current["status"], current["completed_at"], current["interruption_reason_code"], current["final_message_id"], current["state_version"], current["state_mac"],
                 workspace_id, session_id, thread_id, run_id, row["state_version"]),
            )
            if result.rowcount != 1:
                raise MemoryLifecycleConflict("RUN_CAS_CONFLICT")
            return self._run_metadata(self._run(connection, workspace_id, session_id, thread_id, run_id))

    def recover_running(self, workspace_id: str, session_id: str, thread_id: str | None) -> tuple[RunMetadata, ...]:
        with self.store.connection() as connection:
            self._session(connection, workspace_id, session_id)
            if thread_id is not None:
                self._thread(connection, workspace_id, session_id, thread_id)
                rows = connection.execute(
                    f"SELECT thread_id,run_id FROM {self.store.table('runs')} WHERE workspace_id=? AND session_id=? AND thread_id=? AND status='running' AND deleted_at IS NULL ORDER BY run_no",
                    (workspace_id, session_id, thread_id),
                ).fetchall()
            else:
                rows = connection.execute(
                    f"SELECT thread_id,run_id FROM {self.store.table('runs')} WHERE workspace_id=? AND session_id=? AND status='running' AND deleted_at IS NULL ORDER BY thread_id,run_no",
                    (workspace_id, session_id),
                ).fetchall()
        return tuple(
            self.transition_run(workspace_id, session_id, str(row["thread_id"]), str(row["run_id"]), RunStatus.INTERRUPTED, reason_code="PROCESS_RECOVERY")
            for row in rows
        )

    def record_message_progress(
        self, connection: sqlite3.Connection, workspace_id: str, session_id: str,
        thread_id: str, run_id: str, message_id: str, role: str,
    ) -> None:
        row = self._run(connection, workspace_id, session_id, thread_id, run_id)
        if row["status"] != RunStatus.RUNNING.value:
            raise MemoryLifecycleConflict("RUN_NOT_RUNNING")
        current = dict(row)
        if role == "user" and current["input_message_id"] is None:
            current["input_message_id"] = message_id
        if role == "assistant":
            current["turn_count"] = int(current["turn_count"]) + 1
        current["state_version"] = int(current["state_version"]) + 1
        current["state_mac"] = self.store.authenticator.sign_run(run_state_fields(current))
        result = connection.execute(
            f"UPDATE {self.store.table('runs')} SET input_message_id=?,turn_count=?,state_version=?,state_mac=? "
            "WHERE workspace_id=? AND session_id=? AND thread_id=? AND run_id=? AND state_version=?",
            (current["input_message_id"], current["turn_count"], current["state_version"], current["state_mac"],
             workspace_id, session_id, thread_id, run_id, row["state_version"]),
        )
        if result.rowcount != 1:
            raise MemoryLifecycleConflict("RUN_CAS_CONFLICT")

    def _session(self, connection: sqlite3.Connection, workspace_id: str, session_id: str) -> sqlite3.Row:
        row = connection.execute(
            f"SELECT * FROM {self.store.table('sessions')} WHERE workspace_id=? AND session_id=? AND deleted_at IS NULL",
            (workspace_id, session_id),
        ).fetchone()
        if row is None:
            raise MemoryNotFound("session not found or inaccessible")
        self.store.authenticator.verify_session(bytes(row["state_mac"]), session_state_fields(dict(row)))
        if row["status"] != SessionStatus.ACTIVE.value:
            raise MemoryLifecycleConflict("SESSION_NOT_ACTIVE")
        return row

    def _thread(self, connection: sqlite3.Connection, workspace_id: str, session_id: str, thread_id: str) -> sqlite3.Row:
        row = connection.execute(
            f"SELECT * FROM {self.store.table('threads')} WHERE workspace_id=? AND session_id=? AND thread_id=? AND deleted_at IS NULL",
            (workspace_id, session_id, thread_id),
        ).fetchone()
        if row is None:
            raise MemoryNotFound("thread not found or inaccessible")
        return self._verified_thread(row)

    def _run(self, connection: sqlite3.Connection, workspace_id: str, session_id: str, thread_id: str, run_id: str) -> sqlite3.Row:
        row = connection.execute(
            f"SELECT * FROM {self.store.table('runs')} WHERE workspace_id=? AND session_id=? AND thread_id=? AND run_id=? AND deleted_at IS NULL",
            (workspace_id, session_id, thread_id, run_id),
        ).fetchone()
        if row is None:
            raise MemoryNotFound("run not found or inaccessible")
        return self._verified_run(row)

    def _verified_thread(self, row: sqlite3.Row) -> sqlite3.Row:
        self.store.authenticator.verify_thread(bytes(row["state_mac"]), thread_state_fields(dict(row)))
        return row

    def _verified_run(self, row: sqlite3.Row) -> sqlite3.Row:
        self.store.authenticator.verify_run(bytes(row["state_mac"]), run_state_fields(dict(row)))
        return row

    def _update_thread_state(self, connection: sqlite3.Connection, row: sqlite3.Row, **changes: object) -> None:
        current = dict(row)
        current.update(changes, state_version=int(row["state_version"]) + 1, updated_at=_now())
        current["state_mac"] = self.store.authenticator.sign_thread(thread_state_fields(current))
        assignments = [*changes.keys(), "state_version", "updated_at", "state_mac"]
        result = connection.execute(
            f"UPDATE {self.store.table('threads')} SET " + ",".join(f"{name}=?" for name in assignments) +
            " WHERE workspace_id=? AND session_id=? AND thread_id=? AND state_version=?",
            tuple(current[name] for name in assignments) +
            (row["workspace_id"], row["session_id"], row["thread_id"], row["state_version"]),
        )
        if result.rowcount != 1:
            raise MemoryLifecycleConflict("THREAD_CAS_CONFLICT")

    @staticmethod
    def _thread_metadata(row: sqlite3.Row) -> ThreadMetadata:
        return ThreadMetadata(
            workspace_id=str(row["workspace_id"]), session_id=str(row["session_id"]), thread_id=str(row["thread_id"]),
            status=ThreadStatus(str(row["status"])), revision=int(row["revision"]), next_run_no=int(row["next_run_no"]),
            next_thread_sequence=int(row["next_thread_sequence"]), state_version=int(row["state_version"]),
            created_at=_dt(row["created_at"]), updated_at=_dt(row["updated_at"]),
        )

    @staticmethod
    def _run_metadata(row: sqlite3.Row) -> RunMetadata:
        return RunMetadata(
            workspace_id=str(row["workspace_id"]), session_id=str(row["session_id"]), thread_id=str(row["thread_id"]),
            run_id=str(row["run_id"]), run_no=int(row["run_no"]), status=RunStatus(str(row["status"])),
            next_run_sequence=int(row["next_run_sequence"]), state_version=int(row["state_version"]),
            input_message_id=str(row["input_message_id"]) if row["input_message_id"] else None,
            final_message_id=str(row["final_message_id"]) if row["final_message_id"] else None,
            turn_count=int(row["turn_count"]), migration_origin=str(row["migration_origin"]) if row["migration_origin"] else None,
            started_at=_dt(row["started_at"]), completed_at=_dt(row["completed_at"]),
            interruption_reason_code=str(row["interruption_reason_code"]) if row["interruption_reason_code"] else None,
        )
