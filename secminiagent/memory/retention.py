from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .canonical import canonical_timestamp
from .errors import MemoryLifecycleConflict, MemoryNotFound, MemoryValidationError
from .models import MemoryAccessContext, NoteStatus
from .store_v2 import SQLiteV2Store, memory_state_fields


@dataclass(frozen=True, slots=True)
class RetentionDecision:
    memory_id: str
    expires_at: datetime | None
    pinned: bool
    reason_code: str


class RetentionService:
    def __init__(self, store: SQLiteV2Store, *, min_ttl_seconds: int = 60, max_ttl_days: int = 3650) -> None:
        self.store = store
        self.min_ttl_seconds = min_ttl_seconds
        self.max_ttl_days = max_ttl_days

    def set_expiry(
        self, context: MemoryAccessContext, memory_id: str, expires_at: datetime,
        *, policy_id: str = "explicit", expected_state_version: int | None = None,
    ) -> RetentionDecision:
        if expires_at.tzinfo is None or expires_at.utcoffset() is None:
            raise MemoryValidationError("RETENTION_EXPIRY_REQUIRES_TIMEZONE")
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", policy_id):
            raise MemoryValidationError("RETENTION_POLICY_ID_INVALID")
        if expires_at > datetime.now(timezone.utc) + timedelta(days=self.max_ttl_days):
            raise MemoryValidationError("RETENTION_TTL_ABOVE_MAXIMUM")
        return self._update(context, memory_id, expires_at=expires_at, policy_id=policy_id, expected=expected_state_version)

    def apply_default_ttl(
        self, context: MemoryAccessContext, memory_id: str, ttl_seconds: int,
        *, policy_id: str = "default:local-v1",
    ) -> RetentionDecision:
        if not self.min_ttl_seconds <= ttl_seconds <= self.max_ttl_days * 86400:
            raise MemoryValidationError("RETENTION_TTL_OUT_OF_RANGE")
        return self.set_expiry(
            context, memory_id, datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds),
            policy_id=policy_id,
        )

    def pin(self, context: MemoryAccessContext, memory_id: str, pinned: bool) -> RetentionDecision:
        return self._update(context, memory_id, pinned=pinned)

    def scan_expired(self, context: MemoryAccessContext, *, dry_run: bool = True) -> tuple[str, ...]:
        now = canonical_timestamp(datetime.now(timezone.utc))
        with self.store.connection() as connection:
            ids = tuple(str(row[0]) for row in connection.execute(
                f"SELECT id FROM {self.store.table('memories')} WHERE workspace_id=? AND deleted_at IS NULL AND lifecycle_status NOT IN ('expired','deleted','pending_delete') AND expires_at IS NOT NULL AND expires_at<=? AND NOT(pinned=1 AND retention_policy_id LIKE 'default:%') ORDER BY id",
                (context.workspace_id, now),
            ))
        if dry_run:
            return ids
        for memory_id in ids:
            with self.store.connection(immediate=True) as connection:
                row = self._row(connection, context, memory_id)
                if row["expires_at"] is None or row["expires_at"] > now:
                    continue
                if bool(row["pinned"]) and str(row["retention_policy_id"] or "").startswith("default:"):
                    continue
                self._set_lifecycle(connection, row, NoteStatus.EXPIRED)
        return ids

    def decision(self, context: MemoryAccessContext, memory_id: str) -> RetentionDecision:
        with self.store.connection() as connection:
            row = self._row(connection, context, memory_id)
            return self._decision(row)

    def _update(
        self, context: MemoryAccessContext, memory_id: str, *, expires_at: datetime | None = None,
        policy_id: str | None = None, pinned: bool | None = None, expected: int | None = None,
    ) -> RetentionDecision:
        with self.store.connection(immediate=True) as connection:
            row = self._row(connection, context, memory_id)
            if expected is not None and int(row["state_version"]) != expected:
                raise MemoryLifecycleConflict("RETENTION_CAS_CONFLICT")
            current = dict(row)
            current.update(
                expires_at=canonical_timestamp(expires_at) if expires_at is not None else row["expires_at"],
                retention_policy_id=policy_id if policy_id is not None else row["retention_policy_id"],
                pinned=int(pinned) if pinned is not None else int(row["pinned"]),
                state_version=int(row["state_version"]) + 1,
                updated_at=canonical_timestamp(datetime.now(timezone.utc)),
            )
            current["state_mac"] = self.store.authenticator.sign_memory(memory_state_fields(current))
            result = connection.execute(
                f"UPDATE {self.store.table('memories')} SET expires_at=?,retention_policy_id=?,pinned=?,state_version=?,updated_at=?,state_mac=? WHERE id=? AND state_version=?",
                (current["expires_at"], current["retention_policy_id"], current["pinned"], current["state_version"], current["updated_at"], current["state_mac"], memory_id, row["state_version"]),
            )
            if result.rowcount != 1:
                raise MemoryLifecycleConflict("RETENTION_CAS_CONFLICT")
            return self._decision(self._row(connection, context, memory_id))

    def _row(self, connection: sqlite3.Connection, context: MemoryAccessContext, memory_id: str) -> sqlite3.Row:
        row = connection.execute(
            f"SELECT * FROM {self.store.table('memories')} WHERE workspace_id=? AND id=? AND deleted_at IS NULL",
            (context.workspace_id, memory_id),
        ).fetchone()
        if row is None:
            raise MemoryNotFound("memory not found or inaccessible")
        self.store.authenticate_memory_row(row)
        if row["scope"] == "session" and row["session_id"] != context.session_id:
            raise MemoryNotFound("memory not found or inaccessible")
        if row["scope"] == "thread" and (row["session_id"] != context.session_id or row["thread_id"] != context.thread_id):
            raise MemoryNotFound("memory not found or inaccessible")
        return row

    def _set_lifecycle(self, connection: sqlite3.Connection, row: sqlite3.Row, status: NoteStatus) -> None:
        current = dict(row)
        current.update(lifecycle_status=status.value, state_version=int(row["state_version"]) + 1, updated_at=canonical_timestamp(datetime.now(timezone.utc)))
        current["state_mac"] = self.store.authenticator.sign_memory(memory_state_fields(current))
        connection.execute(
            f"UPDATE {self.store.table('memories')} SET lifecycle_status=?,state_version=?,updated_at=?,state_mac=? WHERE id=? AND state_version=?",
            (status.value, current["state_version"], current["updated_at"], current["state_mac"], row["id"], row["state_version"]),
        )

    @staticmethod
    def _decision(row: sqlite3.Row) -> RetentionDecision:
        policy = str(row["retention_policy_id"] or "")
        reason = "RETENTION_PINNED_DEFAULT" if row["pinned"] and policy.startswith("default:") else "RETENTION_EXPLICIT" if policy == "explicit" else "RETENTION_POLICY"
        expires = datetime.fromisoformat(str(row["expires_at"]).replace("Z", "+00:00")) if row["expires_at"] else None
        return RetentionDecision(str(row["id"]), expires, bool(row["pinned"]), reason)
