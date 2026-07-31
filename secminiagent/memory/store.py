from __future__ import annotations

import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Iterator, Sequence

from ._ports import EncryptedPayload
from .audit import AuditEvent
from .errors import MemoryAccessDenied, MemoryNotFound, MemorySchemaUnsupported
from .models import (
    IndexStatus,
    MemoryAccessContext,
    MemoryAction,
    MemoryClassification,
    MemoryMetadata,
    MemoryQuery,
    MemoryScope,
    MemoryType,
)


from .schema import SCHEMA_V1, SchemaState, inspect_schema


SCHEMA_VERSION = SCHEMA_V1


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def hash_memory_id(memory_id: str) -> str:
    return sha256(memory_id.encode("utf-8")).hexdigest()


class SQLiteMemoryStore:
    """Transactional ciphertext authority and metadata-only audit store."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            inspection = inspect_schema(connection)
            if inspection.state in {SchemaState.V2, SchemaState.NEWER, SchemaState.UNKNOWN}:
                raise MemorySchemaUnsupported("memory database schema is unsupported by the v1 runtime")
            if inspection.user_version == 0:
                connection.executescript(
                    """
                    CREATE TABLE memories (
                        id TEXT PRIMARY KEY,
                        schema_version INTEGER NOT NULL,
                        workspace_id TEXT NOT NULL,
                        session_id TEXT,
                        scope TEXT NOT NULL,
                        memory_type TEXT NOT NULL,
                        classification TEXT NOT NULL,
                        source_type TEXT NOT NULL,
                        policy_action TEXT NOT NULL,
                        policy_reason_codes TEXT NOT NULL,
                        key_version INTEGER NOT NULL,
                        algorithm TEXT NOT NULL,
                        ciphertext BLOB NOT NULL,
                        nonce BLOB NOT NULL,
                        index_status TEXT NOT NULL,
                        sequence_no INTEGER,
                        created_at TEXT NOT NULL,
                        expires_at TEXT,
                        deleted_at TEXT
                    );
                    CREATE INDEX idx_memories_workspace
                    ON memories(workspace_id, deleted_at, created_at);
                    CREATE INDEX idx_memories_session
                    ON memories(workspace_id, session_id, deleted_at, sequence_no);
                    CREATE TABLE memory_audit (
                        event_id TEXT PRIMARY KEY,
                        action TEXT NOT NULL,
                        outcome TEXT NOT NULL,
                        workspace_id TEXT NOT NULL,
                        memory_id_hash TEXT,
                        reason_code TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    );
                    PRAGMA user_version = 1;
                    """
                )

    def insert(self, metadata: MemoryMetadata, payload: EncryptedPayload) -> None:
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO memories (
                    id, schema_version, workspace_id, session_id, scope, memory_type,
                    classification, source_type, policy_action, policy_reason_codes,
                    key_version, algorithm, ciphertext, nonce, index_status, sequence_no,
                    created_at, expires_at, deleted_at
                ) VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    metadata.id,
                    metadata.workspace_id,
                    metadata.session_id,
                    metadata.scope.value,
                    metadata.memory_type.value,
                    metadata.classification.value,
                    metadata.source_type,
                    metadata.policy_action.value,
                    "|".join(metadata.policy_reason_codes),
                    payload.key_version,
                    payload.algorithm,
                    payload.ciphertext,
                    payload.nonce,
                    metadata.index_status.value,
                    metadata.sequence_no,
                    metadata.created_at.isoformat(),
                    metadata.expires_at.isoformat() if metadata.expires_at else None,
                    metadata.deleted_at.isoformat() if metadata.deleted_at else None,
                ),
            )

    def fetch(
        self,
        memory_id: str,
        context: MemoryAccessContext,
    ) -> tuple[MemoryMetadata, EncryptedPayload] | None:
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT * FROM memories
                WHERE id = ? AND workspace_id = ? AND deleted_at IS NULL
                  AND (scope = 'workspace' OR (scope = 'session' AND session_id = ?))
                """,
                (memory_id, context.workspace_id, context.session_id),
            ).fetchone()
        if row is None:
            return None
        return self._row_payload(row)

    def list_metadata(
        self,
        query: MemoryQuery,
        context: MemoryAccessContext,
    ) -> Sequence[MemoryMetadata]:
        clauses = [
            "workspace_id = ?",
            "deleted_at IS NULL",
            "(scope = 'workspace' OR (scope = 'session' AND session_id = ?))",
        ]
        values: list[object] = [context.workspace_id, context.session_id]
        if query.memory_types:
            clauses.append("memory_type IN (" + ",".join("?" for _ in query.memory_types) + ")")
            values.extend(item.value for item in query.memory_types)
        if query.classifications:
            clauses.append("classification IN (" + ",".join("?" for _ in query.classifications) + ")")
            values.extend(item.value for item in query.classifications)
        values.append(query.limit)
        sql = (
            "SELECT * FROM memories WHERE "
            + " AND ".join(clauses)
            + " ORDER BY COALESCE(sequence_no, 2147483647), created_at, id LIMIT ?"
        )
        with self._connection() as connection:
            rows = connection.execute(sql, values).fetchall()
        return tuple(self._row_metadata(row) for row in rows)

    def mark_pending_delete(self, memory_id: str, context: MemoryAccessContext) -> MemoryMetadata:
        timestamp = utc_now().isoformat()
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT * FROM memories
                WHERE id = ? AND workspace_id = ? AND deleted_at IS NULL
                  AND (scope = 'workspace' OR (scope = 'session' AND session_id = ?))
                """,
                (memory_id, context.workspace_id, context.session_id),
            ).fetchone()
            if row is None:
                raise MemoryNotFound("memory not found or inaccessible")
            connection.execute(
                "UPDATE memories SET deleted_at = ?, index_status = ? WHERE id = ?",
                (timestamp, IndexStatus.PENDING_DELETE.value, memory_id),
            )
            updated = dict(row)
            updated["deleted_at"] = timestamp
            updated["index_status"] = IndexStatus.PENDING_DELETE.value
        return self._row_metadata(updated)

    def purge_ciphertext(self, memory_id: str, context: MemoryAccessContext) -> None:
        with self._connection() as connection:
            result = connection.execute(
                "DELETE FROM memories WHERE id = ? AND workspace_id = ? AND deleted_at IS NOT NULL",
                (memory_id, context.workspace_id),
            )
            if result.rowcount != 1:
                raise MemoryNotFound("pending deletion not found")

    def update_index_status(self, memory_id: str, workspace_id: str, status: IndexStatus) -> None:
        with self._connection() as connection:
            result = connection.execute(
                "UPDATE memories SET index_status = ? WHERE id = ? AND workspace_id = ?",
                (status.value, memory_id, workspace_id),
            )
            if result.rowcount != 1:
                raise MemoryNotFound("memory not found")

    def pending_delete_ids(self, workspace_id: str) -> tuple[str, ...]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT id FROM memories WHERE workspace_id = ? AND index_status = ?",
                (workspace_id, IndexStatus.PENDING_DELETE.value),
            ).fetchall()
        return tuple(str(row["id"]) for row in rows)

    def all_live_metadata(self, context: MemoryAccessContext) -> tuple[MemoryMetadata, ...]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT * FROM memories
                WHERE workspace_id = ? AND deleted_at IS NULL
                  AND (scope = 'workspace' OR (scope = 'session' AND session_id = ?))
                ORDER BY COALESCE(sequence_no, 2147483647), created_at, id
                """,
                (context.workspace_id, context.session_id),
            ).fetchall()
        return tuple(self._row_metadata(row) for row in rows)

    def all_workspace_live_metadata(self, workspace_id: str) -> tuple[MemoryMetadata, ...]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT * FROM memories
                WHERE workspace_id = ? AND deleted_at IS NULL
                ORDER BY created_at, id
                """,
                (workspace_id,),
            ).fetchall()
        return tuple(self._row_metadata(row) for row in rows)

    def record(
        self,
        *,
        action: str,
        outcome: str,
        workspace_id: str,
        memory_id_hash: str | None,
        reason_code: str,
    ) -> str:
        event_id = str(uuid.uuid4())
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO memory_audit (
                    event_id, action, outcome, workspace_id, memory_id_hash,
                    reason_code, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (event_id, action, outcome, workspace_id, memory_id_hash, reason_code, utc_now().isoformat()),
            )
        return event_id

    def list_audit(self, workspace_id: str, limit: int = 100) -> tuple[AuditEvent, ...]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT * FROM memory_audit
                WHERE workspace_id = ?
                ORDER BY created_at DESC LIMIT ?
                """,
                (workspace_id, max(1, min(limit, 500))),
            ).fetchall()
        return tuple(
            AuditEvent(
                event_id=str(row["event_id"]),
                action=str(row["action"]),
                outcome=str(row["outcome"]),
                workspace_id=str(row["workspace_id"]),
                memory_id_hash=str(row["memory_id_hash"]) if row["memory_id_hash"] else None,
                reason_code=str(row["reason_code"]),
                created_at=datetime.fromisoformat(str(row["created_at"])),
            )
            for row in rows
        )

    def status(self, workspace_id: str) -> dict[str, int]:
        with self._connection() as connection:
            live = connection.execute(
                "SELECT COUNT(*) FROM memories WHERE workspace_id = ? AND deleted_at IS NULL",
                (workspace_id,),
            ).fetchone()[0]
            pending = connection.execute(
                "SELECT COUNT(*) FROM memories WHERE workspace_id = ? AND index_status = ?",
                (workspace_id, IndexStatus.PENDING_DELETE.value),
            ).fetchone()[0]
            audit = connection.execute(
                "SELECT COUNT(*) FROM memory_audit WHERE workspace_id = ?",
                (workspace_id,),
            ).fetchone()[0]
        return {"live_memories": int(live), "pending_deletions": int(pending), "audit_events": int(audit)}

    def vacuum(self) -> None:
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("VACUUM")
        finally:
            connection.close()

    @staticmethod
    def _row_payload(row: sqlite3.Row | dict[str, object]) -> tuple[MemoryMetadata, EncryptedPayload]:
        metadata = SQLiteMemoryStore._row_metadata(row)
        payload = EncryptedPayload(
            ciphertext=bytes(row["ciphertext"]),
            nonce=bytes(row["nonce"]),
            key_version=int(row["key_version"]),
            algorithm=str(row["algorithm"]),
        )
        return metadata, payload

    @staticmethod
    def _row_metadata(row: sqlite3.Row | dict[str, object]) -> MemoryMetadata:
        return MemoryMetadata(
            id=str(row["id"]),
            workspace_id=str(row["workspace_id"]),
            session_id=str(row["session_id"]) if row["session_id"] is not None else None,
            scope=MemoryScope(str(row["scope"])),
            memory_type=MemoryType(str(row["memory_type"])),
            classification=MemoryClassification(str(row["classification"])),
            source_type=str(row["source_type"]),
            policy_action=MemoryAction(str(row["policy_action"])),
            policy_reason_codes=tuple(str(row["policy_reason_codes"]).split("|")),
            index_status=IndexStatus(str(row["index_status"])),
            sequence_no=int(row["sequence_no"]) if row["sequence_no"] is not None else None,
            created_at=datetime.fromisoformat(str(row["created_at"])),
            expires_at=datetime.fromisoformat(str(row["expires_at"])) if row["expires_at"] else None,
            deleted_at=datetime.fromisoformat(str(row["deleted_at"])) if row["deleted_at"] else None,
        )
