from __future__ import annotations

import json
import secrets
import sqlite3
from datetime import datetime, timezone
from typing import Mapping, Sequence

from ._ports import EncryptedPayload
from .canonical import canonical_timestamp
from .classifier import MemorySafetyEvaluator
from .errors import MemoryIntegrityError, MemoryLifecycleConflict, MemoryNotFound, MemoryPolicyDenied
from .models import (
    IndexStatus, MemoryAccessContext, MemoryAction, MemoryCandidate, MemoryClassification,
    MemoryMetadata, MemoryRelationType, MemoryScope, MemorySource, MemoryType, NoteKind,
    NoteStatus, StructuredNote, VerificationStatus,
)
from .provenance import provenance_digest
from .store_v2 import SQLiteV2Store, memory_state_fields
from .thread_run_store import ThreadRunStore


_CLASSIFICATION_ORDER = {
    MemoryClassification.PUBLIC: 0, MemoryClassification.INTERNAL: 1,
    MemoryClassification.CONFIDENTIAL: 2, MemoryClassification.SECRET: 3,
}


def highest_classification(values: Sequence[MemoryClassification]) -> MemoryClassification:
    return max(values or (MemoryClassification.INTERNAL,), key=_CLASSIFICATION_ORDER.__getitem__)


class NotesService:
    """Internal immutable StructuredNote primitives used by M7.4 and later workflows."""

    def __init__(
        self, store: SQLiteV2Store, lifecycle_store: ThreadRunStore,
        *, provenance_key: bytes, evaluator: MemorySafetyEvaluator | None = None,
    ) -> None:
        self.store = store
        self.lifecycle_store = lifecycle_store
        self.provenance_key = provenance_key
        self.evaluator = evaluator or MemorySafetyEvaluator()

    def add_candidate(
        self, context: MemoryAccessContext, *, kind: NoteKind, content: str,
        source_refs: Sequence[str] = (), created_by: str = "user", confidence: float = 0.0,
        importance: float = 0.5, supersedes_id: str | None = None,
        dedup_fingerprint: bytes | None = None, record_revision: int = 1,
    ) -> StructuredNote:
        if context.session_id is None or context.thread_id is None:
            raise MemoryPolicyDenied("NOTE_THREAD_CONTEXT_REQUIRED")
        candidate = MemoryCandidate(
            self._memory_type(kind), content, MemoryScope.THREAD,
            MemorySource("structured_note", user_confirmed=created_by == "user"),
        )
        evaluation = self.evaluator.evaluate(candidate, context)
        if evaluation.persistable_candidate is None:
            raise MemoryPolicyDenied("NOTE_POLICY_REJECTED")
        approved = evaluation.persistable_candidate.content
        note_id = secrets.token_hex(32)
        now = datetime.now(timezone.utc)
        verification = VerificationStatus.MODEL_INFERRED if created_by == "model" else VerificationStatus.UNKNOWN
        with self.store.connection(immediate=True) as connection:
            self.lifecycle_store.verify_ancestry(
                connection, context.workspace_id, context.session_id, context.thread_id,
            )
            source_rows = self._source_rows(connection, context, source_refs)
            inherited = highest_classification([
                evaluation.decision.classification,
                *(MemoryClassification(str(row["classification"])) for row in source_rows),
            ])
            revision = record_revision
            if revision < 1:
                raise MemoryLifecycleConflict("NOTE_REVISION_INVALID")
            if supersedes_id is not None:
                old = self._note_row(connection, context, supersedes_id)
                if old["lifecycle_status"] not in {NoteStatus.CANDIDATE.value, NoteStatus.ACTIVE.value, NoteStatus.DISPUTED.value}:
                    raise MemoryLifecycleConflict("NOTE_REVISION_SOURCE_NOT_ACTIVE")
                revision = int(old["record_revision"]) + 1
            thread_sequence = self.store.allocate_thread_sequence(
                connection, context.workspace_id, context.session_id, context.thread_id,
            )
            note = StructuredNote(
                note_id, context.workspace_id, context.session_id, context.thread_id,
                kind, approved, NoteStatus.CANDIDATE, verification, confidence, importance,
                revision, tuple(source_refs), supersedes_id, created_by=created_by,
                classification=inherited, created_at=now,
            )
            metadata = MemoryMetadata(
                id=note_id, workspace_id=context.workspace_id, session_id=context.session_id,
                scope=MemoryScope.THREAD, memory_type=self._memory_type(kind), classification=inherited,
                source_type="structured_note", policy_action=evaluation.decision.action,
                policy_reason_codes=tuple(evaluation.decision.reason_codes), index_status=IndexStatus.NOT_INDEXED,
                created_at=now, schema_version=2, thread_id=context.thread_id,
                record_revision=revision, thread_sequence=thread_sequence,
                lifecycle_status=NoteStatus.CANDIDATE, verification_status=verification,
                note_kind=kind.value, provenance_digest=provenance_digest(source_refs, MemoryRelationType.DERIVED_FROM, self.provenance_key),
                updated_at=now,
            )
            self.store.insert_memory(
                connection, metadata, self._encode(note),
                importance_millis=round(importance * 1000), dedup_fingerprint=dedup_fingerprint,
            )
            for source_id in source_refs:
                self._relation(connection, context.workspace_id, note_id, source_id, MemoryRelationType.DERIVED_FROM)
            if supersedes_id is not None:
                self._relation(connection, context.workspace_id, note_id, supersedes_id, MemoryRelationType.SUPERSEDES)
                old_target = NoteStatus.REJECTED if old["lifecycle_status"] == NoteStatus.CANDIDATE.value else NoteStatus.SUPERSEDED
                self._set_status(connection, old, old_target)
            return note

    def get(self, context: MemoryAccessContext, note_id: str) -> StructuredNote:
        if context.session_id is None or context.thread_id is None:
            raise MemoryNotFound("note not found or inaccessible")
        with self.store.connection() as connection:
            self.lifecycle_store.verify_ancestry(connection, context.workspace_id, context.session_id, context.thread_id)
            row = self._note_row(connection, context, note_id)
            note = self._decode(row)
            self._verify_note_provenance(connection, row, note)
            return note

    def list_notes(self, context: MemoryAccessContext, *, include_inactive: bool = False) -> tuple[StructuredNote, ...]:
        if context.session_id is None or context.thread_id is None:
            return ()
        with self.store.connection() as connection:
            self.lifecycle_store.verify_ancestry(connection, context.workspace_id, context.session_id, context.thread_id)
            sql = f"SELECT * FROM {self.store.table('memories')} WHERE workspace_id=? AND session_id=? AND thread_id=? AND note_kind IS NOT NULL AND deleted_at IS NULL AND (expires_at IS NULL OR expires_at>? OR (pinned=1 AND retention_policy_id LIKE 'default:%'))"
            params = [context.workspace_id, context.session_id, context.thread_id, canonical_timestamp(datetime.now(timezone.utc))]
            if not include_inactive:
                sql += " AND lifecycle_status='active'"
            sql += " ORDER BY thread_sequence,id"
            result = []
            for row in connection.execute(sql, params):
                note = self._decode(row)
                self._verify_note_provenance(connection, row, note)
                result.append(note)
            return tuple(result)

    def _source_rows(
        self, connection: sqlite3.Connection, context: MemoryAccessContext, source_refs: Sequence[str],
    ) -> tuple[sqlite3.Row, ...]:
        rows = []
        for source_id in source_refs:
            row = connection.execute(
                f"SELECT * FROM {self.store.table('memories')} WHERE workspace_id=? AND id=? AND deleted_at IS NULL",
                (context.workspace_id, source_id),
            ).fetchone()
            if row is None or (row["thread_id"] is not None and row["thread_id"] != context.thread_id):
                raise MemoryNotFound("note source not found or inaccessible")
            self.store.authenticator.verify_memory(bytes(row["state_mac"]), memory_state_fields(dict(row)))
            self.store.authenticate_memory_row(row)
            rows.append(row)
        return tuple(rows)

    def _note_row(self, connection: sqlite3.Connection, context: MemoryAccessContext, note_id: str) -> sqlite3.Row:
        row = connection.execute(
            f"SELECT * FROM {self.store.table('memories')} WHERE workspace_id=? AND session_id=? AND thread_id=? AND id=? AND note_kind IS NOT NULL AND deleted_at IS NULL",
            (context.workspace_id, context.session_id, context.thread_id, note_id),
        ).fetchone()
        if row is None:
            raise MemoryNotFound("note not found or inaccessible")
        self.store.authenticator.verify_memory(bytes(row["state_mac"]), memory_state_fields(dict(row)))
        if (
            row["expires_at"] is not None
            and str(row["expires_at"]) <= (canonical_timestamp(datetime.now(timezone.utc)) or "")
            and not (bool(row["pinned"]) and str(row["retention_policy_id"] or "").startswith("default:"))
        ):
            raise MemoryNotFound("note not found or inaccessible")
        return row

    def _decode(self, row: sqlite3.Row) -> StructuredNote:
        metadata = self.store._metadata_from_row(row)
        payload = EncryptedPayload(bytes(row["ciphertext"]), bytes(row["nonce"]), int(row["key_version"]), str(row["algorithm"]))
        try:
            value = json.loads(self.store.cipher.decrypt_memory(payload, metadata).decode())
            return StructuredNote(
                note_id=metadata.id, workspace_id=metadata.workspace_id, session_id=metadata.session_id,
                thread_id=metadata.thread_id, kind=NoteKind(str(value["kind"])), content=str(value["content"]),
                status=metadata.lifecycle_status, verification=metadata.verification_status,
                confidence=int(value["confidence_millis"]) / 1000,
                importance=int(value["importance_millis"]) / 1000, revision=metadata.record_revision,
                source_refs=tuple(str(item) for item in value["source_refs"]),
                supersedes_id=str(value["supersedes_id"]) if value.get("supersedes_id") else None,
                created_by=str(value["created_by"]), classification=metadata.classification,
                created_at=metadata.created_at, scope=metadata.scope,
            )
        except (KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
            raise MemoryIntegrityError("structured note payload is malformed") from exc

    def _verify_note_provenance(
        self, connection: sqlite3.Connection, row: sqlite3.Row, note: StructuredNote,
    ) -> None:
        targets = []
        for relation in connection.execute(
            f"SELECT * FROM {self.store.table('memory_relations')} WHERE workspace_id=? AND source_memory_id=? AND relation_type='derived_from' AND deleted_at IS NULL",
            (row["workspace_id"], row["id"]),
        ):
            data = dict(relation)
            self.store.authenticator.verify_relation(bytes(relation["relation_mac"]), {
                "workspace_id": data["workspace_id"], "relation_id": data["relation_id"],
                "source_memory_id": data["source_memory_id"], "target_memory_id": data["target_memory_id"],
                "relation_type": data["relation_type"], "state_version": data["state_version"],
                "created_at": data["created_at"], "deleted_at": data.get("deleted_at"),
            })
            target = connection.execute(
                f"SELECT * FROM {self.store.table('memories')} WHERE workspace_id=? AND id=? AND deleted_at IS NULL",
                (row["workspace_id"], relation["target_memory_id"]),
            ).fetchone()
            if target is None:
                raise MemoryIntegrityError("note provenance source is unavailable")
            self.store.authenticator.verify_memory(bytes(target["state_mac"]), memory_state_fields(dict(target)))
            self.store.authenticate_memory_row(target)
            targets.append(str(relation["target_memory_id"]))
        if tuple(sorted(targets)) != tuple(sorted(note.source_refs)):
            raise MemoryIntegrityError("note provenance relations are incomplete")
        expected = provenance_digest(note.source_refs, MemoryRelationType.DERIVED_FROM, self.provenance_key)
        if bytes(row["provenance_digest"]) != expected:
            raise MemoryIntegrityError("note provenance digest is invalid")

    @staticmethod
    def _encode(note: StructuredNote) -> bytes:
        return json.dumps({
            "kind": note.kind.value, "content": note.content,
            "confidence_millis": round(note.confidence * 1000),
            "importance_millis": round(note.importance * 1000),
            "source_refs": list(note.source_refs), "supersedes_id": note.supersedes_id,
            "created_by": note.created_by,
        }, ensure_ascii=False, separators=(",", ":")).encode()

    def _relation(
        self, connection: sqlite3.Connection, workspace_id: str, source_id: str,
        target_id: str, relation_type: MemoryRelationType,
    ) -> None:
        self.store.insert_relation(connection, {
            "relation_id": secrets.token_hex(32), "workspace_id": workspace_id,
            "source_memory_id": source_id, "target_memory_id": target_id,
            "relation_type": relation_type.value, "state_version": 1,
            "created_at": canonical_timestamp(datetime.now(timezone.utc)), "deleted_at": None,
        })

    def _set_status(self, connection: sqlite3.Connection, row: sqlite3.Row, status: NoteStatus) -> None:
        current = dict(row)
        current.update(lifecycle_status=status.value, state_version=int(row["state_version"]) + 1,
                       updated_at=canonical_timestamp(datetime.now(timezone.utc)))
        current["state_mac"] = self.store.authenticator.sign_memory(memory_state_fields(current))
        result = connection.execute(
            f"UPDATE {self.store.table('memories')} SET lifecycle_status=?,state_version=?,updated_at=?,state_mac=? WHERE id=? AND state_version=?",
            (current["lifecycle_status"], current["state_version"], current["updated_at"], current["state_mac"], row["id"], row["state_version"]),
        )
        if result.rowcount != 1:
            raise MemoryLifecycleConflict("NOTE_CAS_CONFLICT")

    @staticmethod
    def _memory_type(kind: NoteKind) -> MemoryType:
        if kind is NoteKind.FINDING:
            return MemoryType.SECURITY_FINDING
        if kind is NoteKind.FACT:
            return MemoryType.PROJECT_FACT
        return MemoryType.USER_NOTE
