from __future__ import annotations

import json
import hmac
import hashlib
import re
import secrets
import sqlite3
import uuid
from dataclasses import replace
from datetime import datetime, timezone
from typing import Sequence

from .canonical import canonical_timestamp
from .classifier import MemorySafetyEvaluator
from .errors import (
    MemoryAccessDenied, MemoryConfirmationRequired, MemoryIntegrityError,
    MemoryLifecycleConflict, MemoryNotFound, MemoryPolicyDenied,
)
from .models import (
    IndexStatus, MemoryAccessContext, MemoryAction, MemoryCandidate, MemoryClassification,
    MemoryMetadata, MemoryRelationType, MemoryScope, MemorySource, MemoryType, NoteKind,
    NoteStatus, StructuredNote, VerificationStatus,
)
from .notes import NotesService, highest_classification
from .promotion import PromotionConfirmation, PromotionPreview
from .provenance import provenance_digest
from .store_v2 import SQLiteV2Store, memory_state_fields
from .thread_run_store import ThreadRunStore


class LongTermMemoryService:
    """Explicit, CAS-protected Note lifecycle and copy-on-promote workflow."""

    def __init__(
        self, store: SQLiteV2Store, lifecycle_store: ThreadRunStore, *,
        provenance_key: bytes, promotion_key: bytes, index: object | None = None,
        evaluator: MemorySafetyEvaluator | None = None,
    ) -> None:
        self.store = store
        self.lifecycle_store = lifecycle_store
        self.provenance_key = provenance_key
        self.confirmation = PromotionConfirmation(promotion_key)
        self.index = index
        self.evaluator = evaluator or MemorySafetyEvaluator()
        self.notes = NotesService(store, lifecycle_store, provenance_key=provenance_key, evaluator=self.evaluator)

    def add_note(
        self, context: MemoryAccessContext, draft: str, scope: MemoryScope, kind: NoteKind,
    ) -> StructuredNote:
        if scope is not MemoryScope.THREAD:
            raise MemoryConfirmationRequired("NOTE_BROADER_SCOPE_REQUIRES_PROMOTION")
        candidate = self.notes.add_candidate(context, kind=kind, content=draft, created_by="user")
        return self.confirm_note(context, candidate.note_id, candidate.revision)

    def get_note(self, context: MemoryAccessContext, note_id: str) -> StructuredNote:
        with self.store.connection() as connection:
            row = self._authorized_note_row(connection, context, note_id)
            note = self.notes._decode(row)
            self._verify_provenance(connection, row, note)
            return note

    def list_notes(
        self, context: MemoryAccessContext, *, scope: MemoryScope | None = None,
        statuses: Sequence[NoteStatus] = (NoteStatus.ACTIVE,),
    ) -> tuple[StructuredNote, ...]:
        with self.store.connection() as connection:
            clauses = ["workspace_id=?", "note_kind IS NOT NULL", "deleted_at IS NULL"]
            params: list[object] = [context.workspace_id]
            clauses.append("(expires_at IS NULL OR expires_at>? OR (pinned=1 AND retention_policy_id LIKE 'default:%'))")
            params.append(canonical_timestamp(datetime.now(timezone.utc)))
            if scope is not None:
                clauses.append("scope=?")
                params.append(scope.value)
            if statuses:
                clauses.append("lifecycle_status IN (" + ",".join("?" for _ in statuses) + ")")
                params.extend(status.value for status in statuses)
            result = []
            for row in connection.execute(
                f"SELECT * FROM {self.store.table('memories')} WHERE " + " AND ".join(clauses) + " ORDER BY created_at,id",
                params,
            ):
                try:
                    self._authorize_row(context, row)
                    note = self.notes._decode(row)
                    self._verify_provenance(connection, row, note)
                    result.append(note)
                except (MemoryAccessDenied, MemoryIntegrityError):
                    continue
            return tuple(result)

    def confirm_note(self, context: MemoryAccessContext, note_id: str, expected_version: int) -> StructuredNote:
        with self.store.connection(immediate=True) as connection:
            row = self._authorized_note_row(connection, context, note_id)
            if int(row["record_revision"]) != expected_version:
                raise MemoryLifecycleConflict("NOTE_EXPECTED_VERSION_MISMATCH")
            if row["lifecycle_status"] == NoteStatus.ACTIVE.value and row["verification_status"] == VerificationStatus.USER_CONFIRMED.value:
                return self.notes._decode(row)
            if row["lifecycle_status"] != NoteStatus.CANDIDATE.value:
                raise MemoryLifecycleConflict("NOTE_CONFIRM_STATE_INVALID")
            self._update_state(
                connection, row, lifecycle_status=NoteStatus.ACTIVE,
                verification_status=VerificationStatus.USER_CONFIRMED,
            )
            for relation in connection.execute(
                f"SELECT * FROM {self.store.table('memory_relations')} WHERE workspace_id=? AND source_memory_id=? AND relation_type='supersedes' AND deleted_at IS NULL",
                (context.workspace_id, note_id),
            ):
                relation_data = dict(relation)
                self.store.authenticator.verify_relation(bytes(relation["relation_mac"]), {
                    "workspace_id": relation_data["workspace_id"], "relation_id": relation_data["relation_id"],
                    "source_memory_id": relation_data["source_memory_id"], "target_memory_id": relation_data["target_memory_id"],
                    "relation_type": relation_data["relation_type"], "state_version": relation_data["state_version"],
                    "created_at": relation_data["created_at"], "deleted_at": relation_data.get("deleted_at"),
                })
                target = self._authorized_note_row(connection, context, str(relation["target_memory_id"]))
                if target["lifecycle_status"] in {NoteStatus.ACTIVE.value, NoteStatus.DISPUTED.value}:
                    self.notes._set_status(connection, target, NoteStatus.SUPERSEDED)
            self._audit(connection, "note_confirm", "success", context.workspace_id, note_id, "NOTE_USER_CONFIRMED")
            updated = self._authorized_note_row(connection, context, note_id)
            return self.notes._decode(updated)

    def revise_note(
        self, context: MemoryAccessContext, note_id: str, replacement: str, expected_version: int,
    ) -> StructuredNote:
        old = self.get_note(context, note_id)
        if old.revision != expected_version:
            raise MemoryLifecycleConflict("NOTE_EXPECTED_VERSION_MISMATCH")
        if old.status not in {NoteStatus.CANDIDATE, NoteStatus.ACTIVE, NoteStatus.DISPUTED}:
            raise MemoryLifecycleConflict("NOTE_REVISE_STATE_INVALID")
        if old.status is NoteStatus.CANDIDATE:
            return self.notes.add_candidate(
                context, kind=old.kind, content=replacement, source_refs=old.source_refs,
                created_by="user", supersedes_id=old.note_id,
            )
        candidate = self.notes.add_candidate(
            context, kind=old.kind, content=replacement, source_refs=old.source_refs,
            created_by="user", supersedes_id=old.note_id,
        )
        return self.confirm_note(context, candidate.note_id, candidate.revision)

    def retract_note(
        self, context: MemoryAccessContext, note_id: str, reason_code: str, expected_version: int,
    ) -> StructuredNote:
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", reason_code):
            raise MemoryLifecycleConflict("NOTE_REASON_CODE_INVALID")
        with self.store.connection(immediate=True) as connection:
            row = self._authorized_note_row(connection, context, note_id)
            if int(row["record_revision"]) != expected_version:
                raise MemoryLifecycleConflict("NOTE_EXPECTED_VERSION_MISMATCH")
            if row["lifecycle_status"] == NoteStatus.RETRACTED.value:
                return self.notes._decode(row)
            if row["lifecycle_status"] not in {NoteStatus.CANDIDATE.value, NoteStatus.ACTIVE.value, NoteStatus.DISPUTED.value}:
                raise MemoryLifecycleConflict("NOTE_RETRACT_STATE_INVALID")
            self._update_state(connection, row, lifecycle_status=NoteStatus.RETRACTED)
            self._audit(connection, "note_retract", "success", context.workspace_id, note_id, reason_code)
            return self.notes._decode(self._authorized_note_row(connection, context, note_id))

    def preview_promotion(
        self, context: MemoryAccessContext, note_id: str, target_scope: MemoryScope,
        *, purpose: str = "promotion",
    ) -> PromotionPreview:
        note = self.get_note(context, note_id)
        if note.status is not NoteStatus.ACTIVE or note.verification is not VerificationStatus.USER_CONFIRMED:
            raise MemoryLifecycleConflict("PROMOTION_SOURCE_NOT_CONFIRMED")
        self._validate_promotion(note.scope, target_scope)
        return self.confirmation.issue(
            workspace_id=context.workspace_id, note_id=note.note_id, revision=note.revision,
            target_scope=target_scope, classification=note.classification, purpose=purpose,
        )

    def preview_independent_retention(
        self, context: MemoryAccessContext, note_id: str,
    ) -> PromotionPreview:
        return self.preview_promotion(context, note_id, MemoryScope.WORKSPACE, purpose="independent_retention")

    def promote_note(
        self, context: MemoryAccessContext, note_id: str, target_scope: MemoryScope,
        confirmation_token: str, *, purpose: str = "promotion",
    ) -> StructuredNote:
        source = self.get_note(context, note_id)
        self._validate_promotion(source.scope, target_scope)
        receipt_hash = self.confirmation.verify(
            confirmation_token, workspace_id=context.workspace_id, note_id=note_id,
            revision=source.revision, target_scope=target_scope,
            classification=source.classification, purpose=purpose,
        )
        with self.store.connection(immediate=True) as connection:
            row = self._authorized_note_row(connection, context, note_id)
            if int(row["record_revision"]) != source.revision or row["lifecycle_status"] != NoteStatus.ACTIVE.value:
                raise MemoryLifecycleConflict("PROMOTION_SOURCE_CHANGED")
            existing = self._existing_promotion(connection, context.workspace_id, note_id, target_scope)
            if existing is not None:
                self.store.authenticate_memory_row(existing)
                note = self.notes._decode(existing)
                self._verify_provenance(connection, existing, note)
                if note.status is NoteStatus.ACTIVE:
                    return note
                raise MemoryLifecycleConflict("PROMOTION_TOKEN_ALREADY_CONSUMED")
            target_id = secrets.token_hex(32)
            now = datetime.now(timezone.utc)
            session_id = context.session_id if target_scope is MemoryScope.SESSION else None
            metadata = MemoryMetadata(
                id=target_id, workspace_id=context.workspace_id, session_id=session_id,
                scope=target_scope, memory_type=self.notes._memory_type(source.kind),
                classification=source.classification, source_type="note_promotion",
                policy_action=MemoryAction.ALLOW, policy_reason_codes=("NOTE_PROMOTION_CONFIRMED",),
                index_status=(
                    IndexStatus.PENDING_INDEX
                    if target_scope is MemoryScope.WORKSPACE
                    and source.classification is not MemoryClassification.SECRET
                    and self.index is not None
                    else IndexStatus.NOT_INDEXED
                ),
                created_at=now, schema_version=2, record_revision=1,
                lifecycle_status=NoteStatus.ACTIVE, verification_status=VerificationStatus.USER_CONFIRMED,
                note_kind=source.kind.value,
                provenance_digest=provenance_digest((source.note_id,), MemoryRelationType.PROMOTED_FROM, self.provenance_key),
                updated_at=now,
            )
            promoted = StructuredNote(
                target_id, context.workspace_id, session_id, None, source.kind, source.content,
                NoteStatus.ACTIVE, VerificationStatus.USER_CONFIRMED, source.confidence,
                source.importance, 1, (source.note_id,), None, created_by="user",
                classification=source.classification, created_at=now, scope=target_scope,
            )
            payload = json.loads(self.notes._encode(promoted).decode())
            payload["confirmation_receipt_hash"] = receipt_hash
            self.store.insert_memory(connection, metadata, json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode())
            self.notes._relation(connection, context.workspace_id, target_id, source.note_id, MemoryRelationType.PROMOTED_FROM)
            self._audit(connection, "note_promote", "success", context.workspace_id, target_id, "NOTE_PROMOTION_CONFIRMED")
        if metadata.index_status is IndexStatus.PENDING_INDEX:
            self._index_workspace(metadata, promoted.content)
        return self.get_note(context, target_id)

    def retry_index(self, context: MemoryAccessContext, note_id: str) -> StructuredNote:
        if self.index is None:
            raise MemoryPolicyDenied("NOTE_INDEX_UNAVAILABLE")
        with self.store.connection() as connection:
            row = self._authorized_note_row(connection, context, note_id)
            note = self.notes._decode(row)
            metadata = self.store._metadata_from_row(row)
        if (
            note.scope is not MemoryScope.WORKSPACE
            or note.status is not NoteStatus.ACTIVE
            or note.verification is not VerificationStatus.USER_CONFIRMED
            or note.classification is MemoryClassification.SECRET
        ):
            raise MemoryPolicyDenied("NOTE_NOT_INDEXABLE")
        if metadata.index_status is IndexStatus.INDEXED:
            return note
        if metadata.index_status not in {IndexStatus.PENDING_INDEX, IndexStatus.INDEX_FAILED}:
            raise MemoryPolicyDenied("NOTE_INDEX_STATE_INVALID")
        self._index_workspace(metadata, note.content)
        return self.get_note(context, note_id)

    def reconcile_index(self, context: MemoryAccessContext, *, dry_run: bool = False) -> tuple[str, ...]:
        with self.store.connection() as connection:
            ids = tuple(str(row[0]) for row in connection.execute(
                f"SELECT id FROM {self.store.table('memories')} WHERE workspace_id=? AND scope='workspace' AND lifecycle_status='active' AND verification_status='user_confirmed' AND classification!='secret' AND deleted_at IS NULL AND index_status IN ('pending_index','index_failed') ORDER BY id",
                (context.workspace_id,),
            ))
        if dry_run:
            return ids
        completed = []
        for note_id in ids:
            self.retry_index(context, note_id)
            completed.append(note_id)
        return tuple(completed)

    def _authorized_note_row(self, connection: sqlite3.Connection, context: MemoryAccessContext, note_id: str) -> sqlite3.Row:
        row = connection.execute(
            f"SELECT * FROM {self.store.table('memories')} WHERE workspace_id=? AND id=? AND note_kind IS NOT NULL AND deleted_at IS NULL",
            (context.workspace_id, note_id),
        ).fetchone()
        if row is None:
            raise MemoryNotFound("note not found or inaccessible")
        self._authorize_row(context, row)
        self.store.authenticate_memory_row(row)
        if (
            row["expires_at"] is not None
            and str(row["expires_at"]) <= (canonical_timestamp(datetime.now(timezone.utc)) or "")
            and not (bool(row["pinned"]) and str(row["retention_policy_id"] or "").startswith("default:"))
        ):
            raise MemoryNotFound("note not found or inaccessible")
        return row

    @staticmethod
    def _authorize_row(context: MemoryAccessContext, row: sqlite3.Row) -> None:
        scope = MemoryScope(str(row["scope"]))
        if scope is MemoryScope.SESSION and context.session_id != row["session_id"]:
            raise MemoryAccessDenied("note belongs to another session")
        if scope is MemoryScope.THREAD and (
            context.session_id != row["session_id"] or context.thread_id != row["thread_id"]
        ):
            raise MemoryAccessDenied("note belongs to another thread")

    def _update_state(
        self, connection: sqlite3.Connection, row: sqlite3.Row, *,
        lifecycle_status: NoteStatus, verification_status: VerificationStatus | None = None,
    ) -> None:
        current = dict(row)
        target_verification = verification_status or VerificationStatus(str(row["verification_status"]))
        payload = None
        if target_verification.value != row["verification_status"]:
            plaintext = self.store.authenticate_memory_row(row)
            metadata = replace(
                self.store._metadata_from_row(row), verification_status=target_verification,
                lifecycle_status=lifecycle_status, state_version=int(row["state_version"]) + 1,
                updated_at=datetime.now(timezone.utc),
            )
            payload = self.store.cipher.encrypt_memory(plaintext, metadata)
        current.update(
            lifecycle_status=lifecycle_status.value,
            verification_status=target_verification.value,
            state_version=int(row["state_version"]) + 1,
            updated_at=canonical_timestamp(datetime.now(timezone.utc)),
        )
        current["state_mac"] = self.store.authenticator.sign_memory(memory_state_fields(current))
        if payload is None:
            result = connection.execute(
                f"UPDATE {self.store.table('memories')} SET lifecycle_status=?,verification_status=?,state_version=?,updated_at=?,state_mac=? WHERE id=? AND state_version=?",
                (current["lifecycle_status"], current["verification_status"], current["state_version"], current["updated_at"], current["state_mac"], row["id"], row["state_version"]),
            )
        else:
            current.update(key_version=payload.key_version, algorithm=payload.algorithm, ciphertext=payload.ciphertext, nonce=payload.nonce)
            result = connection.execute(
                f"UPDATE {self.store.table('memories')} SET lifecycle_status=?,verification_status=?,state_version=?,updated_at=?,state_mac=?,key_version=?,algorithm=?,ciphertext=?,nonce=? WHERE id=? AND state_version=?",
                (current["lifecycle_status"], current["verification_status"], current["state_version"], current["updated_at"], current["state_mac"],
                 current["key_version"], current["algorithm"], current["ciphertext"], current["nonce"], row["id"], row["state_version"]),
            )
        if result.rowcount != 1:
            raise MemoryLifecycleConflict("NOTE_CAS_CONFLICT")

    def _existing_promotion(
        self, connection: sqlite3.Connection, workspace_id: str, source_id: str, target_scope: MemoryScope,
    ) -> sqlite3.Row | None:
        return connection.execute(
            f"SELECT m.* FROM {self.store.table('memory_relations')} r JOIN {self.store.table('memories')} m ON m.workspace_id=r.workspace_id AND m.id=r.source_memory_id "
            "WHERE r.workspace_id=? AND r.target_memory_id=? AND r.relation_type='promoted_from' AND r.deleted_at IS NULL AND m.scope=? ORDER BY m.created_at LIMIT 1",
            (workspace_id, source_id, target_scope.value),
        ).fetchone()

    def _verify_provenance(
        self, connection: sqlite3.Connection, row: sqlite3.Row, note: StructuredNote,
    ) -> None:
        relation_type = (
            MemoryRelationType.PROMOTED_FROM
            if row["source_type"] == "note_promotion"
            else MemoryRelationType.DERIVED_FROM
        )
        targets = []
        for relation in connection.execute(
            f"SELECT * FROM {self.store.table('memory_relations')} WHERE workspace_id=? AND source_memory_id=? AND relation_type=? AND deleted_at IS NULL",
            (row["workspace_id"], row["id"], relation_type.value),
        ):
            data = dict(relation)
            self.store.authenticator.verify_relation(bytes(relation["relation_mac"]), {
                "workspace_id": data["workspace_id"], "relation_id": data["relation_id"],
                "source_memory_id": data["source_memory_id"], "target_memory_id": data["target_memory_id"],
                "relation_type": data["relation_type"], "state_version": data["state_version"],
                "created_at": data["created_at"], "deleted_at": data.get("deleted_at"),
            })
            source = connection.execute(
                f"SELECT * FROM {self.store.table('memories')} WHERE workspace_id=? AND id=? AND deleted_at IS NULL",
                (row["workspace_id"], relation["target_memory_id"]),
            ).fetchone()
            if source is None:
                raise MemoryIntegrityError("note provenance source is unavailable")
            self.store.authenticate_memory_row(source)
            targets.append(str(relation["target_memory_id"]))
        if tuple(sorted(targets)) != tuple(sorted(note.source_refs)):
            raise MemoryIntegrityError("note provenance relations are incomplete")
        expected = provenance_digest(note.source_refs, relation_type, self.provenance_key)
        if not hmac.compare_digest(bytes(row["provenance_digest"]), expected):
            raise MemoryIntegrityError("note provenance digest is invalid")

    @staticmethod
    def _validate_promotion(source: MemoryScope, target: MemoryScope) -> None:
        order = {MemoryScope.THREAD: 0, MemoryScope.SESSION: 1, MemoryScope.WORKSPACE: 2}
        if order[target] <= order[source]:
            raise MemoryLifecycleConflict("PROMOTION_SCOPE_NOT_BROADER")

    def _index_workspace(self, metadata: MemoryMetadata, content: str) -> None:
        try:
            self.index.index(metadata, content)
            status = IndexStatus.INDEXED
        except Exception:
            status = IndexStatus.INDEX_FAILED
        with self.store.connection(immediate=True) as connection:
            row = connection.execute(f"SELECT * FROM {self.store.table('memories')} WHERE id=?", (metadata.id,)).fetchone()
            current = dict(row)
            current.update(index_status=status.value, state_version=int(row["state_version"]) + 1,
                           updated_at=canonical_timestamp(datetime.now(timezone.utc)))
            current["state_mac"] = self.store.authenticator.sign_memory(memory_state_fields(current))
            connection.execute(
                f"UPDATE {self.store.table('memories')} SET index_status=?,state_version=?,updated_at=?,state_mac=? WHERE id=? AND state_version=?",
                (current["index_status"], current["state_version"], current["updated_at"], current["state_mac"], metadata.id, row["state_version"]),
            )
            self._audit(
                connection, "note_index", "success" if status is IndexStatus.INDEXED else "failed",
                metadata.workspace_id, metadata.id,
                "NOTE_INDEXED" if status is IndexStatus.INDEXED else "NOTE_INDEX_FAILED",
            )

    @staticmethod
    def _audit(
        connection: sqlite3.Connection, action: str, outcome: str, workspace_id: str,
        memory_id: str | None, reason_code: str,
    ) -> None:
        connection.execute(
            "INSERT INTO memory_audit(event_id,action,outcome,workspace_id,memory_id_hash,reason_code,created_at) VALUES(?,?,?,?,?,?,?)",
            (
                str(uuid.uuid4()), action, outcome, workspace_id,
                hashlib.sha256(memory_id.encode()).hexdigest() if memory_id else None,
                reason_code, canonical_timestamp(datetime.now(timezone.utc)),
            ),
        )
