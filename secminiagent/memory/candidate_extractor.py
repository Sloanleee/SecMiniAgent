from __future__ import annotations

import sqlite3

from .dedup import note_fingerprint
from .errors import MemoryLifecycleConflict, MemoryPolicyDenied
from .long_term_memory import LongTermMemoryService
from .models import (
    CandidateProposal, MemoryAccessContext, MemoryRelationType, NoteStatus, StructuredNote,
    VerificationStatus,
)


class ControlledCandidateService:
    """Persist validated proposals as model-inferred candidates, never confirmed facts."""

    def __init__(self, long_term: LongTermMemoryService, *, dedup_key: bytes) -> None:
        self.long_term = long_term
        self.store = long_term.store
        self.dedup_key = dedup_key

    def submit(self, context: MemoryAccessContext, proposal: CandidateProposal) -> StructuredNote:
        fingerprint = note_fingerprint(self.dedup_key, proposal.kind, proposal.content)
        record_revision = 1
        with self.store.connection(immediate=True) as connection:
            self._verify_sources(connection, context, proposal.source_refs)
            duplicate = connection.execute(
                f"SELECT * FROM {self.store.table('memories')} WHERE workspace_id=? AND session_id=? AND thread_id=? AND dedup_fingerprint=? AND deleted_at IS NULL ORDER BY created_at LIMIT 1",
                (context.workspace_id, context.session_id, context.thread_id, fingerprint),
            ).fetchone()
            if duplicate is not None:
                self.store.authenticate_memory_row(duplicate)
                for source_id in proposal.source_refs:
                    exists = connection.execute(
                        f"SELECT 1 FROM {self.store.table('memory_relations')} WHERE workspace_id=? AND source_memory_id=? AND target_memory_id=? AND relation_type='supports' AND deleted_at IS NULL",
                        (context.workspace_id, duplicate["id"], source_id),
                    ).fetchone()
                    if exists is None:
                        self.long_term.notes._relation(
                            connection, context.workspace_id, str(duplicate["id"]),
                            source_id, MemoryRelationType.SUPPORTS,
                        )
                return self.long_term.notes._decode(duplicate)
            if proposal.related_note_id is not None:
                related = self.long_term._authorized_note_row(connection, context, proposal.related_note_id)
                if related["lifecycle_status"] != NoteStatus.ACTIVE.value:
                    raise MemoryLifecycleConflict("CANDIDATE_RELATED_NOTE_NOT_ACTIVE")
                if proposal.relationship == "revision":
                    record_revision = int(related["record_revision"]) + 1
        candidate = self.long_term.notes.add_candidate(
            context, kind=proposal.kind, content=proposal.content,
            source_refs=proposal.source_refs, created_by="model",
            confidence=proposal.confidence, importance=proposal.importance,
            dedup_fingerprint=fingerprint, record_revision=record_revision,
        )
        if proposal.related_note_id is not None:
            with self.store.connection(immediate=True) as connection:
                relation_type = (
                    MemoryRelationType.SUPERSEDES
                    if proposal.relationship == "revision" else MemoryRelationType.CONFLICTS_WITH
                )
                self.long_term.notes._relation(
                    connection, context.workspace_id, candidate.note_id,
                    proposal.related_note_id, relation_type,
                )
                if relation_type is MemoryRelationType.CONFLICTS_WITH:
                    self.long_term.notes._relation(
                        connection, context.workspace_id, proposal.related_note_id,
                        candidate.note_id, relation_type,
                    )
        return candidate

    def reject(self, context: MemoryAccessContext, note_id: str, expected_version: int) -> StructuredNote:
        with self.store.connection(immediate=True) as connection:
            row = self.long_term._authorized_note_row(connection, context, note_id)
            if int(row["record_revision"]) != expected_version:
                raise MemoryLifecycleConflict("NOTE_EXPECTED_VERSION_MISMATCH")
            if row["lifecycle_status"] == NoteStatus.REJECTED.value:
                return self.long_term.notes._decode(row)
            if row["lifecycle_status"] != NoteStatus.CANDIDATE.value:
                raise MemoryLifecycleConflict("CANDIDATE_REJECT_STATE_INVALID")
            self.long_term._update_state(connection, row, lifecycle_status=NoteStatus.REJECTED)
            self.long_term._audit(connection, "candidate_reject", "success", context.workspace_id, note_id, "CANDIDATE_USER_REJECTED")
            return self.long_term.notes._decode(self.long_term._authorized_note_row(connection, context, note_id))

    def _verify_sources(
        self, connection: sqlite3.Connection, context: MemoryAccessContext, source_refs: tuple[str, ...],
    ) -> None:
        rows = self.long_term.notes._source_rows(connection, context, source_refs)
        for row in rows:
            if row["run_id"] is not None:
                run = connection.execute(
                    f"SELECT * FROM {self.store.table('runs')} WHERE workspace_id=? AND session_id=? AND thread_id=? AND run_id=? AND deleted_at IS NULL",
                    (context.workspace_id, context.session_id, context.thread_id, row["run_id"]),
                ).fetchone()
                if run is None or run["status"] != "completed":
                    raise MemoryPolicyDenied("AUTO_MEMORY_SOURCE_RUN_NOT_COMPLETED")
                self.long_term.lifecycle_store._verified_run(run)
            elif row["verification_status"] not in {
                VerificationStatus.USER_CONFIRMED.value, VerificationStatus.TOOL_VERIFIED.value,
            }:
                raise MemoryPolicyDenied("AUTO_MEMORY_SOURCE_NOT_CONFIRMED")
