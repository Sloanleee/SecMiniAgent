from __future__ import annotations

import json
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping, Protocol, Sequence

from ._ports import EncryptedPayload
from .canonical import canonical_timestamp
from .classifier import MemorySafetyEvaluator
from .errors import MemoryIntegrityError, MemoryLifecycleConflict, MemoryMigrationConflict, MemoryNotFound, MemoryPolicyDenied
from .models import (
    IndexStatus, MemoryAccessContext, MemoryAction, MemoryCandidate, MemoryClassification,
    MemoryMetadata, MemoryRelationType, MemoryScope, MemorySource, MemoryType, MessageEnvelope,
    NoteStatus, ThreadSummary, VerificationStatus,
)
from .notes import NotesService, highest_classification
from .provenance import provenance_digest
from .store_v2 import SQLiteV2Store, memory_state_fields, thread_state_fields
from .thread_run_store import ThreadRunStore
from .transcript_v2 import ThreadTranscriptService


class SummaryGenerator(Protocol):
    def summarize(
        self, previous: ThreadSummary | None, messages: Sequence[MessageEnvelope],
    ) -> Mapping[str, object]: ...


@dataclass(frozen=True, slots=True)
class SummaryTriggerPolicy:
    max_unsummarized_messages: int = 50
    max_unsummarized_chars: int = 40_000

    def __post_init__(self) -> None:
        if not 1 <= self.max_unsummarized_messages <= 10_000:
            raise ValueError("summary message threshold is out of range")
        if not 1_000 <= self.max_unsummarized_chars <= 10_000_000:
            raise ValueError("summary character threshold is out of range")


class DeterministicLocalSummarizer:
    """Conservative local baseline: preserves excerpts without declaring verified facts."""

    def summarize(
        self, previous: ThreadSummary | None, messages: Sequence[MessageEnvelope],
    ) -> Mapping[str, object]:
        questions = []
        completed = []
        for item in messages:
            content = item.message.get("content")
            if not isinstance(content, str) or not content:
                continue
            excerpt = content[:500]
            if item.role == "user" and content.rstrip().endswith(("?", "？")):
                questions.append(excerpt)
            elif item.role == "assistant":
                completed.append(excerpt)
        return {
            "goal": previous.goal if previous else "",
            "verified_facts": list(previous.verified_facts) if previous else [],
            "decisions": list(previous.decisions) if previous else [],
            "completed_actions": [*(previous.completed_actions if previous else ()), *completed],
            "pending_actions": list(previous.pending_actions) if previous else [],
            "findings": list(previous.findings) if previous else [],
            "entities": list(previous.entities) if previous else [],
            "open_questions": [*(previous.open_questions if previous else ()), *questions],
        }


class RollingSummaryService:
    def __init__(
        self, store: SQLiteV2Store, lifecycle_store: ThreadRunStore,
        transcript: ThreadTranscriptService, *, provenance_key: bytes,
        generator: SummaryGenerator | None = None, evaluator: MemorySafetyEvaluator | None = None,
        trigger_policy: SummaryTriggerPolicy | None = None,
    ) -> None:
        self.store = store
        self.lifecycle_store = lifecycle_store
        self.transcript = transcript
        self.provenance_key = provenance_key
        self.generator = generator or DeterministicLocalSummarizer()
        self.evaluator = evaluator or MemorySafetyEvaluator()
        self.trigger_policy = trigger_policy or SummaryTriggerPolicy()
        self._notes = NotesService(store, lifecycle_store, provenance_key=provenance_key)

    def should_build(self, context: MemoryAccessContext) -> bool:
        previous = self.active(context)
        watermark = previous.covered_through_sequence if previous else 0
        messages = self._complete_messages_after(self.transcript.resume(context), watermark)
        return (
            len(messages) >= self.trigger_policy.max_unsummarized_messages
            or sum(len(json.dumps(item.message, ensure_ascii=False, default=str)) for item in messages)
            >= self.trigger_policy.max_unsummarized_chars
        )

    def maybe_build(self, context: MemoryAccessContext) -> ThreadSummary | None:
        return self.build(context) if self.should_build(context) else None

    def active(self, context: MemoryAccessContext) -> ThreadSummary | None:
        if context.session_id is None or context.thread_id is None:
            return None
        with self.store.connection() as connection:
            self.lifecycle_store.verify_ancestry(connection, context.workspace_id, context.session_id, context.thread_id)
            row = self._active_row(connection, context)
            if row is None:
                return None
            summary = self._decode(row)
            self._verify_summary_sources(connection, row, summary)
            return summary

    def build(self, context: MemoryAccessContext) -> ThreadSummary:
        if context.session_id is None or context.thread_id is None:
            raise MemoryPolicyDenied("SUMMARY_THREAD_CONTEXT_REQUIRED")
        with self.store.connection() as connection:
            thread, _ = self.lifecycle_store.verify_ancestry(
                connection, context.workspace_id, context.session_id, context.thread_id,
            )
            captured_thread_state = int(thread["state_version"])
            old_row = self._active_row(connection, context)
            previous = self._decode(old_row) if old_row is not None else None
            if old_row is not None and previous is not None:
                self._verify_summary_sources(connection, old_row, previous)
            captured_old_state = int(old_row["state_version"]) if old_row is not None else None
        all_messages = self.transcript.resume(context)
        watermark = previous.covered_through_sequence if previous else 0
        selected = self._complete_messages_after(all_messages, watermark)
        if not selected:
            raise MemoryLifecycleConflict("SUMMARY_NO_NEW_COMPLETE_MESSAGES")
        draft = self.generator.summarize(previous, selected)
        structured = self._validate_draft(draft)
        if structured["verified_facts"] and not any(
            item.verification_status in {VerificationStatus.TOOL_VERIFIED, VerificationStatus.USER_CONFIRMED}
            for item in selected
        ):
            raise MemoryPolicyDenied("SUMMARY_UNVERIFIED_FACT_CLAIM")
        source_ids = tuple(
            [*(previous.source_memory_ids if previous else ()), *(item.message_id for item in selected)]
        )
        # Preserve unique order; provenance must describe the complete effective source set.
        source_ids = tuple(dict.fromkeys(source_ids))
        source_classification = highest_classification([
            *(item.classification for item in selected),
            *( (previous.classification,) if previous else () ),
        ])
        candidate_content = json.dumps(structured, ensure_ascii=False, separators=(",", ":"))
        evaluation = self.evaluator.evaluate(MemoryCandidate(
            MemoryType.THREAD_SUMMARY, candidate_content, MemoryScope.THREAD,
            MemorySource("rolling_summary", user_confirmed=False),
        ), context)
        if evaluation.persistable_candidate is None:
            raise MemoryPolicyDenied("SUMMARY_POLICY_REJECTED")
        try:
            structured = self._validate_draft(json.loads(evaluation.persistable_candidate.content))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise MemoryPolicyDenied("SUMMARY_POLICY_OUTPUT_INVALID") from exc
        classification = highest_classification((source_classification, evaluation.decision.classification))
        now = datetime.now(timezone.utc)
        summary_id = secrets.token_hex(32)
        version = (previous.version + 1) if previous else 1
        summary = ThreadSummary(
            summary_id, context.workspace_id, context.session_id, context.thread_id, version,
            goal=str(structured["goal"]),
            verified_facts=tuple(structured["verified_facts"]), decisions=tuple(structured["decisions"]),
            completed_actions=tuple(structured["completed_actions"]), pending_actions=tuple(structured["pending_actions"]),
            findings=tuple(structured["findings"]), entities=tuple(structured["entities"]),
            open_questions=tuple(structured["open_questions"]), source_memory_ids=source_ids,
            covered_through_sequence=selected[-1].thread_sequence,
            generation_method=type(self.generator).__name__, classification=classification,
            status=NoteStatus.ACTIVE, verification=VerificationStatus.MODEL_INFERRED, created_at=now,
        )
        self._activate(
            context, summary, old_row_id=previous.summary_id if previous else None,
            captured_old_state=captured_old_state, captured_thread_state=captured_thread_state,
            selected=selected, policy_action=evaluation.decision.action,
            reason_codes=tuple(evaluation.decision.reason_codes),
        )
        return summary

    def _activate(
        self, context: MemoryAccessContext, summary: ThreadSummary, *, old_row_id: str | None,
        captured_old_state: int | None, captured_thread_state: int,
        selected: Sequence[MessageEnvelope], policy_action: MemoryAction,
        reason_codes: tuple[str, ...],
    ) -> None:
        with self.store.connection(immediate=True) as connection:
            thread, _ = self.lifecycle_store.verify_ancestry(
                connection, context.workspace_id, context.session_id or "", context.thread_id or "",
            )
            if int(thread["state_version"]) != captured_thread_state:
                raise MemoryMigrationConflict("SUMMARY_SOURCE_CHANGED")
            current_old = self._active_row(connection, context)
            if old_row_id is None:
                if current_old is not None:
                    raise MemoryLifecycleConflict("SUMMARY_CAS_CONFLICT")
            elif current_old is None or current_old["id"] != old_row_id or int(current_old["state_version"]) != captured_old_state:
                raise MemoryLifecycleConflict("SUMMARY_CAS_CONFLICT")
            for item in selected:
                row = connection.execute(
                    f"SELECT * FROM {self.store.table('memories')} WHERE workspace_id=? AND id=? AND deleted_at IS NULL",
                    (context.workspace_id, item.message_id),
                ).fetchone()
                if row is None or int(row["thread_sequence"]) != item.thread_sequence:
                    raise MemoryMigrationConflict("SUMMARY_SOURCE_CHANGED")
                self.store.authenticator.verify_memory(bytes(row["state_mac"]), memory_state_fields(dict(row)))
                self.store.authenticate_memory_row(row)
            sequence = self.store.allocate_thread_sequence(
                connection, context.workspace_id, context.session_id or "", context.thread_id or "",
            )
            metadata = MemoryMetadata(
                id=summary.summary_id, workspace_id=context.workspace_id, session_id=context.session_id,
                scope=MemoryScope.THREAD, memory_type=MemoryType.THREAD_SUMMARY,
                classification=summary.classification, source_type="rolling_summary",
                policy_action=policy_action, policy_reason_codes=reason_codes,
                index_status=IndexStatus.NOT_INDEXED, created_at=summary.created_at or datetime.now(timezone.utc),
                schema_version=2, thread_id=context.thread_id, record_revision=summary.version,
                thread_sequence=sequence, lifecycle_status=NoteStatus.CANDIDATE,
                verification_status=summary.verification,
                provenance_digest=provenance_digest(summary.source_memory_ids, MemoryRelationType.SUMMARIZES, self.provenance_key),
                updated_at=summary.created_at,
            )
            self.store.insert_memory(connection, metadata, self._encode(summary))
            for source_id in summary.source_memory_ids:
                self._notes._relation(connection, context.workspace_id, summary.summary_id, source_id, MemoryRelationType.SUMMARIZES)
            new_row = connection.execute(
                f"SELECT * FROM {self.store.table('memories')} WHERE id=?", (summary.summary_id,),
            ).fetchone()
            if current_old is not None:
                self._notes._set_status(connection, current_old, NoteStatus.SUPERSEDED)
            self._notes._set_status(connection, new_row, NoteStatus.ACTIVE)

    def _active_row(self, connection: sqlite3.Connection, context: MemoryAccessContext) -> sqlite3.Row | None:
        row = connection.execute(
            f"SELECT * FROM {self.store.table('memories')} WHERE workspace_id=? AND session_id=? AND thread_id=? "
            "AND memory_type='thread_summary' AND lifecycle_status='active' AND deleted_at IS NULL",
            (context.workspace_id, context.session_id, context.thread_id),
        ).fetchone()
        if row is not None:
            self.store.authenticator.verify_memory(bytes(row["state_mac"]), memory_state_fields(dict(row)))
        return row

    def _decode(self, row: sqlite3.Row) -> ThreadSummary:
        metadata = self.store._metadata_from_row(row)
        payload = EncryptedPayload(bytes(row["ciphertext"]), bytes(row["nonce"]), int(row["key_version"]), str(row["algorithm"]))
        try:
            value = json.loads(self.store.cipher.decrypt_memory(payload, metadata).decode())
            structured = self._validate_draft(value)
            source_ids = tuple(str(item) for item in value["source_memory_ids"])
            return ThreadSummary(
                metadata.id, metadata.workspace_id, metadata.session_id or "", metadata.thread_id or "",
                metadata.record_revision, goal=str(structured["goal"]),
                verified_facts=tuple(structured["verified_facts"]), decisions=tuple(structured["decisions"]),
                completed_actions=tuple(structured["completed_actions"]), pending_actions=tuple(structured["pending_actions"]),
                findings=tuple(structured["findings"]), entities=tuple(structured["entities"]),
                open_questions=tuple(structured["open_questions"]), source_memory_ids=source_ids,
                covered_through_sequence=int(value["covered_through_sequence"]),
                generation_method=str(value["generation_method"]), classification=metadata.classification,
                status=metadata.lifecycle_status, verification=metadata.verification_status, created_at=metadata.created_at,
            )
        except (KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
            raise MemoryIntegrityError("thread summary payload is malformed") from exc

    def _verify_summary_sources(
        self, connection: sqlite3.Connection, row: sqlite3.Row, summary: ThreadSummary,
    ) -> None:
        targets = []
        for relation in connection.execute(
            f"SELECT * FROM {self.store.table('memory_relations')} WHERE workspace_id=? AND source_memory_id=? AND relation_type='summarizes' AND deleted_at IS NULL",
            (row["workspace_id"], row["id"]),
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
                raise MemoryIntegrityError("summary source is unavailable")
            self.store.authenticator.verify_memory(bytes(source["state_mac"]), memory_state_fields(dict(source)))
            self.store.authenticate_memory_row(source)
            targets.append(str(relation["target_memory_id"]))
        if tuple(sorted(targets)) != tuple(sorted(summary.source_memory_ids)):
            raise MemoryIntegrityError("summary provenance relations are incomplete")
        expected = provenance_digest(summary.source_memory_ids, MemoryRelationType.SUMMARIZES, self.provenance_key)
        if bytes(row["provenance_digest"]) != expected:
            raise MemoryIntegrityError("summary provenance digest is invalid")

    @staticmethod
    def _encode(summary: ThreadSummary) -> bytes:
        return json.dumps({
            "goal": summary.goal, "verified_facts": list(summary.verified_facts),
            "decisions": list(summary.decisions), "completed_actions": list(summary.completed_actions),
            "pending_actions": list(summary.pending_actions), "findings": list(summary.findings),
            "entities": list(summary.entities), "open_questions": list(summary.open_questions),
            "source_memory_ids": list(summary.source_memory_ids),
            "covered_through_sequence": summary.covered_through_sequence,
            "generation_method": summary.generation_method,
        }, ensure_ascii=False, separators=(",", ":")).encode()

    @staticmethod
    def _validate_draft(value: Mapping[str, object]) -> dict[str, object]:
        keys = (
            "verified_facts", "decisions", "completed_actions", "pending_actions",
            "findings", "entities", "open_questions",
        )
        if not isinstance(value, Mapping) or not isinstance(value.get("goal"), str):
            raise MemoryIntegrityError("summary draft structure is invalid")
        result: dict[str, object] = {"goal": value["goal"]}
        for key in keys:
            items = value.get(key)
            if not isinstance(items, (list, tuple)) or any(not isinstance(item, str) for item in items):
                raise MemoryIntegrityError("summary draft structure is invalid")
            result[key] = list(items)
        return result

    @staticmethod
    def _complete_messages_after(
        items: Sequence[MessageEnvelope], watermark: int,
    ) -> tuple[MessageEnvelope, ...]:
        candidates = [item for item in items if item.thread_sequence > watermark]
        selected: list[MessageEnvelope] = []
        index = 0
        while index < len(candidates):
            item = candidates[index]
            if not item.tool_call_ids:
                if item.tool_result_call_id:
                    raise MemoryIntegrityError("summary source has orphan tool result")
                selected.append(item)
                index += 1
                continue
            pending = set(item.tool_call_ids)
            group = [item]
            cursor = index + 1
            while cursor < len(candidates) and candidates[cursor].tool_result_call_id in pending:
                pending.remove(candidates[cursor].tool_result_call_id)
                group.append(candidates[cursor])
                cursor += 1
            if pending:
                break
            selected.extend(group)
            index = cursor
        return tuple(selected)
