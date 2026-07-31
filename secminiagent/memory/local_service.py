from __future__ import annotations

import json
import uuid
from dataclasses import replace
from datetime import datetime, timezone
from typing import Sequence

from .classifier import MemoryEvaluation, MemorySafetyEvaluator
from .crypto import build_memory_aad
from .errors import (
    MemoryAccessDenied,
    MemoryConfirmationRequired,
    MemoryNotFound,
    MemoryPolicyDenied,
    MemorySchemaUnsupported,
)
from .models import (
    IndexStatus,
    MemoryAccessContext,
    MemoryAction,
    MemoryCandidate,
    MemoryClassification,
    MemoryMetadata,
    MemoryQuery,
    MemoryRecord,
    MemoryScope,
)
from .redactor import MemoryRedactor
from .service import DeletionReceipt, MemoryService
from .store import SQLiteMemoryStore, hash_memory_id


LOCAL_PROVIDERS = {"local", "fake"}


class LocalMemoryService(MemoryService):
    """Concrete local service combining M1 policy with M2-M5 persistence."""

    def __init__(
        self,
        *,
        store: SQLiteMemoryStore,
        cipher: object,
        evaluator: MemorySafetyEvaluator | None = None,
        index: object | None = None,
    ) -> None:
        self.store = store
        self.cipher = cipher
        self.evaluator = evaluator or MemorySafetyEvaluator()
        self.index = index
        self.redactor = MemoryRedactor()

    def remember(self, candidate: MemoryCandidate, context: MemoryAccessContext) -> MemoryMetadata:
        evaluation = self.evaluator.evaluate(candidate, context)
        if evaluation.decision.action is MemoryAction.DENY:
            self._audit("remember", "denied", context, None, evaluation.decision.reason_codes[0])
            raise MemoryPolicyDenied(evaluation.decision.explanation)
        if evaluation.decision.action is MemoryAction.REQUIRE_CONFIRMATION:
            self._audit("remember", "confirmation_required", context, None, evaluation.decision.reason_codes[0])
            raise MemoryConfirmationRequired(evaluation.decision.explanation)
        approved = evaluation.persistable_candidate
        if approved is None:
            raise MemoryPolicyDenied("memory policy produced no persistable candidate")
        if approved.requested_scope is MemoryScope.THREAD:
            raise MemorySchemaUnsupported("thread memory writes require the v2 runtime")
        if approved.requested_scope is MemoryScope.SESSION and context.session_id is None:
            raise MemoryAccessDenied("session-scoped memory requires an active session")

        memory_id = str(uuid.uuid4())
        sequence = approved.attributes.get("_sequence_no")
        metadata = MemoryMetadata(
            id=memory_id,
            workspace_id=context.workspace_id,
            session_id=context.session_id if approved.requested_scope is MemoryScope.SESSION else None,
            scope=approved.requested_scope,
            memory_type=approved.memory_type,
            classification=evaluation.decision.classification,
            source_type=approved.source.source_type,
            policy_action=evaluation.decision.action,
            policy_reason_codes=evaluation.decision.reason_codes,
            index_status=(
                IndexStatus.PENDING_INDEX if self._index_text(approved, evaluation) is not None else IndexStatus.NOT_INDEXED
            ),
            sequence_no=int(sequence) if isinstance(sequence, int) else None,
            created_at=datetime.now(timezone.utc),
            expires_at=approved.expires_at,
        )
        plaintext = json.dumps(
            {"content": approved.content, "attributes": dict(approved.attributes)},
            ensure_ascii=False,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
        payload = self.cipher.encrypt(
            plaintext,
            aad=build_memory_aad(metadata),
            workspace_id=context.workspace_id,
        )
        self.store.insert(metadata, payload)
        self._audit("remember", "success", context, memory_id, evaluation.decision.reason_codes[0])

        index_text = self._index_text(approved, evaluation)
        if index_text is not None:
            try:
                self.index.index(metadata, index_text)
                self.store.update_index_status(memory_id, context.workspace_id, IndexStatus.INDEXED)
                metadata = replace(metadata, index_status=IndexStatus.INDEXED)
            except Exception:
                self.store.update_index_status(memory_id, context.workspace_id, IndexStatus.INDEX_FAILED)
                metadata = replace(metadata, index_status=IndexStatus.INDEX_FAILED)
                self._audit("index", "failed", context, memory_id, "INDEX_WRITE_FAILED")
        return metadata

    def recall(self, memory_id: str, context: MemoryAccessContext) -> MemoryRecord:
        fetched = self.store.fetch(memory_id, context)
        if fetched is None:
            raise MemoryNotFound("memory not found or inaccessible")
        metadata, payload = fetched
        self._enforce_provider(metadata, context)
        plaintext = self.cipher.decrypt(
            payload,
            aad=build_memory_aad(metadata),
            workspace_id=context.workspace_id,
        )
        decoded = json.loads(plaintext.decode("utf-8"))
        self._audit("recall", "success", context, memory_id, "RECALL_AUTHORIZED")
        return MemoryRecord(metadata, str(decoded["content"]), dict(decoded.get("attributes") or {}))

    def list_metadata(self, query: MemoryQuery, context: MemoryAccessContext) -> Sequence[MemoryMetadata]:
        return tuple(
            metadata
            for metadata in self.store.list_metadata(query, context)
            if self._provider_allows(metadata, context)
        )

    def search(self, query: MemoryQuery, context: MemoryAccessContext) -> Sequence[MemoryRecord]:
        if query.text and self.index is not None:
            ids = self.index.candidate_ids(query, context)
            records: list[MemoryRecord] = []
            for memory_id in ids:
                try:
                    record = self.recall(memory_id, context)
                except (MemoryNotFound, MemoryAccessDenied):
                    continue
                if self._query_accepts(record.metadata, query):
                    records.append(record)
            return tuple(records[: query.limit])

        records = []
        for metadata in self.list_metadata(query, context):
            record = self.recall(metadata.id, context)
            if query.text and query.text.casefold() not in record.content.casefold():
                continue
            records.append(record)
        return tuple(records[: query.limit])

    def forget(self, memory_id: str, context: MemoryAccessContext) -> DeletionReceipt:
        metadata = self.store.mark_pending_delete(memory_id, context)
        event_id = self._audit("forget", "access_revoked", context, memory_id, "DELETE_ACCESS_REVOKED")
        index_deleted = True
        if self.index is not None:
            try:
                self.index.delete(memory_id, context)
            except Exception:
                index_deleted = False
        if index_deleted:
            self.store.purge_ciphertext(memory_id, context)
            self._audit("forget", "complete", context, memory_id, "DELETE_COMPLETE")
        else:
            self._audit("forget", "cleanup_pending", context, memory_id, "DELETE_INDEX_RETRY")
        return DeletionReceipt(
            memory_id=memory_id,
            requested_at=metadata.deleted_at or datetime.now(timezone.utc),
            authoritative_access_revoked=True,
            derived_index_deleted=index_deleted,
            cleanup_pending=not index_deleted,
            audit_event_id=event_id,
        )

    def clear_session(self, context: MemoryAccessContext) -> Sequence[DeletionReceipt]:
        if context.session_id is None:
            raise MemoryAccessDenied("clear_session requires an active session")
        metadata = [
            item
            for item in self.store.all_live_metadata(context)
            if item.scope is MemoryScope.SESSION and item.session_id == context.session_id
        ]
        return tuple(self.forget(item.id, context) for item in metadata)

    def clear_workspace(self, context: MemoryAccessContext) -> Sequence[DeletionReceipt]:
        metadata = self.store.all_workspace_live_metadata(context.workspace_id)
        receipts = []
        for item in metadata:
            item_context = MemoryAccessContext(context.workspace_id, item.session_id, context.provider)
            receipts.append(self.forget(item.id, item_context))
        return tuple(receipts)

    def retry_pending_deletions(self, context: MemoryAccessContext) -> tuple[str, ...]:
        completed: list[str] = []
        for memory_id in self.store.pending_delete_ids(context.workspace_id):
            try:
                if self.index is not None:
                    self.index.delete(memory_id, context)
                self.store.purge_ciphertext(memory_id, context)
                self._audit("forget_retry", "complete", context, memory_id, "DELETE_RETRY_COMPLETE")
                completed.append(memory_id)
            except Exception:
                self._audit("forget_retry", "failed", context, memory_id, "DELETE_RETRY_FAILED")
        return tuple(completed)

    def rebuild_index(self, context: MemoryAccessContext) -> int:
        if self.index is None:
            return 0
        self.index.reset()
        count = 0
        for metadata in self.store.all_live_metadata(context):
            if metadata.scope is not MemoryScope.WORKSPACE or metadata.classification is MemoryClassification.SECRET:
                continue
            record = self.recall(metadata.id, context)
            text = self._safe_rebuild_text(record)
            if text is None:
                continue
            self.index.index(metadata, text)
            self.store.update_index_status(metadata.id, context.workspace_id, IndexStatus.INDEXED)
            count += 1
        return count

    def status(self, context: MemoryAccessContext) -> dict[str, int]:
        return {
            **self.store.status(context.workspace_id),
            "vector_index_enabled": int(self.index is not None),
        }

    def audit_events(self, context: MemoryAccessContext, limit: int = 100):
        return self.store.list_audit(context.workspace_id, limit)

    def vacuum(self) -> None:
        self.store.vacuum()

    def close(self) -> None:
        if self.index is not None:
            close = getattr(self.index, "close", None)
            if close is not None:
                close()

    def _safe_rebuild_text(self, record: MemoryRecord) -> str | None:
        if record.metadata.classification in {MemoryClassification.PUBLIC, MemoryClassification.INTERNAL}:
            return record.content
        return f"Sensitive {record.metadata.memory_type.value} memory; original content withheld."

    def _index_text(self, candidate: MemoryCandidate, evaluation: MemoryEvaluation) -> str | None:
        if self.index is None or candidate.requested_scope is not MemoryScope.WORKSPACE:
            return None
        if evaluation.decision.classification is MemoryClassification.SECRET:
            return None
        if evaluation.decision.classification in {MemoryClassification.PUBLIC, MemoryClassification.INTERNAL}:
            return candidate.content
        categories = sorted({signal.category for signal in evaluation.signals if signal.severity >= 0.5})
        return f"Sensitive {candidate.memory_type.value} memory: {', '.join(categories) or 'confidential context'}."

    @staticmethod
    def _query_accepts(metadata: MemoryMetadata, query: MemoryQuery) -> bool:
        return (
            (not query.memory_types or metadata.memory_type in query.memory_types)
            and (not query.classifications or metadata.classification in query.classifications)
        )

    @staticmethod
    def _provider_allows(metadata: MemoryMetadata, context: MemoryAccessContext) -> bool:
        if metadata.classification is MemoryClassification.SECRET:
            return False
        if metadata.classification is MemoryClassification.CONFIDENTIAL:
            return context.provider.lower() in LOCAL_PROVIDERS
        return True

    def _enforce_provider(self, metadata: MemoryMetadata, context: MemoryAccessContext) -> None:
        if not self._provider_allows(metadata, context):
            raise MemoryAccessDenied("current provider may not receive this memory classification")

    def _audit(
        self,
        action: str,
        outcome: str,
        context: MemoryAccessContext,
        memory_id: str | None,
        reason_code: str,
    ) -> str:
        return self.store.record(
            action=action,
            outcome=outcome,
            workspace_id=context.workspace_id,
            memory_id_hash=hash_memory_id(memory_id) if memory_id else None,
            reason_code=reason_code,
        )
