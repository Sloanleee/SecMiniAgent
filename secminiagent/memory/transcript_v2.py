from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
from datetime import datetime, timezone
from typing import Mapping, Sequence

from ._ports import EncryptedPayload
from .canonical import canonical_json_bytes, canonical_timestamp, digest_provenance
from .errors import MemoryIntegrityError, MemoryLifecycleConflict, MemoryValidationError
from .models import (
    IndexStatus, MemoryAccessContext, MemoryAction, MemoryClassification, MemoryMetadata,
    MemoryScope, MemoryType, MessageEnvelope, NoteStatus, VerificationStatus,
)
from .store_v2 import SQLiteV2Store, memory_state_fields
from .thread_run_service import ThreadRunService
from .thread_run_store import ThreadRunStore
from .migration_v1_v2 import decode_v1_envelope
from .classifier import MemorySafetyEvaluator
from .models import MemoryCandidate, MemorySource


class ThreadTranscriptService:
    """Thread-filtered authenticated transcript for an already-active Schema v2 runtime."""

    def __init__(
        self, store: SQLiteV2Store, lifecycle: ThreadRunService, lifecycle_store: ThreadRunStore,
        *, envelope_key: bytes,
        evaluator: MemorySafetyEvaluator | None = None,
    ) -> None:
        if len(envelope_key) < 32:
            raise MemoryValidationError("transcript envelope key is invalid")
        self.store = store
        self.lifecycle = lifecycle
        self.lifecycle_store = lifecycle_store
        self._envelope_key = envelope_key
        self.evaluator = evaluator or MemorySafetyEvaluator()

    def append(self, context: MemoryAccessContext, run_id: str, message: Mapping[str, object]) -> MessageEnvelope:
        if context.session_id is None or context.thread_id is None:
            raise MemoryValidationError("transcript append requires session and thread context")
        safe_message, classification, policy_action, reason_codes = self._evaluate_message(context, message)
        role, call_ids, result_id = self._message_shape(safe_message)
        memory_type = MemoryType.TOOL_RESULT if role == "tool" else MemoryType.MESSAGE
        created_at = datetime.now(timezone.utc)
        message_id = secrets.token_hex(32)
        with self.store.connection(immediate=True) as connection:
            self.lifecycle_store.verify_ancestry(
                connection, context.workspace_id, context.session_id, context.thread_id, run_id,
                require_running=True,
            )
            existing = self._load_run(connection, context, run_id)
            self._validate_new_tool_message(existing, role, call_ids, result_id)
            thread_sequence = self.store.allocate_thread_sequence(
                connection, context.workspace_id, context.session_id, context.thread_id,
            )
            run_sequence = self.store.allocate_run_sequence(
                connection, context.workspace_id, context.session_id, context.thread_id, run_id,
            )
            header = self._header(
                message_id, context, run_id, thread_sequence, run_sequence, role,
                memory_type, created_at, call_ids, result_id,
            )
            digest = self._header_digest(header)
            metadata = MemoryMetadata(
                id=message_id, workspace_id=context.workspace_id, session_id=context.session_id,
                scope=MemoryScope.THREAD, memory_type=memory_type,
                classification=classification, source_type="transcript",
                policy_action=policy_action, policy_reason_codes=reason_codes,
                index_status=IndexStatus.NOT_INDEXED, created_at=created_at, schema_version=2,
                thread_id=context.thread_id, run_id=run_id, thread_sequence=thread_sequence,
                run_sequence=run_sequence, lifecycle_status=NoteStatus.ACTIVE,
                verification_status=VerificationStatus.UNKNOWN, provenance_digest=digest,
                updated_at=created_at,
            )
            plaintext = canonical_json_bytes({"header": header, "message": safe_message})
            self.store.insert_memory(connection, metadata, plaintext)
            self.lifecycle_store.record_message_progress(
                connection, context.workspace_id, context.session_id, context.thread_id,
                run_id, message_id, role,
            )
        return MessageEnvelope(
            message_id, context.workspace_id, context.session_id, context.thread_id, run_id,
            thread_sequence, run_sequence, role, memory_type, created_at, safe_message,
            call_ids, result_id, classification=classification,
        )

    def resume(self, context: MemoryAccessContext) -> tuple[MessageEnvelope, ...]:
        if context.session_id is None or context.thread_id is None:
            raise MemoryValidationError("transcript resume requires session and thread context")
        with self.store.connection() as connection:
            self.lifecycle_store.verify_ancestry(
                connection, context.workspace_id, context.session_id, context.thread_id,
            )
            rows = connection.execute(
                f"SELECT * FROM {self.store.table('memories')} WHERE workspace_id=? AND session_id=? AND thread_id=? "
                "AND scope='thread' AND memory_type IN ('message','tool_result') AND lifecycle_status='active' "
                "AND deleted_at IS NULL AND (expires_at IS NULL OR expires_at>? OR (pinned=1 AND retention_policy_id LIKE 'default:%')) ORDER BY thread_sequence,id",
                (context.workspace_id, context.session_id, context.thread_id, canonical_timestamp(datetime.now(timezone.utc))),
            ).fetchall()
            for run_id in sorted({str(row["run_id"]) for row in rows}):
                self.lifecycle_store.verify_ancestry(
                    connection, context.workspace_id, context.session_id, context.thread_id, run_id,
                )
            envelopes = tuple(self._decode_row(row) for row in rows)
        self._validate_sequence_and_pairs(envelopes)
        return envelopes

    def _load_run(
        self, connection: sqlite3.Connection, context: MemoryAccessContext, run_id: str,
    ) -> tuple[MessageEnvelope, ...]:
        rows = connection.execute(
            f"SELECT * FROM {self.store.table('memories')} WHERE workspace_id=? AND session_id=? AND thread_id=? AND run_id=? "
            "AND memory_type IN ('message','tool_result') AND deleted_at IS NULL ORDER BY run_sequence,id",
            (context.workspace_id, context.session_id, context.thread_id, run_id),
        ).fetchall()
        return tuple(self._decode_row(row) for row in rows)

    def _decode_row(self, row: sqlite3.Row) -> MessageEnvelope:
        data = dict(row)
        self.store.authenticator.verify_memory(bytes(row["state_mac"]), memory_state_fields(data))
        metadata = self.store._metadata_from_row(row)
        payload = EncryptedPayload(bytes(row["ciphertext"]), bytes(row["nonce"]), int(row["key_version"]), str(row["algorithm"]))
        try:
            plaintext = self.store.cipher.decrypt_memory(payload, metadata)
            value = json.loads(plaintext.decode())
        except (TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
            raise MemoryIntegrityError("transcript envelope is malformed") from exc
        if isinstance(value, dict) and isinstance(value.get("header"), dict) and isinstance(value.get("message"), dict):
            return self._decode_current(metadata, value["header"], value["message"])
        return self._decode_migrated(metadata, plaintext)

    def _decode_current(
        self, metadata: MemoryMetadata, header: Mapping[str, object], message: Mapping[str, object],
    ) -> MessageEnvelope:
        if not isinstance(header, dict) or not isinstance(message, dict):
            raise MemoryIntegrityError("transcript envelope is malformed")
        if not hmac.compare_digest(metadata.provenance_digest, self._header_digest(header)):
            raise MemoryIntegrityError("transcript envelope header authentication failed")
        expected = {
            "message_id": metadata.id, "workspace_id": metadata.workspace_id,
            "session_id": metadata.session_id, "thread_id": metadata.thread_id,
            "run_id": metadata.run_id, "thread_sequence": metadata.thread_sequence,
            "run_sequence": metadata.run_sequence, "memory_type": metadata.memory_type.value,
            "created_at": metadata.created_at,
        }
        for key, expected_value in expected.items():
            normalized = expected_value.isoformat() if isinstance(expected_value, datetime) else expected_value
            if key == "created_at":
                normalized = metadata.created_at.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            if header.get(key) != normalized:
                raise MemoryIntegrityError("transcript envelope ancestry is inconsistent")
        role, call_ids, result_id = self._message_shape(message)
        if header.get("role") != role or tuple(header.get("tool_call_ids", ())) != call_ids or header.get("tool_result_call_id") != result_id:
            raise MemoryIntegrityError("transcript envelope message shape is inconsistent")
        return MessageEnvelope(
            metadata.id, metadata.workspace_id, metadata.session_id or "", metadata.thread_id or "",
            metadata.run_id or "", metadata.thread_sequence or 0, metadata.run_sequence or 0,
            role, metadata.memory_type, metadata.created_at, message, call_ids, result_id,
            classification=metadata.classification, verification_status=metadata.verification_status,
        )

    def _decode_migrated(self, metadata: MemoryMetadata, plaintext: bytes) -> MessageEnvelope:
        if not hmac.compare_digest(metadata.provenance_digest, digest_provenance((), self._envelope_key)):
            raise MemoryIntegrityError("legacy transcript provenance is invalid")
        try:
            content, _attributes = decode_v1_envelope(plaintext)
            message = json.loads(content)
        except (TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
            raise MemoryIntegrityError("legacy transcript envelope is malformed") from exc
        if not isinstance(message, dict):
            raise MemoryIntegrityError("legacy transcript message is malformed")
        role, call_ids, result_id = self._message_shape(message)
        logical_type = MemoryType.TOOL_RESULT if role == "tool" else MemoryType.MESSAGE
        return MessageEnvelope(
            metadata.id, metadata.workspace_id, metadata.session_id or "", metadata.thread_id or "",
            metadata.run_id or "", metadata.thread_sequence or 0, metadata.run_sequence or 0,
            role, logical_type, metadata.created_at, message, call_ids, result_id,
            source_type="legacy_transcript", classification=metadata.classification,
            verification_status=metadata.verification_status,
        )

    def _evaluate_message(
        self, context: MemoryAccessContext, message: Mapping[str, object],
    ) -> tuple[dict[str, object], MemoryClassification, MemoryAction, tuple[str, ...]]:
        serialized = json.dumps(dict(message), ensure_ascii=False, separators=(",", ":"), default=str)
        candidate = MemoryCandidate(
            memory_type=MemoryType.MESSAGE, content=serialized, requested_scope=MemoryScope.THREAD,
            source=MemorySource("transcript", user_confirmed=True),
        )
        evaluation = self.evaluator.evaluate(candidate, context)
        if evaluation.persistable_candidate is None:
            return self._safe_message_shape(message), MemoryClassification.INTERNAL, MemoryAction.REDACT, (
                "TRANSCRIPT_SECRET_REDACTED", *evaluation.decision.reason_codes,
            )
        try:
            approved = json.loads(evaluation.persistable_candidate.content)
        except (TypeError, ValueError, json.JSONDecodeError):
            approved = None
        if not isinstance(approved, dict):
            approved = self._safe_message_shape(message)
            return approved, MemoryClassification.INTERNAL, MemoryAction.REDACT, ("TRANSCRIPT_REDACTION_FALLBACK",)
        return (
            approved, evaluation.decision.classification, evaluation.decision.action,
            tuple(evaluation.decision.reason_codes),
        )

    @staticmethod
    def _safe_message_shape(message: Mapping[str, object]) -> dict[str, object]:
        safe: dict[str, object] = {"role": str(message.get("role") or "user"), "content": "[REDACTED:SECRET]"}
        if message.get("tool_call_id") is not None:
            safe["tool_call_id"] = str(message["tool_call_id"])
        if isinstance(message.get("tool_calls"), list):
            calls = []
            for item in message["tool_calls"]:
                if not isinstance(item, dict):
                    continue
                function = item.get("function") if isinstance(item.get("function"), dict) else {}
                calls.append({
                    "id": str(item.get("id") or ""), "type": str(item.get("type") or "function"),
                    "function": {"name": str(function.get("name") or ""), "arguments": '{"redacted":true}'},
                })
            safe["tool_calls"] = calls
        return safe

    def _header(
        self, message_id: str, context: MemoryAccessContext, run_id: str,
        thread_sequence: int, run_sequence: int, role: str, memory_type: MemoryType,
        created_at: datetime, call_ids: Sequence[str], result_id: str | None,
    ) -> dict[str, object]:
        return {
            "message_id": message_id, "workspace_id": context.workspace_id,
            "session_id": context.session_id, "thread_id": context.thread_id, "run_id": run_id,
            "thread_sequence": thread_sequence, "run_sequence": run_sequence,
            "role": role, "memory_type": memory_type.value,
            "tool_call_ids": list(call_ids), "tool_result_call_id": result_id,
            "created_at": created_at.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "source_type": "transcript",
        }

    def _header_digest(self, header: Mapping[str, object]) -> bytes:
        return hmac.new(self._envelope_key, canonical_json_bytes(header), hashlib.sha256).digest()

    @staticmethod
    def _message_shape(message: Mapping[str, object]) -> tuple[str, tuple[str, ...], str | None]:
        role = message.get("role")
        if role not in {"user", "assistant", "tool"}:
            raise MemoryValidationError("transcript message role is invalid")
        call_ids: tuple[str, ...] = ()
        if role == "assistant" and message.get("tool_calls") is not None:
            calls = message["tool_calls"]
            if not isinstance(calls, list):
                raise MemoryValidationError("assistant tool_calls must be a list")
            values = []
            for call in calls:
                if not isinstance(call, dict) or not isinstance(call.get("id"), str) or not call["id"]:
                    raise MemoryValidationError("assistant tool call id is invalid")
                values.append(call["id"])
            if len(set(values)) != len(values):
                raise MemoryValidationError("assistant tool call ids must be unique")
            call_ids = tuple(values)
        result_id = message.get("tool_call_id") if role == "tool" else None
        if result_id is not None and (not isinstance(result_id, str) or not result_id):
            raise MemoryValidationError("tool_call_id is invalid")
        return str(role), call_ids, result_id

    @staticmethod
    def _validate_new_tool_message(
        existing: Sequence[MessageEnvelope], role: str, call_ids: Sequence[str], result_id: str | None,
    ) -> None:
        declared = {value for item in existing for value in item.tool_call_ids}
        consumed = {item.tool_result_call_id for item in existing if item.tool_result_call_id}
        pending = declared - consumed
        if pending and role != "tool":
            raise MemoryLifecycleConflict("TOOL_RESULTS_PENDING")
        if call_ids and (set(call_ids) & (declared | consumed)):
            raise MemoryLifecycleConflict("TOOL_CALL_ID_DUPLICATE")
        if role == "tool":
            if result_id not in declared:
                raise MemoryLifecycleConflict("TOOL_RESULT_ORPHANED")
            if result_id in consumed:
                raise MemoryLifecycleConflict("TOOL_RESULT_DUPLICATE")

    @staticmethod
    def _validate_sequence_and_pairs(items: Sequence[MessageEnvelope]) -> None:
        thread_sequences = [item.thread_sequence for item in items]
        if thread_sequences != sorted(set(thread_sequences)):
            raise MemoryIntegrityError("transcript thread sequence is invalid")
        by_run: dict[str, list[MessageEnvelope]] = {}
        for item in items:
            by_run.setdefault(item.run_id, []).append(item)
        for run_items in by_run.values():
            run_sequences = [item.run_sequence for item in run_items]
            if run_sequences != sorted(set(run_sequences)):
                raise MemoryIntegrityError("transcript run sequence is invalid")
            declared: set[str] = set()
            consumed: set[str] = set()
            pending: set[str] = set()
            for item in run_items:
                if pending and item.tool_result_call_id is None:
                    raise MemoryIntegrityError("transcript tool result group is not contiguous")
                if set(item.tool_call_ids) & (declared | consumed):
                    raise MemoryIntegrityError("transcript tool call is duplicated")
                declared.update(item.tool_call_ids)
                pending.update(item.tool_call_ids)
                if item.tool_result_call_id:
                    if item.tool_result_call_id not in pending or item.tool_result_call_id in consumed:
                        raise MemoryIntegrityError("transcript tool result is orphaned or duplicated")
                    consumed.add(item.tool_result_call_id)
                    pending.remove(item.tool_result_call_id)
