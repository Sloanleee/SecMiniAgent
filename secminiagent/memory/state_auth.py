from __future__ import annotations

import hashlib
import hmac
from typing import Mapping

from .canonical import canonical_domain_payload
from .errors import MemoryStateIntegrityError


class StateAuthenticator:
    """Entity-specific authenticated mutable state for Schema v2."""

    def __init__(self, state_key: bytes, *, relation_key: bytes | None = None) -> None:
        if len(state_key) < 32:
            raise MemoryStateIntegrityError("state authentication key is invalid")
        self._state_key = state_key
        self._relation_key = relation_key or state_key

    def _sign(self, entity_type: str, fields: Mapping[str, object], *, relation: bool = False) -> bytes:
        self._require_fields(entity_type, fields)
        payload = canonical_domain_payload(
            "secminiagent.relation.v2" if relation else "secminiagent.state.v2",
            {"entity_type": entity_type, **dict(fields)},
        )
        key = self._relation_key if relation else self._state_key
        return hmac.new(key, payload, hashlib.sha256).digest()

    @staticmethod
    def _require_fields(entity_type: str, fields: Mapping[str, object]) -> None:
        required = {
            "session": {"workspace_id", "session_id", "state_version", "status", "revision", "updated_at", "deleted_at"},
            "thread": {"workspace_id", "session_id", "thread_id", "state_version", "status", "revision", "next_run_no", "next_thread_sequence", "updated_at", "deleted_at"},
            "run": {"workspace_id", "session_id", "thread_id", "run_id", "state_version", "run_no", "status", "next_run_sequence", "input_message_id", "final_message_id", "turn_count", "started_at", "completed_at", "interruption_reason_code", "migration_origin", "deleted_at"},
            "memory": {"workspace_id", "session_id", "thread_id", "run_id", "memory_id", "state_version", "lifecycle_status", "deleted_at", "expires_at", "pinned", "retention_policy_id", "index_status", "last_recalled_at", "last_validated_at", "provenance_digest", "updated_at"},
            "relation": {"workspace_id", "relation_id", "source_memory_id", "target_memory_id", "relation_type", "state_version", "created_at", "deleted_at"},
            "deletion_job": {"job_id", "workspace_id", "state_version", "root_type", "root_id", "status", "reason_code", "updated_at"},
            "deletion_item": {"job_id", "target_type", "target_id", "state_version", "phase", "outcome", "selected_action", "target_revision", "confirmation_receipt_hash", "independent_record_id", "last_error_code", "updated_at"},
            "migration_journal": {"journal_entry_id", "migration_id", "state_version", "from_version", "to_version", "phase", "source_record_id_hash", "target_record_id_hash", "outcome", "created_at", "updated_at"},
        }[entity_type]
        missing = required.difference(fields)
        if missing:
            raise MemoryStateIntegrityError("authenticated state is missing required fields")

    def _verify(self, expected: bytes, entity_type: str, fields: Mapping[str, object], *, relation: bool = False) -> None:
        actual = self._sign(entity_type, fields, relation=relation)
        if not hmac.compare_digest(expected, actual):
            raise MemoryStateIntegrityError("authenticated memory state is invalid")

    def sign_session(self, fields: Mapping[str, object]) -> bytes:
        return self._sign("session", fields)

    def verify_session(self, expected: bytes, fields: Mapping[str, object]) -> None:
        self._verify(expected, "session", fields)

    def sign_thread(self, fields: Mapping[str, object]) -> bytes:
        return self._sign("thread", fields)

    def verify_thread(self, expected: bytes, fields: Mapping[str, object]) -> None:
        self._verify(expected, "thread", fields)

    def sign_run(self, fields: Mapping[str, object]) -> bytes:
        return self._sign("run", fields)

    def verify_run(self, expected: bytes, fields: Mapping[str, object]) -> None:
        self._verify(expected, "run", fields)

    def sign_memory(self, fields: Mapping[str, object]) -> bytes:
        return self._sign("memory", fields)

    def verify_memory(self, expected: bytes, fields: Mapping[str, object]) -> None:
        self._verify(expected, "memory", fields)

    def sign_relation(self, fields: Mapping[str, object]) -> bytes:
        return self._sign("relation", fields, relation=True)

    def verify_relation(self, expected: bytes, fields: Mapping[str, object]) -> None:
        self._verify(expected, "relation", fields, relation=True)

    def sign_deletion_job(self, fields: Mapping[str, object]) -> bytes:
        return self._sign("deletion_job", fields)

    def verify_deletion_job(self, expected: bytes, fields: Mapping[str, object]) -> None:
        self._verify(expected, "deletion_job", fields)

    def sign_deletion_item(self, fields: Mapping[str, object]) -> bytes:
        return self._sign("deletion_item", fields)

    def verify_deletion_item(self, expected: bytes, fields: Mapping[str, object]) -> None:
        self._verify(expected, "deletion_item", fields)

    def sign_migration_entry(self, fields: Mapping[str, object]) -> bytes:
        return self._sign("migration_journal", fields)

    def verify_migration_entry(self, expected: bytes, fields: Mapping[str, object]) -> None:
        self._verify(expected, "migration_journal", fields)
