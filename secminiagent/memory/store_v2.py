from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Mapping

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ._ports import EncryptedPayload
from .canonical import canonical_domain_payload, canonical_timestamp
from .crypto import ALGORITHM, AesGcmMemoryCipher
from .errors import MemoryIntegrityError, MemoryNotFound
from .models import (
    IndexStatus, MemoryAction, MemoryClassification, MemoryMetadata, MemoryScope, MemoryType,
    NoteStatus, VerificationStatus,
)
from .schema import V2_SHADOW_SUFFIX
from .state_auth import StateAuthenticator


def _utc_text(value: datetime | None = None) -> str:
    return canonical_timestamp(value or datetime.now(timezone.utc)) or ""


def session_state_fields(row: Mapping[str, object]) -> dict[str, object]:
    return {
        "workspace_id": row["workspace_id"], "session_id": row["session_id"],
        "state_version": row["state_version"], "status": row["status"], "revision": row["revision"],
        "updated_at": row["updated_at"], "deleted_at": row.get("deleted_at"),
    }


def thread_state_fields(row: Mapping[str, object]) -> dict[str, object]:
    return {
        "workspace_id": row["workspace_id"], "session_id": row["session_id"], "thread_id": row["thread_id"],
        "state_version": row["state_version"], "status": row["status"], "revision": row["revision"],
        "next_run_no": row["next_run_no"], "next_thread_sequence": row["next_thread_sequence"],
        "updated_at": row["updated_at"], "deleted_at": row.get("deleted_at"),
    }


def run_state_fields(row: Mapping[str, object]) -> dict[str, object]:
    return {
        "workspace_id": row["workspace_id"], "session_id": row["session_id"], "thread_id": row["thread_id"],
        "run_id": row["run_id"], "state_version": row["state_version"], "run_no": row["run_no"],
        "status": row["status"], "next_run_sequence": row["next_run_sequence"],
        "input_message_id": row.get("input_message_id"), "final_message_id": row.get("final_message_id"),
        "turn_count": row["turn_count"], "started_at": row["started_at"],
        "completed_at": row.get("completed_at"), "interruption_reason_code": row.get("interruption_reason_code"),
        "migration_origin": row.get("migration_origin"), "deleted_at": row.get("deleted_at"),
    }


def memory_state_fields(row: Mapping[str, object]) -> dict[str, object]:
    return {
        "workspace_id": row["workspace_id"], "session_id": row.get("session_id"), "thread_id": row.get("thread_id"),
        "run_id": row.get("run_id"), "memory_id": row["id"], "state_version": row["state_version"],
        "lifecycle_status": row["lifecycle_status"], "deleted_at": row.get("deleted_at"),
        "expires_at": row.get("expires_at"), "pinned": row["pinned"],
        "retention_policy_id": row.get("retention_policy_id"), "index_status": row["index_status"],
        "last_recalled_at": row.get("last_recalled_at"), "last_validated_at": row.get("last_validated_at"),
        "provenance_digest": row["provenance_digest"], "updated_at": row["updated_at"],
    }


class SQLiteV2Store:
    """Internal Schema v2 writer used by migration and contract tests only."""

    def __init__(
        self,
        path: Path,
        *,
        key_provider: object,
        authenticator: StateAuthenticator,
        shadow: bool = True,
    ) -> None:
        self.path = path
        self.key_provider = key_provider
        self.authenticator = authenticator
        self.shadow = shadow
        self.suffix = V2_SHADOW_SUFFIX if shadow else ""
        self.cipher = AesGcmMemoryCipher(key_provider)

    def table(self, name: str) -> str:
        return f"{name}{self.suffix}"

    @contextmanager
    def connection(self, *, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=1000")
        try:
            if immediate:
                connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _encrypt_entity(
        self,
        *,
        workspace_id: str,
        domain: str,
        aad_fields: Mapping[str, object],
        plaintext: bytes,
    ) -> EncryptedPayload:
        key, version = self.key_provider.get_existing_key(workspace_id)
        aad = canonical_domain_payload(domain, {**dict(aad_fields), "algorithm": ALGORITHM, "key_version": version})
        nonce = os.urandom(12)
        return EncryptedPayload(AESGCM(key).encrypt(nonce, plaintext, aad), nonce, version, ALGORITHM)

    def insert_session(self, connection: sqlite3.Connection, row: Mapping[str, object], payload_plaintext: bytes = b"{}") -> None:
        data = dict(row)
        payload = self._encrypt_entity(
            workspace_id=str(data["workspace_id"]), domain="secminiagent.session.v2",
            aad_fields={k: data[k] for k in ("schema_version", "workspace_id", "session_id", "revision", "created_at")},
            plaintext=payload_plaintext,
        )
        data.update(key_version=payload.key_version, algorithm=payload.algorithm, ciphertext=payload.ciphertext, nonce=payload.nonce)
        data["state_mac"] = self.authenticator.sign_session(session_state_fields(data))
        self._insert(connection, self.table("sessions"), data)

    def insert_thread(self, connection: sqlite3.Connection, row: Mapping[str, object], payload_plaintext: bytes = b"{}") -> None:
        data = dict(row)
        payload = self._encrypt_entity(
            workspace_id=str(data["workspace_id"]), domain="secminiagent.thread.v2",
            aad_fields={k: data[k] for k in ("schema_version", "thread_id", "workspace_id", "session_id", "revision", "created_at")},
            plaintext=payload_plaintext,
        )
        data.update(key_version=payload.key_version, algorithm=payload.algorithm, ciphertext=payload.ciphertext, nonce=payload.nonce)
        data["state_mac"] = self.authenticator.sign_thread(thread_state_fields(data))
        self._insert(connection, self.table("threads"), data)

    def insert_run(self, connection: sqlite3.Connection, row: Mapping[str, object]) -> None:
        data = dict(row)
        data["state_mac"] = self.authenticator.sign_run(run_state_fields(data))
        self._insert(connection, self.table("runs"), data)

    def insert_memory(
        self,
        connection: sqlite3.Connection,
        metadata: MemoryMetadata,
        plaintext: bytes,
        *,
        importance_millis: int = 500,
        dedup_fingerprint: bytes | None = None,
    ) -> None:
        payload = self.cipher.encrypt_memory(plaintext, metadata)
        updated = metadata.updated_at or metadata.created_at
        row: dict[str, object] = {
            "id": metadata.id, "schema_version": 2, "workspace_id": metadata.workspace_id,
            "session_id": metadata.session_id, "thread_id": metadata.thread_id, "run_id": metadata.run_id,
            "scope": metadata.scope.value, "memory_type": metadata.memory_type.value, "note_kind": metadata.note_kind,
            "classification": metadata.classification.value, "verification_status": metadata.verification_status.value,
            "lifecycle_status": metadata.lifecycle_status.value, "source_type": metadata.source_type,
            "policy_action": metadata.policy_action.value,
            "policy_reason_codes_json": json.dumps(sorted(set(metadata.policy_reason_codes)), separators=(",", ":")),
            "record_revision": metadata.record_revision, "provenance_digest": metadata.provenance_digest,
            "dedup_fingerprint": dedup_fingerprint, "importance_millis": importance_millis,
            "key_version": payload.key_version, "algorithm": payload.algorithm, "ciphertext": payload.ciphertext,
            "nonce": payload.nonce, "index_status": metadata.index_status.value,
            "thread_sequence": metadata.thread_sequence, "run_sequence": metadata.run_sequence,
            "state_version": metadata.state_version, "retention_policy_id": metadata.retention_policy_id,
            "pinned": int(metadata.pinned), "created_at": canonical_timestamp(metadata.created_at),
            "updated_at": canonical_timestamp(updated), "expires_at": canonical_timestamp(metadata.expires_at),
            "last_recalled_at": canonical_timestamp(metadata.last_recalled_at),
            "last_validated_at": canonical_timestamp(metadata.last_validated_at),
            "deleted_at": canonical_timestamp(metadata.deleted_at),
        }
        row["state_mac"] = self.authenticator.sign_memory(memory_state_fields(row))
        self._insert(connection, self.table("memories"), row)

    def insert_relation(self, connection: sqlite3.Connection, row: Mapping[str, object]) -> None:
        data = dict(row)
        data["relation_mac"] = self.authenticator.sign_relation(
            {
                "workspace_id": data["workspace_id"], "relation_id": data["relation_id"],
                "source_memory_id": data["source_memory_id"], "target_memory_id": data["target_memory_id"],
                "relation_type": data["relation_type"], "state_version": data["state_version"],
                "created_at": data["created_at"], "deleted_at": data.get("deleted_at"),
            }
        )
        self._insert(connection, self.table("memory_relations"), data)

    def allocate_thread_sequence(self, connection: sqlite3.Connection, workspace_id: str, session_id: str, thread_id: str) -> int:
        table = self.table("threads")
        row = connection.execute(
            f"SELECT * FROM {table} WHERE workspace_id=? AND session_id=? AND thread_id=?",
            (workspace_id, session_id, thread_id),
        ).fetchone()
        if row is None:
            raise MemoryNotFound("thread not found or inaccessible")
        current = dict(row)
        self.authenticator.verify_thread(bytes(row["state_mac"]), thread_state_fields(current))
        if row["status"] != "active" or row["deleted_at"] is not None:
            raise MemoryNotFound("thread not found or inaccessible")
        sequence = int(row["next_thread_sequence"])
        current["next_thread_sequence"] = sequence + 1
        current["state_version"] = int(row["state_version"]) + 1
        current["updated_at"] = _utc_text()
        mac = self.authenticator.sign_thread(thread_state_fields(current))
        result = connection.execute(
            f"UPDATE {table} SET next_thread_sequence=?,state_version=?,updated_at=?,state_mac=? WHERE workspace_id=? AND session_id=? AND thread_id=? AND state_version=?",
            (sequence + 1, current["state_version"], current["updated_at"], mac, workspace_id, session_id, thread_id, row["state_version"]),
        )
        if result.rowcount != 1:
            raise MemoryIntegrityError("thread sequence allocation conflicted")
        return sequence

    def allocate_run_sequence(
        self, connection: sqlite3.Connection, workspace_id: str, session_id: str, thread_id: str, run_id: str,
    ) -> int:
        table = self.table("runs")
        row = connection.execute(
            f"SELECT * FROM {table} WHERE workspace_id=? AND session_id=? AND thread_id=? AND run_id=?",
            (workspace_id, session_id, thread_id, run_id),
        ).fetchone()
        if row is None:
            raise MemoryNotFound("run not found or inaccessible")
        current = dict(row)
        self.authenticator.verify_run(bytes(row["state_mac"]), run_state_fields(current))
        if row["status"] != "running" or row["deleted_at"] is not None:
            raise MemoryNotFound("run not found or inaccessible")
        sequence = int(row["next_run_sequence"])
        current["next_run_sequence"] = sequence + 1
        current["state_version"] = int(row["state_version"]) + 1
        mac = self.authenticator.sign_run(run_state_fields(current))
        result = connection.execute(
            f"UPDATE {table} SET next_run_sequence=?,state_version=?,state_mac=? WHERE workspace_id=? AND session_id=? AND thread_id=? AND run_id=? AND state_version=?",
            (sequence + 1, current["state_version"], mac, workspace_id, session_id, thread_id, run_id, row["state_version"]),
        )
        if result.rowcount != 1:
            raise MemoryIntegrityError("run sequence allocation conflicted")
        return sequence

    def verify_state(self, connection: sqlite3.Connection) -> None:
        for table_name, builder, verifier in (
            ("sessions", session_state_fields, self.authenticator.verify_session),
            ("threads", thread_state_fields, self.authenticator.verify_thread),
            ("runs", run_state_fields, self.authenticator.verify_run),
            ("memories", memory_state_fields, self.authenticator.verify_memory),
        ):
            for row in connection.execute(f"SELECT * FROM {self.table(table_name)}"):
                data = dict(row)
                verifier(bytes(row["state_mac"]), builder(data))
        for row in connection.execute(f"SELECT * FROM {self.table('memory_relations')}"):
            data = dict(row)
            self.authenticator.verify_relation(
                bytes(row["relation_mac"]),
                {
                    "workspace_id": data["workspace_id"], "relation_id": data["relation_id"],
                    "source_memory_id": data["source_memory_id"], "target_memory_id": data["target_memory_id"],
                    "relation_type": data["relation_type"], "state_version": data["state_version"],
                    "created_at": data["created_at"], "deleted_at": data.get("deleted_at"),
                },
            )

    def read_memory(self, memory_id: str) -> bytes:
        """Authenticate parent/state/ciphertext without updating recall metadata."""

        with self.connection() as connection:
            row = connection.execute(
                f"SELECT * FROM {self.table('memories')} WHERE id=? AND deleted_at IS NULL",
                (memory_id,),
            ).fetchone()
            if row is None:
                raise MemoryNotFound("memory not found or inaccessible")
            data = dict(row)
            if row["session_id"] is not None:
                parent = connection.execute(
                    f"SELECT * FROM {self.table('sessions')} WHERE workspace_id=? AND session_id=?",
                    (row["workspace_id"], row["session_id"]),
                ).fetchone()
                if parent is None:
                    raise MemoryIntegrityError("memory parent state is unavailable")
                self.authenticator.verify_session(bytes(parent["state_mac"]), session_state_fields(dict(parent)))
            if row["thread_id"] is not None:
                parent = connection.execute(
                    f"SELECT * FROM {self.table('threads')} WHERE workspace_id=? AND session_id=? AND thread_id=?",
                    (row["workspace_id"], row["session_id"], row["thread_id"]),
                ).fetchone()
                if parent is None:
                    raise MemoryIntegrityError("memory parent state is unavailable")
                self.authenticator.verify_thread(bytes(parent["state_mac"]), thread_state_fields(dict(parent)))
            if row["run_id"] is not None:
                parent = connection.execute(
                    f"SELECT * FROM {self.table('runs')} WHERE workspace_id=? AND session_id=? AND thread_id=? AND run_id=?",
                    (row["workspace_id"], row["session_id"], row["thread_id"], row["run_id"]),
                ).fetchone()
                if parent is None:
                    raise MemoryIntegrityError("memory parent state is unavailable")
                self.authenticator.verify_run(bytes(parent["state_mac"]), run_state_fields(dict(parent)))
            return self.authenticate_memory_row(row)

    def authenticate_memory_row(self, row: Mapping[str, object]) -> bytes:
        data = dict(row)
        self.authenticator.verify_memory(bytes(row["state_mac"]), memory_state_fields(data))
        metadata = self._metadata_from_row(row)
        payload = EncryptedPayload(bytes(row["ciphertext"]), bytes(row["nonce"]), int(row["key_version"]), str(row["algorithm"]))
        return self.cipher.decrypt_memory(payload, metadata)

    @staticmethod
    def _insert(connection: sqlite3.Connection, table: str, row: Mapping[str, object]) -> None:
        columns = tuple(row.keys())
        placeholders = ",".join("?" for _ in columns)
        connection.execute(
            f"INSERT OR IGNORE INTO {table} ({','.join(columns)}) VALUES ({placeholders})",
            tuple(row[column] for column in columns),
        )

    @staticmethod
    def _metadata_from_row(row: Mapping[str, object]) -> MemoryMetadata:
        return MemoryMetadata(
            id=str(row["id"]), workspace_id=str(row["workspace_id"]),
            session_id=str(row["session_id"]) if row["session_id"] is not None else None,
            scope=MemoryScope(str(row["scope"])), memory_type=MemoryType(str(row["memory_type"])),
            classification=MemoryClassification(str(row["classification"])), source_type=str(row["source_type"]),
            policy_action=MemoryAction(str(row["policy_action"])),
            policy_reason_codes=tuple(str(value) for value in json.loads(str(row["policy_reason_codes_json"]))),
            index_status=IndexStatus(str(row["index_status"])), created_at=datetime.fromisoformat(str(row["created_at"])),
            expires_at=datetime.fromisoformat(str(row["expires_at"])) if row["expires_at"] else None,
            deleted_at=datetime.fromisoformat(str(row["deleted_at"])) if row["deleted_at"] else None,
            schema_version=2, thread_id=str(row["thread_id"]) if row["thread_id"] is not None else None,
            run_id=str(row["run_id"]) if row["run_id"] is not None else None,
            record_revision=int(row["record_revision"]),
            thread_sequence=int(row["thread_sequence"]) if row["thread_sequence"] is not None else None,
            run_sequence=int(row["run_sequence"]) if row["run_sequence"] is not None else None,
            lifecycle_status=NoteStatus(str(row["lifecycle_status"])),
            verification_status=VerificationStatus(str(row["verification_status"])),
            note_kind=str(row["note_kind"]) if row["note_kind"] is not None else None,
            provenance_digest=bytes(row["provenance_digest"]), state_version=int(row["state_version"]),
            updated_at=datetime.fromisoformat(str(row["updated_at"])),
            retention_policy_id=str(row["retention_policy_id"]) if row["retention_policy_id"] is not None else None,
            pinned=bool(row["pinned"]),
            last_recalled_at=datetime.fromisoformat(str(row["last_recalled_at"])) if row["last_recalled_at"] else None,
            last_validated_at=datetime.fromisoformat(str(row["last_validated_at"])) if row["last_validated_at"] else None,
        )
