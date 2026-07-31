from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Callable, Mapping, Sequence

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from ._ports import EncryptedPayload
from .canonical import canonical_domain_payload, canonical_timestamp, digest_provenance
from .crypto import ALGORITHM, AesGcmMemoryCipher, build_memory_aad_v1
from .errors import (
    MemoryIntegrityError,
    MemoryMigrationConflict,
    MemoryMigrationFailed,
    MemoryMigrationIncomplete,
    MemorySchemaUnsupported,
)
from .migration_v1_v2 import (
    LegacyEvent,
    event_from_plaintext,
    infer_legacy_runs,
    legacy_main_thread_id,
    legacy_note_mapping,
    source_snapshot,
)
from .models import (
    IndexStatus,
    MemoryAction,
    MemoryClassification,
    MemoryMetadata,
    MemoryScope,
    MemoryType,
    NoteStatus,
    VerificationStatus,
)
from .schema import (
    INDEXES,
    SCHEMA_V1,
    SCHEMA_V2,
    TABLES,
    V2_SHADOW_SUFFIX,
    SchemaState,
    create_v2_shadow,
    inspect_database_path,
    inspect_schema,
    validate_v2_structure,
)
from .state_auth import StateAuthenticator
from .store_v2 import SQLiteV2Store, memory_state_fields, run_state_fields, session_state_fields, thread_state_fields


class MigrationPhase(str, Enum):
    PREPARED = "prepared"
    COPYING = "copying"
    VERIFIED = "verified"
    SWITCHED = "switched"
    CLEANUP_PENDING = "cleanup_pending"
    COMPLETE = "complete"
    FAILED = "failed"


_VERIFIED_RUNTIME_TOKEN = object()


@dataclass(frozen=True, slots=True)
class MigrationCapability:
    can_read_v2: bool = False
    can_write_v2_memory: bool = False
    can_write_thread_transcript: bool = False
    can_verify_v2_parent_state: bool = False
    test_only: bool = False
    _runtime_token: object | None = field(default=None, repr=False, compare=False)

    @property
    def can_activate(self) -> bool:
        return (self.test_only or self._runtime_token is _VERIFIED_RUNTIME_TOKEN) and all(
            (
                self.can_read_v2,
                self.can_write_v2_memory,
                self.can_write_thread_transcript,
                self.can_verify_v2_parent_state,
            )
        )

    @classmethod
    def internal_test(cls) -> "MigrationCapability":
        return cls(True, True, True, True, True)

    @classmethod
    def verified_v2_runtime(cls) -> "MigrationCapability":
        """Internal release gate available only after the M7.3 runtime ships."""

        return cls(True, True, True, True, False, _VERIFIED_RUNTIME_TOKEN)


@dataclass(frozen=True, slots=True)
class MigrationPlan:
    current_schema: int
    target_schema: int
    state: str
    migratable_records: int
    session_count: int
    has_incomplete_journal: bool
    reason_codes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class MigrationItem:
    source_id_hash: str
    target_id_hash: str
    outcome: str


@dataclass(frozen=True, slots=True)
class MigrationVerification:
    valid: bool
    source_records: int
    target_records: int
    session_count: int
    thread_count: int
    run_count: int
    reason_codes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class MigrationReport:
    current_schema: int
    target_schema: int
    phase: str
    source_records: int
    target_records: int
    sessions: int
    threads: int
    runs: int
    notes: int
    reason_codes: tuple[str, ...] = ()


Failpoint = Callable[[str, str], None]


class _ExistingOnlyKeyProvider:
    def __init__(self, delegate: object) -> None:
        self.delegate = delegate

    def get_key(self, workspace_id: str) -> tuple[bytes, int]:
        return self.delegate.get_existing_key(workspace_id)

    def get_existing_key(self, workspace_id: str) -> tuple[bytes, int]:
        return self.delegate.get_existing_key(workspace_id)

    def derive_key(self, workspace_id: str, purpose: str, *, create: bool = False) -> tuple[bytes, int]:
        return self.delegate.derive_key(workspace_id, purpose, create=False)


class SchemaMigrator:
    def __init__(
        self,
        path: Path,
        *,
        key_provider: object | None = None,
        workspace_id: str | None = None,
        failpoint: Failpoint | None = None,
    ) -> None:
        self.path = path
        self.key_provider = key_provider
        self._key_reader = _ExistingOnlyKeyProvider(key_provider) if key_provider is not None else None
        self.workspace_id = workspace_id
        self.failpoint = failpoint
        self._emitted: set[str] = set()

    def inspect(self) -> MigrationPlan:
        inspection = inspect_database_path(self.path)
        if inspection.state is SchemaState.UNINITIALIZED:
            return MigrationPlan(0, SCHEMA_V2, inspection.state.value, 0, 0, False, (inspection.reason_code,))
        if inspection.state is SchemaState.NEWER:
            return MigrationPlan(inspection.user_version, SCHEMA_V2, inspection.state.value, 0, 0, False, (inspection.reason_code,))
        uri = f"file:{self.path.resolve().as_posix()}?mode=ro"
        connection = sqlite3.connect(uri, uri=True)
        try:
            memory_table = "memories" if inspection.user_version == SCHEMA_V1 else "memories_v1_backup"
            record_count = self._safe_count(connection, memory_table)
            session_count = self._safe_scalar(
                connection,
                f"SELECT COUNT(DISTINCT session_id) FROM {memory_table} WHERE session_id IS NOT NULL",
            )
            journal = "migration_journal_v2" if inspection.has_shadow else "migration_journal"
            incomplete = self._table_exists(connection, journal) and bool(
                self._safe_scalar(connection, f"SELECT COUNT(*) FROM {journal} WHERE phase NOT IN ('complete')")
            )
            return MigrationPlan(
                inspection.user_version,
                SCHEMA_V2,
                inspection.state.value,
                record_count,
                session_count,
                incomplete,
                ("MIGRATION_INCOMPLETE",) if incomplete else (),
            )
        finally:
            connection.close()

    def dry_run(self) -> MigrationReport:
        plan = self.inspect()
        if plan.current_schema not in {0, SCHEMA_V1}:
            code = "SCHEMA_ALREADY_V2" if plan.current_schema == SCHEMA_V2 else "SCHEMA_UNSUPPORTED"
            return MigrationReport(plan.current_schema, SCHEMA_V2, "dry_run", plan.migratable_records, 0, plan.session_count, 0, 0, 0, (code,))
        if plan.current_schema == 0:
            return MigrationReport(0, SCHEMA_V2, "dry_run", 0, 0, 0, 0, 0, 0, ("SCHEMA_UNINITIALIZED",))
        uri = f"file:{self.path.resolve().as_posix()}?mode=ro"
        connection = sqlite3.connect(uri, uri=True)
        connection.row_factory = sqlite3.Row
        try:
            rows = self._v1_rows(connection)
            reason_codes: tuple[str, ...] = ()
            if self.key_provider is not None:
                _workspace_id, _authenticator, keys = self._security_context()
                inference = self._session_inference(rows, AesGcmMemoryCipher(self._key_reader), keys["migration"])
                runs = sum(len(data["inference"].runs) for data in inference.values())
            else:
                runs = 0
                reason_codes = ("MIGRATION_KEY_UNAVAILABLE",)
            notes = self._safe_scalar(
                connection,
                "SELECT COUNT(*) FROM memories WHERE memory_type IN ('security_finding','project_fact','user_note','session_summary')",
            )
            return MigrationReport(
                SCHEMA_V1, SCHEMA_V2, "dry_run", plan.migratable_records, 0,
                plan.session_count, plan.session_count, runs, notes, reason_codes,
            )
        finally:
            connection.close()

    def prepare_shadow(self, capability: MigrationCapability) -> MigrationReport:
        if not capability.can_write_v2_memory:
            raise MemoryMigrationFailed("MIGRATION_CAPABILITY_REQUIRED")
        if not self.path.is_file():
            raise MemoryMigrationFailed("MIGRATION_SOURCE_UNAVAILABLE")
        workspace_id, authenticator, keys = self._security_context()
        connection = sqlite3.connect(self.path, timeout=0.05)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=50")
        try:
            if inspect_schema(connection).user_version != SCHEMA_V1:
                raise MemorySchemaUnsupported("migration requires schema v1 authority")
            create_v2_shadow(connection)
            connection.commit()
            try:
                connection.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as exc:
                raise MemoryMigrationConflict("MIGRATION_WRITER_CONFLICT") from exc
            self._verify_journal(connection, authenticator)
            rows = self._v1_rows(connection)
            snapshot = source_snapshot(rows)
            prepared_snapshot = self._prepared_snapshot(connection)
            if prepared_snapshot and prepared_snapshot != snapshot:
                raise MemoryMigrationConflict("MIGRATION_SOURCE_CHANGED")
            migration_id = self._migration_id(keys["migration"], workspace_id)
            self._record_journal(connection, authenticator, keys["migration"], migration_id, MigrationPhase.PREPARED, snapshot, "", "ready")
            self._emit("after_prepare")
            cipher = AesGcmMemoryCipher(self._key_reader)
            session_data = self._session_inference(rows, cipher, keys["migration"])
            v2 = SQLiteV2Store(self.path, key_provider=self._key_reader, authenticator=authenticator, shadow=True)
            self._copy_parents(connection, v2, workspace_id, session_data)
            self._emit("after_thread")
            self._emit("after_run")
            self._record_journal(connection, authenticator, keys["migration"], migration_id, MigrationPhase.COPYING, snapshot, "", "copying")
            migrated = self._copy_memories(connection, v2, rows, cipher, keys, session_data)
            self._emit("after_relation")
            self._emit("before_verify")
            connection.commit()
        except sqlite3.OperationalError as exc:
            connection.rollback()
            if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                raise MemoryMigrationConflict("MIGRATION_WRITER_CONFLICT") from exc
            raise
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

        verification = self.verify_shadow()
        if not verification.valid:
            raise MemoryMigrationFailed("MIGRATION_VERIFY_FAILED")
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._record_journal(connection, authenticator, keys["migration"], migration_id, MigrationPhase.VERIFIED, snapshot, "", "verified")
            connection.commit()
        finally:
            connection.close()
        self._emit("after_verify")
        return MigrationReport(
            SCHEMA_V1, SCHEMA_V2, MigrationPhase.VERIFIED.value,
            len(rows), migrated, verification.session_count, verification.thread_count, verification.run_count,
            self._note_count(rows),
        )

    def resume(self, capability: MigrationCapability) -> MigrationReport:
        return self.prepare_shadow(capability)

    def verify_shadow(self) -> MigrationVerification:
        if not self.path.is_file():
            raise MemoryMigrationIncomplete("MIGRATION_SOURCE_UNAVAILABLE")
        workspace_id, authenticator, _keys = self._security_context()
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        try:
            structure = validate_v2_structure(connection, shadow=True)
            if not structure.valid:
                return MigrationVerification(False, 0, 0, 0, 0, 0, ("MIGRATION_STRUCTURE_INVALID",))
            self._verify_journal(connection, authenticator)
            rows = self._v1_rows(connection)
            expected = self._prepared_snapshot(connection)
            if not expected or expected != source_snapshot(rows):
                return MigrationVerification(False, len(rows), 0, 0, 0, 0, ("MIGRATION_SOURCE_CHANGED",))
            v2 = SQLiteV2Store(self.path, key_provider=self._key_reader, authenticator=authenticator, shadow=True)
            v2.verify_state(connection)
            self._verify_entity_ciphertexts(connection, workspace_id)
            target_count = self._safe_count(connection, "memories_v2")
            if target_count != len(rows):
                return MigrationVerification(False, len(rows), target_count, 0, 0, 0, ("MIGRATION_COUNT_MISMATCH",))
            for row in connection.execute("SELECT * FROM memories_v2"):
                metadata = self._metadata_from_v2_row(row)
                payload = EncryptedPayload(bytes(row["ciphertext"]), bytes(row["nonce"]), int(row["key_version"]), str(row["algorithm"]))
                AesGcmMemoryCipher(self._key_reader).decrypt_memory(payload, metadata)
            fk_issues = tuple(connection.execute("PRAGMA foreign_key_check"))
            if fk_issues:
                return MigrationVerification(False, len(rows), target_count, 0, 0, 0, ("MIGRATION_ANCESTRY_INVALID",))
            sessions = self._safe_count(connection, "sessions_v2")
            threads = self._safe_count(connection, "threads_v2")
            runs = self._safe_count(connection, "runs_v2")
            return MigrationVerification(True, len(rows), target_count, sessions, threads, runs)
        except (MemoryIntegrityError, InvalidTag, ValueError, json.JSONDecodeError) as exc:
            raise MemoryMigrationFailed("MIGRATION_AUTHENTICATION_FAILED") from exc
        finally:
            connection.close()

    def activate_for_test(self, capability: MigrationCapability) -> MigrationReport:
        if not capability.test_only or not capability.can_activate:
            raise MemoryMigrationFailed("M7_V2_RUNTIME_NOT_READY")
        return self._activate(capability)

    def activate(self, capability: MigrationCapability) -> MigrationReport:
        if capability._runtime_token is not _VERIFIED_RUNTIME_TOKEN or not capability.can_activate:
            raise MemoryMigrationFailed("M7_V2_RUNTIME_NOT_READY")
        return self._activate(capability)

    def _activate(self, capability: MigrationCapability) -> MigrationReport:
        _ = capability
        verification = self.verify_shadow()
        if not verification.valid:
            raise MemoryMigrationFailed("MIGRATION_VERIFY_FAILED")
        workspace_id, authenticator, keys = self._security_context()
        self._emit("before_switch")
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        try:
            connection.execute("BEGIN IMMEDIATE")
            rows = self._v1_rows(connection)
            snapshot = source_snapshot(rows)
            if snapshot != self._prepared_snapshot(connection):
                raise MemoryMigrationConflict("MIGRATION_SOURCE_CHANGED")
            connection.execute("ALTER TABLE memories RENAME TO memories_v1_backup")
            for index_name in INDEXES:
                connection.execute(f"DROP INDEX IF EXISTS {index_name}{V2_SHADOW_SUFFIX}")
            for table_name in TABLES:
                connection.execute(f"ALTER TABLE {table_name}{V2_SHADOW_SUFFIX} RENAME TO {table_name}")
            self._create_final_indexes(connection)
            migration_id = self._migration_id(keys["migration"], workspace_id)
            self._record_journal(connection, authenticator, keys["migration"], migration_id, MigrationPhase.SWITCHED, snapshot, "", "switched", shadow=False)
            connection.execute(f"PRAGMA user_version={SCHEMA_V2}")
            self._emit("during_switch")
            validation = validate_v2_structure(connection, shadow=False)
            if not validation.valid:
                raise MemoryMigrationFailed("MIGRATION_SWITCH_VALIDATION_FAILED")
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        return MigrationReport(
            SCHEMA_V2, SCHEMA_V2, MigrationPhase.SWITCHED.value,
            verification.source_records, verification.target_records,
            verification.session_count, verification.thread_count, verification.run_count, 0,
        )

    def _security_context(self) -> tuple[str, StateAuthenticator, dict[str, bytes]]:
        if self.key_provider is None:
            raise MemoryMigrationFailed("MIGRATION_KEY_UNAVAILABLE")
        connection = sqlite3.connect(self.path)
        try:
            ids = [str(row[0]) for row in connection.execute("SELECT DISTINCT workspace_id FROM memories")]
        finally:
            connection.close()
        if len(ids) != 1 or (self.workspace_id is not None and ids[0] != self.workspace_id):
            raise MemoryMigrationFailed("MIGRATION_WORKSPACE_AMBIGUOUS")
        workspace_id = ids[0]
        keys = {
            purpose: self.key_provider.derive_key(workspace_id, purpose, create=False)[0]
            for purpose in ("state", "relation", "provenance", "migration", "dedup")
        }
        return workspace_id, StateAuthenticator(keys["state"], relation_key=keys["relation"]), keys

    def _session_inference(
        self,
        rows: Sequence[Mapping[str, object]],
        cipher: AesGcmMemoryCipher,
        migration_key: bytes,
    ) -> dict[str, dict[str, object]]:
        grouped: dict[str, list[Mapping[str, object]]] = {}
        for row in rows:
            if row["session_id"] is not None:
                grouped.setdefault(str(row["session_id"]), []).append(row)
        result: dict[str, dict[str, object]] = {}
        for session_id, session_rows in grouped.items():
            events: list[LegacyEvent] = []
            for row in session_rows:
                if str(row["memory_type"]) not in {"message", "tool_result"}:
                    continue
                metadata = self._metadata_from_v1_row(row)
                payload = EncryptedPayload(bytes(row["ciphertext"]), bytes(row["nonce"]), int(row["key_version"]), str(row["algorithm"]))
                plaintext = cipher.decrypt(payload, aad=build_memory_aad_v1(metadata), workspace_id=metadata.workspace_id)
                events.append(
                    event_from_plaintext(
                        memory_id=metadata.id,
                        sequence_no=metadata.sequence_no or 0,
                        memory_type=metadata.memory_type.value,
                        plaintext=plaintext,
                    )
                )
            thread_sequences: dict[str, int] = {}
            used_sequences: set[int] = set()
            next_sequence = 1
            for row in sorted(
                (item for item in session_rows if str(item["memory_type"]) != "session_meta"),
                key=lambda item: (
                    int(item["sequence_no"]) if item["sequence_no"] is not None else 2**31,
                    str(item["created_at"]),
                    str(item["id"]),
                ),
            ):
                proposed = int(row["sequence_no"]) if row["sequence_no"] is not None else next_sequence
                proposed = max(1, proposed)
                while proposed in used_sequences:
                    proposed += 1
                used_sequences.add(proposed)
                next_sequence = max(next_sequence, proposed + 1)
                thread_sequences[str(row["id"])] = proposed
            result[session_id] = {
                "thread_id": legacy_main_thread_id(migration_key, session_id),
                "inference": infer_legacy_runs(events, key=migration_key, session_id=session_id),
                "rows": session_rows,
                "thread_sequences": thread_sequences,
            }
        return result

    def _copy_parents(
        self,
        connection: sqlite3.Connection,
        v2: SQLiteV2Store,
        workspace_id: str,
        session_data: Mapping[str, Mapping[str, object]],
    ) -> None:
        for session_id, data in sorted(session_data.items()):
            rows = data["rows"]
            assert isinstance(rows, list)
            created_at = min(str(row["created_at"]) for row in rows)
            now = self._canonical_existing_time(created_at)
            session = {
                "workspace_id": workspace_id, "session_id": session_id, "schema_version": 2,
                "status": "active", "revision": 1, "state_version": 1,
                "created_at": now, "updated_at": now, "deleted_at": None,
            }
            v2.insert_session(connection, session)
            thread_sequences = data["thread_sequences"]
            max_sequence = max(thread_sequences.values(), default=0)
            inference = data["inference"]
            thread = {
                "workspace_id": workspace_id, "session_id": session_id, "thread_id": data["thread_id"],
                "schema_version": 2, "status": "active", "revision": 1,
                "next_run_no": len(inference.runs) + 1, "next_thread_sequence": max_sequence + 1,
                "state_version": 1, "created_at": now, "updated_at": now, "deleted_at": None,
            }
            v2.insert_thread(connection, thread)
            for run in inference.runs:
                event_rows = [row for row in rows if str(row["id"]) in run.event_ids]
                started = self._canonical_existing_time(min((str(row["created_at"]) for row in event_rows), default=created_at))
                completed = self._canonical_existing_time(max((str(row["created_at"]) for row in event_rows), default=created_at)) if run.status == "completed" else None
                v2.insert_run(
                    connection,
                    {
                        "workspace_id": workspace_id, "session_id": session_id, "thread_id": data["thread_id"],
                        "run_id": run.run_id, "run_no": run.run_no, "status": run.status,
                        "next_run_sequence": len(run.event_ids) + 1, "state_version": 1,
                        "input_message_id": run.input_message_id, "final_message_id": run.final_message_id,
                        "turn_count": 0, "started_at": started, "completed_at": completed,
                        "interruption_reason_code": "LEGACY_NEW_USER" if run.status == "interrupted" else None,
                        "migration_origin": run.migration_origin, "deleted_at": None,
                    },
                )

    def _copy_memories(
        self,
        connection: sqlite3.Connection,
        v2: SQLiteV2Store,
        rows: Sequence[Mapping[str, object]],
        cipher: AesGcmMemoryCipher,
        keys: Mapping[str, bytes],
        session_data: Mapping[str, Mapping[str, object]],
    ) -> int:
        migrated = 0
        for row in sorted(rows, key=lambda item: (str(item["created_at"]), str(item["id"]))):
            old = self._metadata_from_v1_row(row)
            payload = EncryptedPayload(bytes(row["ciphertext"]), bytes(row["nonce"]), int(row["key_version"]), str(row["algorithm"]))
            plaintext = cipher.decrypt(payload, aad=build_memory_aad_v1(old), workspace_id=old.workspace_id)
            session_id = old.session_id
            scope = old.scope
            thread_id = run_id = None
            thread_sequence = run_sequence = None
            if old.scope is MemoryScope.SESSION and old.memory_type is not MemoryType.SESSION_META:
                scope = MemoryScope.THREAD
                data = session_data[session_id or ""]
                thread_id = str(data["thread_id"])
                thread_sequence = data["thread_sequences"][old.id]
                inference = data["inference"]
                assignment = inference.event_assignments.get(old.id)
                if assignment:
                    run_id, run_sequence = assignment
            note_kind, verification, lifecycle, _legacy_flag = legacy_note_mapping(old.memory_type.value)
            if old.deleted_at is not None:
                lifecycle = "pending_delete"
            metadata = MemoryMetadata(
                id=old.id, workspace_id=old.workspace_id,
                session_id=session_id if scope is not MemoryScope.WORKSPACE else None,
                scope=scope, memory_type=old.memory_type, classification=old.classification,
                source_type=old.source_type, policy_action=old.policy_action,
                policy_reason_codes=old.policy_reason_codes, index_status=old.index_status,
                sequence_no=old.sequence_no, created_at=old.created_at, expires_at=old.expires_at,
                deleted_at=old.deleted_at, schema_version=2, thread_id=thread_id, run_id=run_id,
                record_revision=1, thread_sequence=thread_sequence, run_sequence=run_sequence,
                lifecycle_status=NoteStatus(lifecycle), verification_status=VerificationStatus(verification),
                note_kind=note_kind, provenance_digest=digest_provenance((), keys["provenance"]),
                state_version=1, updated_at=old.created_at,
            )
            v2.insert_memory(connection, metadata, plaintext)
            migrated += 1
            self._emit("after_memory")
        return migrated

    def _verify_entity_ciphertexts(self, connection: sqlite3.Connection, workspace_id: str) -> None:
        key, _version = self._key_reader.get_existing_key(workspace_id)
        for table, domain, fields in (
            ("sessions_v2", "secminiagent.session.v2", ("schema_version", "workspace_id", "session_id", "revision", "created_at")),
            ("threads_v2", "secminiagent.thread.v2", ("schema_version", "thread_id", "workspace_id", "session_id", "revision", "created_at")),
        ):
            for row in connection.execute(f"SELECT * FROM {table}"):
                aad = canonical_domain_payload(domain, {**{field: row[field] for field in fields}, "algorithm": row["algorithm"], "key_version": row["key_version"]})
                AESGCM(key).decrypt(bytes(row["nonce"]), bytes(row["ciphertext"]), aad)

    def _verify_journal(self, connection: sqlite3.Connection, authenticator: StateAuthenticator) -> None:
        if not self._table_exists(connection, "migration_journal_v2"):
            return
        for row in connection.execute("SELECT * FROM migration_journal_v2"):
            authenticator.verify_migration_entry(bytes(row["state_mac"]), self._journal_fields(dict(row)))

    def _record_journal(
        self,
        connection: sqlite3.Connection,
        authenticator: StateAuthenticator,
        migration_key: bytes,
        migration_id: str,
        phase: MigrationPhase,
        source_hash: str,
        target_hash: str,
        outcome: str,
        *,
        shadow: bool = True,
    ) -> None:
        table = f"migration_journal{V2_SHADOW_SUFFIX}" if shadow else "migration_journal"
        entry_id = self._migration_id(migration_key, f"{migration_id}:{phase.value}:{source_hash}:{target_hash}")
        existing = connection.execute(f"SELECT * FROM {table} WHERE journal_entry_id=?", (entry_id,)).fetchone()
        if existing is not None:
            authenticator.verify_migration_entry(bytes(existing["state_mac"]), self._journal_fields(dict(existing)))
            return
        now = canonical_timestamp(datetime.now(timezone.utc))
        row: dict[str, object] = {
            "journal_entry_id": entry_id, "migration_id": migration_id, "from_version": SCHEMA_V1,
            "to_version": SCHEMA_V2, "phase": phase.value, "source_record_id_hash": source_hash,
            "target_record_id_hash": target_hash, "outcome": outcome, "state_version": 1,
            "created_at": now, "updated_at": now,
        }
        row["state_mac"] = authenticator.sign_migration_entry(self._journal_fields(row))
        columns = tuple(row)
        connection.execute(
            f"INSERT INTO {table} ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})",
            tuple(row[column] for column in columns),
        )

    @staticmethod
    def _journal_fields(row: Mapping[str, object]) -> dict[str, object]:
        return {
            "journal_entry_id": row["journal_entry_id"], "migration_id": row["migration_id"],
            "state_version": row["state_version"], "from_version": row["from_version"],
            "to_version": row["to_version"], "phase": row["phase"],
            "source_record_id_hash": row["source_record_id_hash"],
            "target_record_id_hash": row["target_record_id_hash"], "outcome": row["outcome"],
            "created_at": row["created_at"], "updated_at": row["updated_at"],
        }

    def _prepared_snapshot(self, connection: sqlite3.Connection) -> str | None:
        if not self._table_exists(connection, "migration_journal_v2"):
            return None
        row = connection.execute(
            "SELECT source_record_id_hash FROM migration_journal_v2 WHERE phase='prepared' ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        return str(row[0]) if row else None

    def _v1_rows(self, connection: sqlite3.Connection) -> list[dict[str, object]]:
        return [dict(row) for row in connection.execute("SELECT * FROM memories ORDER BY created_at,id")]

    def _dry_run_counts(self, connection: sqlite3.Connection) -> int:
        total = 0
        for row in connection.execute(
            "SELECT session_id,COUNT(*) FROM memories WHERE session_id IS NOT NULL AND memory_type IN ('message','tool_result') GROUP BY session_id"
        ):
            total += max(1, int(row[1]))
        return total

    @staticmethod
    def _metadata_from_v1_row(row: Mapping[str, object]) -> MemoryMetadata:
        return MemoryMetadata(
            id=str(row["id"]), workspace_id=str(row["workspace_id"]),
            session_id=str(row["session_id"]) if row["session_id"] is not None else None,
            scope=MemoryScope(str(row["scope"])), memory_type=MemoryType(str(row["memory_type"])),
            classification=MemoryClassification(str(row["classification"])), source_type=str(row["source_type"]),
            policy_action=MemoryAction(str(row["policy_action"])),
            policy_reason_codes=tuple(str(row["policy_reason_codes"]).split("|")),
            index_status=IndexStatus(str(row["index_status"])),
            sequence_no=int(row["sequence_no"]) if row["sequence_no"] is not None else None,
            created_at=datetime.fromisoformat(str(row["created_at"])),
            expires_at=datetime.fromisoformat(str(row["expires_at"])) if row["expires_at"] else None,
            deleted_at=datetime.fromisoformat(str(row["deleted_at"])) if row["deleted_at"] else None,
        )

    @staticmethod
    def _metadata_from_v2_row(row: Mapping[str, object]) -> MemoryMetadata:
        reasons = json.loads(str(row["policy_reason_codes_json"]))
        return MemoryMetadata(
            id=str(row["id"]), workspace_id=str(row["workspace_id"]),
            session_id=str(row["session_id"]) if row["session_id"] is not None else None,
            scope=MemoryScope(str(row["scope"])), memory_type=MemoryType(str(row["memory_type"])),
            classification=MemoryClassification(str(row["classification"])), source_type=str(row["source_type"]),
            policy_action=MemoryAction(str(row["policy_action"])), policy_reason_codes=tuple(str(x) for x in reasons),
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

    @staticmethod
    def _canonical_existing_time(value: str) -> str:
        return canonical_timestamp(datetime.fromisoformat(value)) or ""

    @staticmethod
    def _migration_id(key: bytes, value: str) -> str:
        import hashlib, hmac
        return hmac.new(key, f"migration:{value}".encode("utf-8"), hashlib.sha256).hexdigest()

    @staticmethod
    def _table_exists(connection: sqlite3.Connection, name: str) -> bool:
        return connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None

    @staticmethod
    def _safe_count(connection: sqlite3.Connection, table: str) -> int:
        if not SchemaMigrator._table_exists(connection, table):
            return 0
        return int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])

    @staticmethod
    def _safe_scalar(connection: sqlite3.Connection, sql: str) -> int:
        row = connection.execute(sql).fetchone()
        return int(row[0] or 0)

    @staticmethod
    def _note_count(rows: Sequence[Mapping[str, object]]) -> int:
        return sum(str(row["memory_type"]) in {"security_finding", "project_fact", "user_note", "session_summary"} for row in rows)

    def _emit(self, name: str) -> None:
        if self.failpoint is None or name in self._emitted:
            return
        self._emitted.add(name)
        self.failpoint(name, "MIGRATION_FAILPOINT")

    @staticmethod
    def _create_final_indexes(connection: sqlite3.Connection) -> None:
        statements = (
            "CREATE UNIQUE INDEX ux_runs_one_running ON runs(workspace_id,session_id,thread_id) WHERE status='running' AND deleted_at IS NULL",
            "CREATE UNIQUE INDEX ux_memories_thread_sequence ON memories(workspace_id,session_id,thread_id,thread_sequence) WHERE scope='thread'",
            "CREATE UNIQUE INDEX ux_memories_run_sequence ON memories(workspace_id,session_id,thread_id,run_id,run_sequence) WHERE run_id IS NOT NULL",
            "CREATE UNIQUE INDEX ux_memories_one_active_summary ON memories(workspace_id,session_id,thread_id) WHERE memory_type='thread_summary' AND lifecycle_status='active' AND deleted_at IS NULL",
            "CREATE INDEX idx_memories_thread_recall ON memories(workspace_id,session_id,thread_id,lifecycle_status,expires_at,thread_sequence)",
            "CREATE INDEX idx_memories_workspace_recall ON memories(workspace_id,scope,memory_type,lifecycle_status,expires_at,created_at)",
            "CREATE INDEX idx_relations_source ON memory_relations(workspace_id,source_memory_id,relation_type)",
            "CREATE INDEX idx_relations_target ON memory_relations(workspace_id,target_memory_id,relation_type)",
        )
        for statement in statements:
            connection.execute(statement)
