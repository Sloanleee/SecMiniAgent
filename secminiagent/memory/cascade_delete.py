from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Mapping, Sequence

from .canonical import canonical_json_bytes, canonical_timestamp
from .errors import (
    MemoryConfirmationRequired, MemoryDeletionIncomplete, MemoryIntegrityError,
    MemoryLifecycleConflict, MemoryNotFound, MemoryValidationError,
)
from .long_term_memory import LongTermMemoryService
from .models import (
    IndexStatus, MemoryAccessContext, MemoryAction, MemoryMetadata, MemoryRelationType,
    MemoryScope, NoteStatus, StructuredNote, VerificationStatus,
)
from .notes import provenance_digest
from .promotion import PromotionPreview
from .store_v2 import memory_state_fields, run_state_fields, thread_state_fields


@dataclass(frozen=True, slots=True)
class DeletionPreview:
    root_type: str
    root_id_hash: str
    direct_memory_count: int
    derived_memory_count: int
    promoted_workspace_count: int
    chroma_delete_count: int
    snapshot_digest: str
    confirmation_token: str = field(repr=False)
    expires_unix: int = 0
    retention_confirmations: tuple[PromotionPreview, ...] = field(default=(), repr=False)


@dataclass(frozen=True, slots=True)
class CascadeDeletionReceipt:
    job_id: str
    root_id_hash: str
    root_type: str
    authoritative_access_revoked: bool
    affected_runs: int
    affected_memories: int
    affected_relations: int
    derived_records_retracted: int
    independent_records_created: int
    index_deletions_complete: bool
    cleanup_pending: bool
    audit_event_id: str
    physical_overwrite_claimed: bool = False


class DeletionConfirmation:
    def __init__(self, key: bytes, ttl_seconds: int = 300) -> None:
        if len(key) < 32 or not 30 <= ttl_seconds <= 3600:
            raise MemoryValidationError("deletion confirmation configuration is invalid")
        self.key = key
        self.ttl_seconds = ttl_seconds

    def issue(self, workspace_id: str, root_type: str, root_id: str, snapshot: str) -> tuple[str, int]:
        expires = int(time.time()) + self.ttl_seconds
        payload = canonical_json_bytes({
            "workspace_id": workspace_id, "root_type": root_type,
            "root_id": root_id, "snapshot": snapshot, "expires": expires,
        })
        mac = hmac.new(self.key, payload, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(len(payload).to_bytes(4, "big") + payload + mac).decode().rstrip("="), expires

    def verify(self, token: str, workspace_id: str, root_type: str, root_id: str, snapshot: str) -> str:
        try:
            raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
            size = int.from_bytes(raw[:4], "big")
            payload, supplied = raw[4:4 + size], raw[4 + size:]
            fields = json.loads(payload.decode("ascii"))
        except Exception as exc:
            raise MemoryConfirmationRequired("DELETION_CONFIRMATION_INVALID") from exc
        expected = hmac.new(self.key, payload, hashlib.sha256).digest()
        required = {"workspace_id": workspace_id, "root_type": root_type, "root_id": root_id, "snapshot": snapshot}
        if len(supplied) != 32 or not hmac.compare_digest(supplied, expected):
            raise MemoryConfirmationRequired("DELETION_CONFIRMATION_INVALID")
        if any(fields.get(key) != value for key, value in required.items()):
            raise MemoryConfirmationRequired("DELETION_CONFIRMATION_BINDING_MISMATCH")
        if not isinstance(fields.get("expires"), int) or fields["expires"] < int(time.time()):
            raise MemoryConfirmationRequired("DELETION_CONFIRMATION_EXPIRED")
        return hashlib.sha256(raw).hexdigest()


class CascadeDeletionService:
    def __init__(
        self, long_term: LongTermMemoryService, *, deletion_key: bytes,
        index: object | None = None, max_nodes: int = 10_000, max_depth: int = 64,
    ) -> None:
        self.long_term = long_term
        self.store = long_term.store
        self.lifecycle = long_term.lifecycle_store
        self.confirmation = DeletionConfirmation(deletion_key)
        self.index = index
        self.max_nodes = max_nodes
        self.max_depth = max_depth

    def preview(self, context: MemoryAccessContext, root_type: str, root_id: str) -> DeletionPreview:
        with self.store.connection() as connection:
            plan = self._plan(connection, context, root_type, root_id)
        token, expires = self.confirmation.issue(context.workspace_id, root_type, root_id, plan["snapshot"])
        retention = tuple(
            self.long_term.confirmation.issue(
                workspace_id=context.workspace_id, note_id=note_id, revision=revision,
                target_scope=MemoryScope.WORKSPACE, classification=classification,
                purpose="independent_retention",
            )
            for note_id, revision, classification in plan["promoted"]
        )
        return DeletionPreview(
            root_type, self._hash(root_id), len(plan["direct"]), len(plan["derived"]),
            len(plan["promoted"]), len(plan["index_ids"]), plan["snapshot"], token, expires, retention,
        )

    def execute(
        self, context: MemoryAccessContext, root_type: str, root_id: str, token: str,
        *, independent_retention_tokens: Sequence[str] = (), fail_at: str | None = None,
    ) -> CascadeDeletionReceipt:
        try:
            raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
        except Exception as exc:
            raise MemoryConfirmationRequired("DELETION_CONFIRMATION_INVALID") from exc
        tentative_receipt_hash = hashlib.sha256(raw).hexdigest()
        tentative_job_id = hashlib.sha256(("delete:" + tentative_receipt_hash).encode()).hexdigest()
        existing = self._existing_receipt(context, tentative_job_id)
        if existing is not None:
            with self.store.connection() as connection:
                job = self._job(connection, context, tentative_job_id)
                if str(job["root_type"]) != root_type or str(job["root_id"]) != root_id:
                    raise MemoryConfirmationRequired("DELETION_CONFIRMATION_BINDING_MISMATCH")
            if existing.cleanup_pending and fail_at is None:
                return self.resume(context, tentative_job_id)
            return existing
        with self.store.connection() as connection:
            plan = self._plan(connection, context, root_type, root_id)
        receipt_hash = self.confirmation.verify(token, context.workspace_id, root_type, root_id, plan["snapshot"])
        job_id = hashlib.sha256(("delete:" + receipt_hash).encode()).hexdigest()
        retained = self._retention_selection(context, plan["promoted"], independent_retention_tokens)
        self._create_job(context, job_id, root_type, root_id, plan, receipt_hash, retained)
        if fail_at == "after_planned":
            raise RuntimeError("DELETION_FAILPOINT_AFTER_PLANNED")
        self._apply_sqlite(context, job_id, root_type, root_id, plan, retained)
        if fail_at == "after_sqlite":
            raise RuntimeError("DELETION_FAILPOINT_AFTER_SQLITE")
        return self._sync_index(context, job_id)

    def resume(self, context: MemoryAccessContext, job_id: str) -> CascadeDeletionReceipt:
        with self.store.connection() as connection:
            job = self._job(connection, context, job_id)
            status = str(job["status"])
        if status in {"authorized", "applying"}:
            with self.store.connection() as connection:
                plan = self._plan(connection, context, str(job["root_type"]), str(job["root_id"]))
            self._apply_sqlite(context, job_id, str(job["root_type"]), str(job["root_id"]), plan, set())
        return self._sync_index(context, job_id)

    def status(self, context: MemoryAccessContext, job_id: str) -> CascadeDeletionReceipt:
        receipt = self._existing_receipt(context, job_id)
        if receipt is None:
            raise MemoryNotFound("deletion job not found")
        return receipt

    def _plan(self, connection: sqlite3.Connection, context: MemoryAccessContext, root_type: str, root_id: str) -> dict[str, object]:
        if root_type not in {"run", "thread"}:
            raise MemoryValidationError("DELETION_ROOT_TYPE_INVALID")
        if context.session_id is None:
            raise MemoryNotFound("deletion root not found")
        direct: set[str] = set()
        affected_runs: set[str] = set()
        if root_type == "thread":
            thread_id = root_id
            self.lifecycle.verify_ancestry(connection, context.workspace_id, context.session_id, thread_id)
            affected_runs.update(str(row[0]) for row in connection.execute(
                f"SELECT run_id FROM {self.store.table('runs')} WHERE workspace_id=? AND session_id=? AND thread_id=? AND deleted_at IS NULL",
                (context.workspace_id, context.session_id, thread_id),
            ))
            direct.update(str(row[0]) for row in connection.execute(
                f"SELECT id FROM {self.store.table('memories')} WHERE workspace_id=? AND session_id=? AND thread_id=? AND deleted_at IS NULL",
                (context.workspace_id, context.session_id, thread_id),
            ))
        else:
            if context.thread_id is None:
                raise MemoryNotFound("deletion root not found")
            self.lifecycle.verify_ancestry(connection, context.workspace_id, context.session_id, context.thread_id, root_id)
            affected_runs.add(root_id)
            direct.update(str(row[0]) for row in connection.execute(
                f"SELECT id FROM {self.store.table('memories')} WHERE workspace_id=? AND session_id=? AND thread_id=? AND run_id=? AND deleted_at IS NULL",
                (context.workspace_id, context.session_id, context.thread_id, root_id),
            ))
        closure = set(direct)
        derived: set[str] = set()
        frontier = set(direct)
        relation_ids: set[str] = set()
        adjacency: dict[str, set[str]] = {}
        depth = 0
        while frontier:
            if depth >= self.max_depth or len(closure) > self.max_nodes:
                raise MemoryLifecycleConflict("DELETION_CLOSURE_LIMIT_EXCEEDED")
            next_frontier: set[str] = set()
            placeholders = ",".join("?" for _ in frontier)
            for relation in connection.execute(
                f"SELECT * FROM {self.store.table('memory_relations')} WHERE workspace_id=? AND target_memory_id IN ({placeholders}) AND deleted_at IS NULL",
                (context.workspace_id, *sorted(frontier)),
            ):
                self._verify_relation(relation)
                relation_ids.add(str(relation["relation_id"]))
                child = str(relation["source_memory_id"])
                adjacency.setdefault(str(relation["target_memory_id"]), set()).add(child)
                if child not in closure:
                    row = connection.execute(
                        f"SELECT * FROM {self.store.table('memories')} WHERE workspace_id=? AND id=? AND deleted_at IS NULL",
                        (context.workspace_id, child),
                    ).fetchone()
                    if row is None:
                        raise MemoryIntegrityError("DELETION_DERIVED_RECORD_MISSING")
                    self.store.authenticate_memory_row(row)
                    closure.add(child)
                    derived.add(child)
                    next_frontier.add(child)
            frontier = next_frontier
            depth += 1
        visiting: set[str] = set()
        visited: set[str] = set()
        def visit(node: str) -> None:
            if node in visiting:
                raise MemoryIntegrityError("DELETION_PROVENANCE_CYCLE")
            if node in visited:
                return
            visiting.add(node)
            for child in adjacency.get(node, ()):
                visit(child)
            visiting.remove(node)
            visited.add(node)
        for node in closure:
            visit(node)
        rows = {}
        for memory_id in closure:
            row = connection.execute(f"SELECT * FROM {self.store.table('memories')} WHERE id=?", (memory_id,)).fetchone()
            self.store.authenticate_memory_row(row)
            if row["note_kind"] is not None:
                note = self.long_term.notes._decode(row)
                self.long_term._verify_provenance(connection, row, note)
            elif row["memory_type"] == "thread_summary":
                payload = json.loads(self.store.authenticate_memory_row(row).decode())
                source_ids = tuple(str(item) for item in payload.get("source_memory_ids", ()))
                targets = tuple(str(item[0]) for item in connection.execute(
                    f"SELECT target_memory_id FROM {self.store.table('memory_relations')} WHERE workspace_id=? AND source_memory_id=? AND relation_type='summarizes' AND deleted_at IS NULL ORDER BY target_memory_id",
                    (context.workspace_id, memory_id),
                ))
                if tuple(sorted(source_ids)) != tuple(sorted(targets)) or not hmac.compare_digest(
                    bytes(row["provenance_digest"]),
                    provenance_digest(source_ids, MemoryRelationType.SUMMARIZES, self.long_term.provenance_key),
                ):
                    raise MemoryIntegrityError("DELETION_SUMMARY_PROVENANCE_INVALID")
            rows[memory_id] = row
        promoted = tuple(
            (memory_id, int(rows[memory_id]["record_revision"]), self.store._metadata_from_row(rows[memory_id]).classification)
            for memory_id in sorted(derived)
            if rows[memory_id]["scope"] == MemoryScope.WORKSPACE.value and rows[memory_id]["source_type"] == "note_promotion"
        )
        index_ids = {memory_id for memory_id, row in rows.items() if row["scope"] == "workspace" and row["index_status"] in {"indexed", "pending_index", "index_failed", "pending_delete"}}
        snapshot_fields = {
            "root_type": root_type, "root_id": root_id,
            "memories": [(memory_id, int(rows[memory_id]["record_revision"]), int(rows[memory_id]["state_version"])) for memory_id in sorted(rows)],
            "relations": sorted(relation_ids), "runs": sorted(affected_runs),
        }
        snapshot = hmac.new(self.confirmation.key, canonical_json_bytes(snapshot_fields), hashlib.sha256).hexdigest()
        return {"direct": direct, "derived": derived, "rows": rows, "runs": affected_runs, "relations": relation_ids, "promoted": promoted, "index_ids": index_ids, "snapshot": snapshot}

    def _create_job(self, context, job_id, root_type, root_id, plan, receipt_hash, retained) -> None:
        now = canonical_timestamp(datetime.now(timezone.utc))
        with self.store.connection(immediate=True) as connection:
            job = {"job_id": job_id, "workspace_id": context.workspace_id, "root_type": root_type, "root_id": root_id, "status": "authorized", "reason_code": "USER_CONFIRMED_DELETE", "state_version": 1, "updated_at": now}
            connection.execute(
                f"INSERT INTO {self.store.table('deletion_jobs')}(job_id,workspace_id,root_type,root_id,status,reason_code,state_version,state_mac,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (job_id, context.workspace_id, root_type, root_id, job["status"], job["reason_code"], 1, self.store.authenticator.sign_deletion_job(job), now, now),
            )
            for memory_id in sorted(set(plan["direct"]) | set(plan["derived"])):
                action = "delete" if memory_id in plan["direct"] else "retain_independent" if memory_id in retained else "retract"
                row = plan["rows"][memory_id]
                item = {"job_id": job_id, "target_type": "memory", "target_id": memory_id, "phase": "planned", "outcome": "pending", "selected_action": action, "target_revision": int(row["record_revision"]), "confirmation_receipt_hash": retained.get(memory_id), "independent_record_id": None, "last_error_code": None, "state_version": 1, "updated_at": now}
                connection.execute(
                    f"INSERT INTO {self.store.table('deletion_items')}(job_id,target_type,target_id,phase,outcome,selected_action,target_revision,confirmation_receipt_hash,independent_record_id,last_error_code,state_version,state_mac,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (job_id, "memory", memory_id, "planned", "pending", action, item["target_revision"], item["confirmation_receipt_hash"], None, None, 1, self.store.authenticator.sign_deletion_item(item), now),
                )

    def _apply_sqlite(self, context, job_id, root_type, root_id, plan, retained) -> None:
        now = canonical_timestamp(datetime.now(timezone.utc))
        with self.store.connection(immediate=True) as connection:
            job = self._job(connection, context, job_id)
            if job["status"] in {"index_pending", "complete"}:
                return
            independent_count = 0
            for item in connection.execute(f"SELECT * FROM {self.store.table('deletion_items')} WHERE job_id=? ORDER BY target_id", (job_id,)):
                self._verify_item(item)
                row = connection.execute(f"SELECT * FROM {self.store.table('memories')} WHERE id=?", (item["target_id"],)).fetchone()
                if row is None or row["deleted_at"] is not None or row["lifecycle_status"] in {"retracted", "deleted"}:
                    continue
                action = str(item["selected_action"])
                independent_id = None
                if action == "retain_independent":
                    independent_id = self._independent_copy(connection, context, row, str(item["confirmation_receipt_hash"]))
                    independent_count += 1
                target_status = NoteStatus.DELETED if action == "delete" else NoteStatus.RETRACTED
                self._set_memory_deleted(connection, row, target_status, now)
                self._update_item(connection, item, "sqlite_committed", "complete", independent_id=independent_id)
            for relation in connection.execute(
                f"SELECT * FROM {self.store.table('memory_relations')} WHERE workspace_id=? AND deleted_at IS NULL AND (source_memory_id IN (SELECT target_id FROM {self.store.table('deletion_items')} WHERE job_id=?) OR target_memory_id IN (SELECT target_id FROM {self.store.table('deletion_items')} WHERE job_id=?))",
                (context.workspace_id, job_id, job_id),
            ):
                self._tombstone_relation(connection, relation, now)
            self._set_root_deleted(connection, context, root_type, root_id, now)
            self._update_job(connection, job, "index_pending", "SQLITE_ACCESS_REVOKED")
            self.long_term._audit(connection, "cascade_delete", "access_revoked", context.workspace_id, root_id, "CASCADE_SQLITE_COMMITTED")

    def _sync_index(self, context, job_id) -> CascadeDeletionReceipt:
        with self.store.connection() as connection:
            job = self._job(connection, context, job_id)
            if job["status"] == "complete":
                receipt = self._existing_receipt(context, job_id)
                if receipt is None:
                    raise MemoryDeletionIncomplete("DELETION_RECEIPT_UNAVAILABLE")
                return receipt
            items = tuple(connection.execute(f"SELECT * FROM {self.store.table('deletion_items')} WHERE job_id=?", (job_id,)))
        failures = 0
        if self.index is not None:
            for item in items:
                try:
                    self.index.delete(str(item["target_id"]), context)
                except Exception:
                    failures += 1
                if item["independent_record_id"] is not None:
                    with self.store.connection() as connection:
                        retained = connection.execute(
                            f"SELECT * FROM {self.store.table('memories')} WHERE id=? AND deleted_at IS NULL",
                            (item["independent_record_id"],),
                        ).fetchone()
                    if retained is None:
                        failures += 1
                    elif retained["index_status"] in {IndexStatus.PENDING_INDEX.value, IndexStatus.INDEX_FAILED.value}:
                        note = self.long_term.notes._decode(retained)
                        self.long_term._index_workspace(self.store._metadata_from_row(retained), note.content)
                        with self.store.connection() as connection:
                            indexed = connection.execute(
                                f"SELECT index_status FROM {self.store.table('memories')} WHERE id=?",
                                (item["independent_record_id"],),
                            ).fetchone()
                        if indexed is None or indexed[0] != IndexStatus.INDEXED.value:
                            failures += 1
        with self.store.connection(immediate=True) as connection:
            job = self._job(connection, context, job_id)
            if failures:
                self._update_job(connection, job, "index_pending", "INDEX_DELETE_RETRY")
            else:
                self._update_job(connection, job, "complete", "DELETE_COMPLETE")
                self.long_term._audit(connection, "cascade_delete", "complete", context.workspace_id, str(job["root_id"]), "CASCADE_DELETE_COMPLETE")
        receipt = self._existing_receipt(context, job_id)
        if receipt is None:
            raise MemoryDeletionIncomplete("DELETION_RECEIPT_UNAVAILABLE")
        return receipt

    def _existing_receipt(self, context, job_id):
        with self.store.connection() as connection:
            row = connection.execute(f"SELECT * FROM {self.store.table('deletion_jobs')} WHERE job_id=? AND workspace_id=?", (job_id, context.workspace_id)).fetchone()
            if row is None:
                return None
            job = self._verified_job(row)
            items = tuple(connection.execute(f"SELECT * FROM {self.store.table('deletion_items')} WHERE job_id=?", (job_id,)))
            for item in items:
                self._verify_item(item)
            if job["root_type"] == "run":
                runs = 1
            else:
                runs = int(connection.execute(
                    f"SELECT COUNT(*) FROM {self.store.table('runs')} WHERE workspace_id=? AND thread_id=? AND deleted_at IS NOT NULL",
                    (context.workspace_id, job["root_id"]),
                ).fetchone()[0])
            relations = connection.execute(f"SELECT COUNT(*) FROM {self.store.table('memory_relations')} WHERE deleted_at IS NOT NULL AND (source_memory_id IN (SELECT target_id FROM {self.store.table('deletion_items')} WHERE job_id=?) OR target_memory_id IN (SELECT target_id FROM {self.store.table('deletion_items')} WHERE job_id=?))", (job_id, job_id)).fetchone()[0]
            retracted = sum(item["selected_action"] in {"retract", "retain_independent"} for item in items)
            independent = sum(item["independent_record_id"] is not None for item in items)
            complete = job["status"] == "complete"
            audit = connection.execute(
                "SELECT event_id FROM memory_audit WHERE workspace_id=? AND action='cascade_delete' AND memory_id_hash=? ORDER BY created_at DESC LIMIT 1",
                (context.workspace_id, self._hash(str(job["root_id"]))),
            ).fetchone()
            return CascadeDeletionReceipt(job_id, self._hash(str(job["root_id"])), str(job["root_type"]), job["status"] in {"index_pending", "complete"}, runs, len(items), int(relations), retracted, independent, complete, not complete, str(audit[0]) if audit else "pending")

    def _retention_selection(self, context, promoted, tokens):
        selected = {}
        for token in tokens:
            matched = False
            for note_id, revision, classification in promoted:
                try:
                    receipt = self.long_term.confirmation.verify(token, workspace_id=context.workspace_id, note_id=note_id, revision=revision, target_scope=MemoryScope.WORKSPACE, classification=classification, purpose="independent_retention")
                except MemoryConfirmationRequired:
                    continue
                selected[note_id] = receipt
                matched = True
                break
            if not matched:
                raise MemoryConfirmationRequired("INDEPENDENT_RETENTION_CONFIRMATION_INVALID")
        return selected

    def _independent_copy(self, connection, context, row, receipt_hash):
        note = self.long_term.notes._decode(row)
        target_id = secrets.token_hex(32)
        now = datetime.now(timezone.utc)
        metadata = MemoryMetadata(
            id=target_id, workspace_id=context.workspace_id, session_id=None, scope=MemoryScope.WORKSPACE,
            memory_type=self.long_term.notes._memory_type(note.kind), classification=note.classification,
            source_type="independent_retention", policy_action=MemoryAction.ALLOW,
            policy_reason_codes=("INDEPENDENT_RETENTION_CONFIRMED",),
            index_status=(
                IndexStatus.PENDING_INDEX
                if self.index is not None and note.classification.value != "secret"
                else IndexStatus.NOT_INDEXED
            ),
            created_at=now, schema_version=2, record_revision=1, lifecycle_status=NoteStatus.ACTIVE,
            verification_status=VerificationStatus.USER_CONFIRMED, note_kind=note.kind.value,
            provenance_digest=provenance_digest((), MemoryRelationType.DERIVED_FROM, self.long_term.provenance_key), updated_at=now,
        )
        copy = StructuredNote(
            target_id, context.workspace_id, None, None, note.kind, note.content,
            NoteStatus.ACTIVE, VerificationStatus.USER_CONFIRMED, note.confidence, note.importance,
            1, (), None, created_by="user", classification=note.classification, created_at=now,
            scope=MemoryScope.WORKSPACE,
        )
        payload = json.loads(self.long_term.notes._encode(copy).decode())
        payload["confirmation_receipt_hash"] = receipt_hash
        self.store.insert_memory(connection, metadata, json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode())
        return target_id

    def _set_memory_deleted(self, connection, row, status, now):
        current = dict(row)
        current.update(lifecycle_status=status.value, deleted_at=now if status is NoteStatus.DELETED else row["deleted_at"], index_status=IndexStatus.PENDING_DELETE.value if row["scope"] == "workspace" else row["index_status"], state_version=int(row["state_version"]) + 1, updated_at=now)
        current["state_mac"] = self.store.authenticator.sign_memory(memory_state_fields(current))
        connection.execute(f"UPDATE {self.store.table('memories')} SET lifecycle_status=?,deleted_at=?,index_status=?,state_version=?,updated_at=?,state_mac=? WHERE id=? AND state_version=?", (current["lifecycle_status"], current["deleted_at"], current["index_status"], current["state_version"], now, current["state_mac"], row["id"], row["state_version"]))

    def _set_root_deleted(self, connection, context, root_type, root_id, now):
        if root_type == "run":
            row = self.lifecycle._run(connection, context.workspace_id, context.session_id, context.thread_id, root_id)
            current = dict(row); current.update(status="deleted", deleted_at=now, state_version=int(row["state_version"]) + 1)
            current["state_mac"] = self.store.authenticator.sign_run(run_state_fields(current))
            connection.execute(f"UPDATE {self.store.table('runs')} SET status='deleted',deleted_at=?,state_version=?,state_mac=? WHERE run_id=? AND state_version=?", (now, current["state_version"], current["state_mac"], root_id, row["state_version"]))
        else:
            row = self.lifecycle._thread(connection, context.workspace_id, context.session_id, root_id)
            for run in connection.execute(f"SELECT * FROM {self.store.table('runs')} WHERE workspace_id=? AND session_id=? AND thread_id=? AND deleted_at IS NULL", (context.workspace_id, context.session_id, root_id)):
                verified = self.lifecycle._verified_run(run); current = dict(verified); current.update(status="deleted", deleted_at=now, state_version=int(run["state_version"]) + 1)
                current["state_mac"] = self.store.authenticator.sign_run(run_state_fields(current))
                connection.execute(f"UPDATE {self.store.table('runs')} SET status='deleted',deleted_at=?,state_version=?,state_mac=? WHERE run_id=? AND state_version=?", (now, current["state_version"], current["state_mac"], run["run_id"], run["state_version"]))
            current = dict(row); current.update(status="deleted", deleted_at=now, state_version=int(row["state_version"]) + 1, updated_at=now)
            current["state_mac"] = self.store.authenticator.sign_thread(thread_state_fields(current))
            connection.execute(f"UPDATE {self.store.table('threads')} SET status='deleted',deleted_at=?,state_version=?,updated_at=?,state_mac=? WHERE thread_id=? AND state_version=?", (now, current["state_version"], now, current["state_mac"], root_id, row["state_version"]))

    def _tombstone_relation(self, connection, relation, now):
        self._verify_relation(relation)
        current = dict(relation); current.update(deleted_at=now, state_version=int(relation["state_version"]) + 1)
        fields = {key: current[key] for key in ("workspace_id","relation_id","source_memory_id","target_memory_id","relation_type","state_version","created_at","deleted_at")}
        mac = self.store.authenticator.sign_relation(fields)
        connection.execute(f"UPDATE {self.store.table('memory_relations')} SET deleted_at=?,state_version=?,relation_mac=? WHERE relation_id=? AND state_version=?", (now, current["state_version"], mac, relation["relation_id"], relation["state_version"]))

    def _update_job(self, connection, row, status, reason):
        current = dict(row); current.update(status=status, reason_code=reason, state_version=int(row["state_version"]) + 1, updated_at=canonical_timestamp(datetime.now(timezone.utc)))
        mac = self.store.authenticator.sign_deletion_job({key: current[key] for key in ("job_id","workspace_id","state_version","root_type","root_id","status","reason_code","updated_at")})
        connection.execute(f"UPDATE {self.store.table('deletion_jobs')} SET status=?,reason_code=?,state_version=?,state_mac=?,updated_at=? WHERE job_id=? AND state_version=?", (status, reason, current["state_version"], mac, current["updated_at"], row["job_id"], row["state_version"]))

    def _update_item(self, connection, row, phase, outcome, independent_id=None):
        current = dict(row); current.update(phase=phase, outcome=outcome, independent_record_id=independent_id, state_version=int(row["state_version"]) + 1, updated_at=canonical_timestamp(datetime.now(timezone.utc)))
        fields = {key: current.get(key) for key in ("job_id","target_type","target_id","state_version","phase","outcome","selected_action","target_revision","confirmation_receipt_hash","independent_record_id","last_error_code","updated_at")}
        mac = self.store.authenticator.sign_deletion_item(fields)
        connection.execute(f"UPDATE {self.store.table('deletion_items')} SET phase=?,outcome=?,independent_record_id=?,state_version=?,state_mac=?,updated_at=? WHERE job_id=? AND target_type=? AND target_id=? AND state_version=?", (phase, outcome, independent_id, current["state_version"], mac, current["updated_at"], row["job_id"], row["target_type"], row["target_id"], row["state_version"]))

    def _job(self, connection, context, job_id):
        row = connection.execute(f"SELECT * FROM {self.store.table('deletion_jobs')} WHERE job_id=? AND workspace_id=?", (job_id, context.workspace_id)).fetchone()
        if row is None: raise MemoryNotFound("deletion job not found")
        return self._verified_job(row)

    def _verified_job(self, row):
        fields = {key: row[key] for key in ("job_id","workspace_id","state_version","root_type","root_id","status","reason_code","updated_at")}
        self.store.authenticator.verify_deletion_job(bytes(row["state_mac"]), fields); return row

    def _verify_item(self, row):
        fields = {key: row[key] for key in ("job_id","target_type","target_id","state_version","phase","outcome","selected_action","target_revision","confirmation_receipt_hash","independent_record_id","last_error_code","updated_at")}
        self.store.authenticator.verify_deletion_item(bytes(row["state_mac"]), fields)

    def _verify_relation(self, row):
        fields = {key: row[key] for key in ("workspace_id","relation_id","source_memory_id","target_memory_id","relation_type","state_version","created_at","deleted_at")}
        self.store.authenticator.verify_relation(bytes(row["relation_mac"]), fields)

    @staticmethod
    def _hash(value): return hashlib.sha256(value.encode()).hexdigest()
