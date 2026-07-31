from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

from .canonical import canonical_timestamp
from .errors import MemoryIntegrityError, MemoryValidationError
from .models import (
    MemoryAccessContext, MemoryClassification, MemoryQuery, MemoryScope, MemorySearchHit,
    NoteStatus,
)
from .ranking import rank_features, tokens
from .store_v2 import SQLiteV2Store
from .thread_run_store import ThreadRunStore


class HybridMemorySearch:
    """Bounded authority-first retrieval; Chroma contributes opaque workspace IDs only."""

    def __init__(
        self, store: SQLiteV2Store, lifecycle: ThreadRunStore, *, index: object | None = None,
        candidate_limit: int = 256, decrypt_limit: int = 128,
    ) -> None:
        if not 1 <= decrypt_limit <= candidate_limit <= 1000:
            raise MemoryValidationError("search limits are invalid")
        self.store = store
        self.lifecycle = lifecycle
        self.index = index
        self.candidate_limit = candidate_limit
        self.decrypt_limit = decrypt_limit
        self._stale_index_ids: set[str] = set()

    def search(
        self, context: MemoryAccessContext, query: str, *, limit: int = 20,
        scopes: tuple[MemoryScope, ...] = (),
    ) -> tuple[MemorySearchHit, ...]:
        if not query.strip() or not 1 <= limit <= 100:
            raise MemoryValidationError("search query or limit is invalid")
        semantic_ids: set[str] = set()
        if self.index is not None:
            try:
                semantic_ids.update(self.index.candidate_ids(MemoryQuery(text=query, limit=self.candidate_limit), context))
            except Exception:
                semantic_ids.clear()
        with self.store.connection() as connection:
            if context.thread_id is not None:
                if context.session_id is None:
                    return ()
                self.lifecycle.verify_ancestry(connection, context.workspace_id, context.session_id, context.thread_id)
            rows = self._authority_candidates(connection, context, scopes, semantic_ids)
            self._stale_index_ids.update(semantic_ids - {str(row["id"]) for row in rows})
            hits: list[MemorySearchHit] = []
            query_tokens = tokens(query)
            for row in rows[: self.decrypt_limit]:
                try:
                    plaintext = self.store.authenticate_memory_row(row)
                    content = self._content(plaintext)
                except (MemoryIntegrityError, UnicodeError, ValueError, TypeError, KeyError, json.JSONDecodeError):
                    continue
                lexical_match = bool(query_tokens & tokens(content))
                semantic = str(row["id"]) in semantic_ids
                if not lexical_match and not semantic:
                    continue
                metadata = self.store._metadata_from_row(row)
                score, features, reasons = rank_features(
                    query, content, semantic=semantic,
                    importance_millis=int(row["importance_millis"]),
                    verification=metadata.verification_status, created_at=metadata.created_at,
                )
                hits.append(MemorySearchHit(
                    metadata.id, metadata.scope, metadata.memory_type, metadata.classification,
                    metadata.verification_status, metadata.lifecycle_status, content,
                    score, features, (*reasons, "SEARCH_SQLITE_AUTHORITY_VERIFIED"),
                ))
        hits.sort(key=lambda item: (-item.score_millis, item.memory_id))
        return tuple(hits[:limit])

    def reconcile_stale(self, context: MemoryAccessContext, *, dry_run: bool = False) -> tuple[str, ...]:
        ids = tuple(sorted(self._stale_index_ids))
        if dry_run or self.index is None:
            return ids
        completed = []
        for memory_id in ids:
            try:
                self.index.delete(memory_id, context)
                completed.append(memory_id)
            except Exception:
                continue
        self._stale_index_ids.difference_update(completed)
        return tuple(completed)

    def _authority_candidates(
        self, connection: sqlite3.Connection, context: MemoryAccessContext,
        scopes: tuple[MemoryScope, ...], semantic_ids: set[str],
    ) -> list[sqlite3.Row]:
        clauses = [
            "workspace_id=?", "deleted_at IS NULL", "lifecycle_status='active'",
            "verification_status IN ('user_confirmed','tool_verified','model_inferred')",
            "(expires_at IS NULL OR expires_at>? OR (pinned=1 AND retention_policy_id LIKE 'default:%'))", "classification!='secret'",
        ]
        params: list[object] = [context.workspace_id, canonical_timestamp(datetime.now(timezone.utc))]
        access = ["scope='workspace'"]
        if context.session_id is not None:
            access.append("(scope='session' AND session_id=?)")
            params.append(context.session_id)
        if context.session_id is not None and context.thread_id is not None:
            access.append("(scope='thread' AND session_id=? AND thread_id=?)")
            params.extend((context.session_id, context.thread_id))
        clauses.append("(" + " OR ".join(access) + ")")
        if context.provider not in {"local", "fake"}:
            clauses.append("classification!='confidential'")
        if scopes:
            clauses.append("scope IN (" + ",".join("?" for _ in scopes) + ")")
            params.extend(item.value for item in scopes)
        sql = f"SELECT * FROM {self.store.table('memories')} WHERE " + " AND ".join(clauses)
        semantic_order: list[object] = []
        bounded_ids = tuple(sorted(semantic_ids))[: self.candidate_limit]
        if bounded_ids:
            placeholders = ",".join("?" for _ in bounded_ids)
            sql += f" ORDER BY CASE WHEN id IN ({placeholders}) THEN 0 ELSE 1 END,created_at DESC,id"
            semantic_order.extend(bounded_ids)
        else:
            sql += " ORDER BY created_at DESC,id"
        params.extend(semantic_order)
        sql += " LIMIT ?"
        params.append(self.candidate_limit)
        rows = list(connection.execute(sql, params))
        # Semantic IDs never bypass the same authority query. They only affect ranking among eligible rows.
        return rows

    @staticmethod
    def _content(plaintext: bytes) -> str:
        value = json.loads(plaintext.decode())
        if isinstance(value, dict) and isinstance(value.get("content"), str):
            return value["content"]
        if isinstance(value, dict) and isinstance(value.get("message"), dict):
            content = value["message"].get("content")
            if isinstance(content, str):
                return content
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
