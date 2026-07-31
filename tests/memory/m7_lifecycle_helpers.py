from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from secminiagent.memory.canonical import canonical_timestamp
from secminiagent.memory.models import MemoryAccessContext
from secminiagent.memory.schema import create_v2_schema
from secminiagent.memory.state_auth import StateAuthenticator
from secminiagent.memory.store_v2 import SQLiteV2Store
from secminiagent.memory.thread_run_service import ThreadRunService
from secminiagent.memory.thread_run_store import ThreadRunStore
from secminiagent.memory.transcript_v2 import ThreadTranscriptService
from tests.memory.fixtures.schema_v1_factory import FixtureKeyProvider


def create_lifecycle_service(root: Path, *, workspace_id: str = "a" * 64, session_id: str = "session-a"):
    path = root / "memory-v2.db"
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA foreign_keys=ON")
    create_v2_schema(connection)
    connection.commit()
    connection.close()
    keys = FixtureKeyProvider(workspace_id)
    state_key = keys.derive_key(workspace_id, "state")[0]
    relation_key = keys.derive_key(workspace_id, "relation")[0]
    store = SQLiteV2Store(path, key_provider=keys, authenticator=StateAuthenticator(state_key, relation_key=relation_key), shadow=False)
    now = canonical_timestamp(datetime.now(timezone.utc))
    with store.connection(immediate=True) as connection:
        store.insert_session(connection, {
            "workspace_id": workspace_id, "session_id": session_id, "schema_version": 2,
            "status": "active", "revision": 1, "state_version": 1,
            "created_at": now, "updated_at": now, "deleted_at": None,
        })
    service = ThreadRunService(ThreadRunStore(store), id_key=keys.derive_key(workspace_id, "migration")[0])
    context = MemoryAccessContext(workspace_id, session_id, "test")
    return path, store, service, context


def create_transcript_service(root: Path, *, workspace_id: str = "a" * 64, session_id: str = "session-a"):
    path, store, lifecycle, context = create_lifecycle_service(root, workspace_id=workspace_id, session_id=session_id)
    keys = store.key_provider
    lifecycle_store = lifecycle.store
    transcript = ThreadTranscriptService(
        store, lifecycle, lifecycle_store,
        envelope_key=keys.derive_key(workspace_id, "provenance")[0],
    )
    return path, store, lifecycle, transcript, context


def create_note_summary_services(root: Path, *, generator=None):
    from secminiagent.memory.notes import NotesService
    from secminiagent.memory.summarizer import RollingSummaryService

    path, store, lifecycle, transcript, context = create_transcript_service(root)
    key = store.key_provider.derive_key(context.workspace_id, "provenance")[0]
    notes = NotesService(store, lifecycle.store, provenance_key=key)
    summaries = RollingSummaryService(
        store, lifecycle.store, transcript, provenance_key=key, generator=generator,
    )
    return path, store, lifecycle, transcript, notes, summaries, context


def create_long_term_service(root: Path, *, index=None):
    from secminiagent.memory.long_term_memory import LongTermMemoryService

    path, store, lifecycle, transcript, notes, summaries, context = create_note_summary_services(root)
    keys = store.key_provider
    service = LongTermMemoryService(
        store, lifecycle.store,
        provenance_key=keys.derive_key(context.workspace_id, "provenance")[0],
        promotion_key=keys.derive_key(context.workspace_id, "promotion")[0],
        index=index,
    )
    return path, store, lifecycle, transcript, service, context
