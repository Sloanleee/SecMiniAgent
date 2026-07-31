from __future__ import annotations

from pathlib import Path

from .crypto import AesGcmMemoryCipher
from .errors import MemoryDependencyUnavailable, MemorySchemaUnsupported
from .keys import DPAPIKeyProtector, WorkspaceKeyManager, load_existing_local_salt, load_or_create_local_salt
from .local_service import LocalMemoryService
from .models import MemoryAccessContext, derive_workspace_id
from .store import SQLiteMemoryStore
from .vector_index import ChromaMemoryIndex
from .migration import SchemaMigrator
from .schema import SchemaState, inspect_database_path
from .state_auth import StateAuthenticator
from .store_v2 import SQLiteV2Store
from .thread_run_service import ThreadRunService
from .thread_run_store import ThreadRunStore
from .transcript_v2 import ThreadTranscriptService
from .notes import NotesService
from .summarizer import RollingSummaryService
from .long_term_memory import LongTermMemoryService
from .search import HybridMemorySearch
from .candidate_extractor import ControlledCandidateService
from .retention import RetentionService
from .cascade_delete import CascadeDeletionService


def create_local_memory(
    cwd: Path,
    *,
    provider: str = "local",
    session_id: str | None = None,
    enable_chroma: bool = True,
) -> tuple[LocalMemoryService, MemoryAccessContext]:
    root = cwd.resolve() / ".secminiagent" / "memory"
    salt = load_or_create_local_salt(root / "workspace.salt")
    workspace_id = derive_workspace_id(cwd.resolve(), salt)
    protector = DPAPIKeyProtector(entropy=b"SecMiniAgent-memory-v1")
    keys = WorkspaceKeyManager(root / "keys", protector)
    cipher = AesGcmMemoryCipher(keys)
    store = SQLiteMemoryStore(root / "memory.db")
    index = None
    if enable_chroma:
        try:
            index = ChromaMemoryIndex(root / "chroma")
        except MemoryDependencyUnavailable:
            index = None
    service = LocalMemoryService(store=store, cipher=cipher, index=index)
    return service, MemoryAccessContext(workspace_id, session_id, provider)


def create_schema_migrator(cwd: Path) -> SchemaMigrator:
    """Construct a read-only migration facade without initializing workspace state."""

    cwd = cwd.resolve()
    root = cwd / ".secminiagent" / "memory"
    database_path = root / "memory.db"
    salt_path = root / "workspace.salt"
    if not database_path.is_file() or not salt_path.is_file():
        return SchemaMigrator(database_path)
    salt = load_existing_local_salt(salt_path)
    workspace_id = derive_workspace_id(cwd, salt)
    protector = DPAPIKeyProtector(entropy=b"SecMiniAgent-memory-v1")
    keys = WorkspaceKeyManager(root / "keys", protector, create=False)
    return SchemaMigrator(database_path, key_provider=keys, workspace_id=workspace_id)


def create_thread_run_runtime(
    cwd: Path, *, session_id: str, thread_id: str | None = None, provider: str = "local",
) -> tuple[ThreadRunService, MemoryAccessContext]:
    """Open an already-activated v2 database without creating workspace state."""

    cwd = cwd.resolve()
    root = cwd / ".secminiagent" / "memory"
    database_path = root / "memory.db"
    salt_path = root / "workspace.salt"
    if inspect_database_path(database_path).state is not SchemaState.V2:
        raise MemorySchemaUnsupported("M7_THREAD_RUNTIME_REQUIRES_SCHEMA_V2")
    salt = load_existing_local_salt(salt_path)
    workspace_id = derive_workspace_id(cwd, salt)
    protector = DPAPIKeyProtector(entropy=b"SecMiniAgent-memory-v1")
    keys = WorkspaceKeyManager(root / "keys", protector, create=False)
    state_key = keys.derive_key(workspace_id, "state")[0]
    relation_key = keys.derive_key(workspace_id, "relation")[0]
    id_key = keys.derive_key(workspace_id, "migration")[0]
    store = SQLiteV2Store(
        database_path, key_provider=keys,
        authenticator=StateAuthenticator(state_key, relation_key=relation_key), shadow=False,
    )
    service = ThreadRunService(ThreadRunStore(store), id_key=id_key)
    return service, MemoryAccessContext(workspace_id, session_id, provider, thread_id=thread_id)


def create_thread_transcript_runtime(
    cwd: Path, *, session_id: str, thread_id: str | None = None, provider: str = "local",
) -> tuple[ThreadRunService, ThreadTranscriptService, MemoryAccessContext]:
    lifecycle, context = create_thread_run_runtime(
        cwd, session_id=session_id, thread_id=thread_id, provider=provider,
    )
    store = lifecycle.store.store
    envelope_key = store.key_provider.derive_key(context.workspace_id, "provenance")[0]
    transcript = ThreadTranscriptService(
        store, lifecycle, lifecycle.store, envelope_key=envelope_key,
    )
    return lifecycle, transcript, context


def create_note_summary_runtime(
    cwd: Path, *, session_id: str, thread_id: str | None = None, provider: str = "local",
) -> tuple[ThreadRunService, ThreadTranscriptService, NotesService, RollingSummaryService, MemoryAccessContext]:
    lifecycle, transcript, context = create_thread_transcript_runtime(
        cwd, session_id=session_id, thread_id=thread_id, provider=provider,
    )
    store = lifecycle.store.store
    key = store.key_provider.derive_key(context.workspace_id, "provenance")[0]
    notes = NotesService(store, lifecycle.store, provenance_key=key)
    summaries = RollingSummaryService(store, lifecycle.store, transcript, provenance_key=key)
    return lifecycle, transcript, notes, summaries, context


def create_long_term_runtime(
    cwd: Path, *, session_id: str, thread_id: str | None = None,
    provider: str = "local", enable_chroma: bool = True,
) -> tuple[LongTermMemoryService, MemoryAccessContext]:
    lifecycle, _transcript, _notes, _summaries, context = create_note_summary_runtime(
        cwd, session_id=session_id, thread_id=thread_id, provider=provider,
    )
    store = lifecycle.store.store
    index = None
    if enable_chroma:
        try:
            index = ChromaMemoryIndex(cwd.resolve() / ".secminiagent" / "memory" / "chroma")
        except MemoryDependencyUnavailable:
            index = None
    service = LongTermMemoryService(
        store, lifecycle.store,
        provenance_key=store.key_provider.derive_key(context.workspace_id, "provenance")[0],
        promotion_key=store.key_provider.derive_key(context.workspace_id, "promotion")[0],
        index=index,
    )
    return service, context


def create_advanced_memory_runtime(
    cwd: Path, *, session_id: str, thread_id: str | None = None,
    provider: str = "local", enable_chroma: bool = True,
) -> tuple[LongTermMemoryService, HybridMemorySearch, ControlledCandidateService, MemoryAccessContext]:
    long_term, context = create_long_term_runtime(
        cwd, session_id=session_id, thread_id=thread_id,
        provider=provider, enable_chroma=enable_chroma,
    )
    search = HybridMemorySearch(long_term.store, long_term.lifecycle_store, index=long_term.index)
    candidates = ControlledCandidateService(
        long_term,
        dedup_key=long_term.store.key_provider.derive_key(context.workspace_id, "dedup")[0],
    )
    return long_term, search, candidates, context


def create_retention_deletion_runtime(
    cwd: Path, *, session_id: str, thread_id: str | None = None,
    provider: str = "local", enable_chroma: bool = True,
) -> tuple[LongTermMemoryService, RetentionService, CascadeDeletionService, MemoryAccessContext]:
    long_term, context = create_long_term_runtime(
        cwd, session_id=session_id, thread_id=thread_id,
        provider=provider, enable_chroma=enable_chroma,
    )
    retention = RetentionService(long_term.store)
    deletion = CascadeDeletionService(
        long_term,
        deletion_key=long_term.store.key_provider.derive_key(context.workspace_id, "deletion")[0],
        index=long_term.index,
    )
    return long_term, retention, deletion, context
