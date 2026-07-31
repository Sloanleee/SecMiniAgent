from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .errors import MemorySchemaUnsupported


SCHEMA_V1 = 1
SCHEMA_V2 = 2
V2_SHADOW_SUFFIX = "_v2"


class SchemaState(str, Enum):
    UNINITIALIZED = "uninitialized"
    V1 = "v1"
    MIGRATING = "migrating"
    V2 = "v2"
    NEWER = "newer"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class SchemaInspection:
    state: SchemaState
    user_version: int
    has_shadow: bool = False
    reason_code: str = "SCHEMA_OK"


@dataclass(frozen=True, slots=True)
class SchemaValidation:
    valid: bool
    missing_tables: tuple[str, ...] = ()
    missing_indexes: tuple[str, ...] = ()
    foreign_key_issues: tuple[tuple[object, ...], ...] = ()


TABLES = (
    "sessions",
    "threads",
    "runs",
    "memories",
    "memory_relations",
    "deletion_jobs",
    "deletion_items",
    "migration_journal",
)

INDEXES = (
    "ux_runs_one_running",
    "ux_memories_thread_sequence",
    "ux_memories_run_sequence",
    "ux_memories_one_active_summary",
    "idx_memories_thread_recall",
    "idx_memories_workspace_recall",
    "idx_relations_source",
    "idx_relations_target",
)


def _table(name: str, shadow: bool) -> str:
    return f"{name}{V2_SHADOW_SUFFIX}" if shadow else name


def _index(name: str, shadow: bool) -> str:
    return f"{name}{V2_SHADOW_SUFFIX}" if shadow else name


def build_v2_ddl(*, shadow: bool = False) -> str:
    s, t, r, m, rel, dj, di, journal = (_table(name, shadow) for name in TABLES)
    i = {name: _index(name, shadow) for name in INDEXES}
    return f"""
CREATE TABLE {s} (
 workspace_id TEXT NOT NULL, session_id TEXT NOT NULL,
 schema_version INTEGER NOT NULL CHECK(schema_version=2),
 status TEXT NOT NULL CHECK(status IN ('active','deleting','deleted')),
 revision INTEGER NOT NULL CHECK(revision>=1), state_version INTEGER NOT NULL CHECK(state_version>=1),
 state_mac BLOB NOT NULL, key_version INTEGER NOT NULL CHECK(key_version>=1), algorithm TEXT NOT NULL,
 ciphertext BLOB NOT NULL, nonce BLOB NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 deleted_at TEXT, PRIMARY KEY(workspace_id,session_id)
);
CREATE TABLE {t} (
 workspace_id TEXT NOT NULL, session_id TEXT NOT NULL, thread_id TEXT NOT NULL,
 schema_version INTEGER NOT NULL CHECK(schema_version=2),
 status TEXT NOT NULL CHECK(status IN ('active','archived','deleting','deleted')),
 revision INTEGER NOT NULL CHECK(revision>=1), next_run_no INTEGER NOT NULL DEFAULT 1 CHECK(next_run_no>=1),
 next_thread_sequence INTEGER NOT NULL DEFAULT 1 CHECK(next_thread_sequence>=1),
 state_version INTEGER NOT NULL CHECK(state_version>=1), state_mac BLOB NOT NULL,
 key_version INTEGER NOT NULL CHECK(key_version>=1), algorithm TEXT NOT NULL, ciphertext BLOB NOT NULL,
 nonce BLOB NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, deleted_at TEXT,
 PRIMARY KEY(workspace_id,session_id,thread_id),
 FOREIGN KEY(workspace_id,session_id) REFERENCES {s}(workspace_id,session_id) ON DELETE RESTRICT
);
CREATE TABLE {r} (
 workspace_id TEXT NOT NULL, session_id TEXT NOT NULL, thread_id TEXT NOT NULL, run_id TEXT NOT NULL,
 run_no INTEGER NOT NULL CHECK(run_no>=1),
 status TEXT NOT NULL CHECK(status IN ('running','completed','failed','interrupted','deleting','deleted')),
 next_run_sequence INTEGER NOT NULL DEFAULT 1 CHECK(next_run_sequence>=1),
 state_version INTEGER NOT NULL CHECK(state_version>=1), state_mac BLOB NOT NULL,
 input_message_id TEXT, final_message_id TEXT, turn_count INTEGER NOT NULL DEFAULT 0 CHECK(turn_count>=0),
 started_at TEXT NOT NULL, completed_at TEXT, interruption_reason_code TEXT,
 migration_origin TEXT CHECK(migration_origin IS NULL OR migration_origin IN ('legacy_inferred','legacy_unassigned')),
 deleted_at TEXT, PRIMARY KEY(workspace_id,session_id,thread_id,run_id),
 UNIQUE(workspace_id,session_id,thread_id,run_no),
 FOREIGN KEY(workspace_id,session_id,thread_id) REFERENCES {t}(workspace_id,session_id,thread_id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX {i['ux_runs_one_running']} ON {r}(workspace_id,session_id,thread_id)
 WHERE status='running' AND deleted_at IS NULL;
CREATE TABLE {m} (
 id TEXT PRIMARY KEY, schema_version INTEGER NOT NULL CHECK(schema_version=2), workspace_id TEXT NOT NULL,
 session_id TEXT, thread_id TEXT, run_id TEXT,
 scope TEXT NOT NULL CHECK(scope IN ('thread','session','workspace')), memory_type TEXT NOT NULL, note_kind TEXT,
 classification TEXT NOT NULL CHECK(classification IN ('public','internal','confidential','secret')),
 verification_status TEXT NOT NULL CHECK(verification_status IN ('unknown','model_inferred','tool_verified','user_confirmed')),
 lifecycle_status TEXT NOT NULL CHECK(lifecycle_status IN ('candidate','active','rejected','resolved','superseded','disputed','retracted','expired','pending_rebuild','pending_delete','deleted')),
 source_type TEXT NOT NULL, policy_action TEXT NOT NULL, policy_reason_codes_json TEXT NOT NULL,
 record_revision INTEGER NOT NULL CHECK(record_revision>=1), provenance_digest BLOB NOT NULL, dedup_fingerprint BLOB,
 importance_millis INTEGER NOT NULL DEFAULT 500 CHECK(importance_millis BETWEEN 0 AND 1000),
 key_version INTEGER NOT NULL CHECK(key_version>=1), algorithm TEXT NOT NULL, ciphertext BLOB NOT NULL,
 nonce BLOB NOT NULL, index_status TEXT NOT NULL, thread_sequence INTEGER, run_sequence INTEGER,
 state_version INTEGER NOT NULL CHECK(state_version>=1), state_mac BLOB NOT NULL,
 retention_policy_id TEXT, pinned INTEGER NOT NULL DEFAULT 0 CHECK(pinned IN (0,1)),
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL, expires_at TEXT, last_recalled_at TEXT,
 last_validated_at TEXT, deleted_at TEXT, UNIQUE(workspace_id,id),
 FOREIGN KEY(workspace_id,session_id) REFERENCES {s}(workspace_id,session_id) ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,session_id,thread_id) REFERENCES {t}(workspace_id,session_id,thread_id) ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,session_id,thread_id,run_id) REFERENCES {r}(workspace_id,session_id,thread_id,run_id) ON DELETE RESTRICT,
 CHECK((scope='thread' AND session_id IS NOT NULL AND thread_id IS NOT NULL AND thread_sequence IS NOT NULL)
    OR (scope='session' AND session_id IS NOT NULL AND thread_id IS NULL AND run_id IS NULL AND thread_sequence IS NULL AND run_sequence IS NULL)
    OR (scope='workspace' AND session_id IS NULL AND thread_id IS NULL AND run_id IS NULL AND thread_sequence IS NULL AND run_sequence IS NULL)),
 CHECK((run_id IS NULL AND run_sequence IS NULL) OR (run_id IS NOT NULL AND run_sequence IS NOT NULL)),
 CHECK(memory_type NOT IN ('message','tool_result') OR (scope='thread' AND run_id IS NOT NULL))
);
CREATE UNIQUE INDEX {i['ux_memories_thread_sequence']} ON {m}(workspace_id,session_id,thread_id,thread_sequence) WHERE scope='thread';
CREATE UNIQUE INDEX {i['ux_memories_run_sequence']} ON {m}(workspace_id,session_id,thread_id,run_id,run_sequence) WHERE run_id IS NOT NULL;
CREATE UNIQUE INDEX {i['ux_memories_one_active_summary']} ON {m}(workspace_id,session_id,thread_id)
 WHERE memory_type='thread_summary' AND lifecycle_status='active' AND deleted_at IS NULL;
CREATE INDEX {i['idx_memories_thread_recall']} ON {m}(workspace_id,session_id,thread_id,lifecycle_status,expires_at,thread_sequence);
CREATE INDEX {i['idx_memories_workspace_recall']} ON {m}(workspace_id,scope,memory_type,lifecycle_status,expires_at,created_at);
CREATE TABLE {rel} (
 relation_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, source_memory_id TEXT NOT NULL,
 target_memory_id TEXT NOT NULL,
 relation_type TEXT NOT NULL CHECK(relation_type IN ('derived_from','summarizes','supersedes','conflicts_with','promoted_from','supports')),
 state_version INTEGER NOT NULL CHECK(state_version>=1), relation_mac BLOB NOT NULL, created_at TEXT NOT NULL,
 deleted_at TEXT, UNIQUE(workspace_id,source_memory_id,target_memory_id,relation_type),
 FOREIGN KEY(workspace_id,source_memory_id) REFERENCES {m}(workspace_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,target_memory_id) REFERENCES {m}(workspace_id,id) ON DELETE RESTRICT
);
CREATE INDEX {i['idx_relations_source']} ON {rel}(workspace_id,source_memory_id,relation_type);
CREATE INDEX {i['idx_relations_target']} ON {rel}(workspace_id,target_memory_id,relation_type);
CREATE TABLE {dj} (
 job_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, root_type TEXT NOT NULL, root_id TEXT NOT NULL,
 status TEXT NOT NULL, reason_code TEXT NOT NULL, state_version INTEGER NOT NULL CHECK(state_version>=1),
 state_mac BLOB NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE {di} (
 job_id TEXT NOT NULL, target_type TEXT NOT NULL, target_id TEXT NOT NULL, phase TEXT NOT NULL,
 outcome TEXT NOT NULL, selected_action TEXT NOT NULL, target_revision INTEGER,
 confirmation_receipt_hash TEXT, independent_record_id TEXT, last_error_code TEXT,
 state_version INTEGER NOT NULL CHECK(state_version>=1), state_mac BLOB NOT NULL, updated_at TEXT NOT NULL,
 PRIMARY KEY(job_id,target_type,target_id), FOREIGN KEY(job_id) REFERENCES {dj}(job_id) ON DELETE CASCADE
);
CREATE TABLE {journal} (
 journal_entry_id TEXT PRIMARY KEY, migration_id TEXT NOT NULL, from_version INTEGER NOT NULL,
 to_version INTEGER NOT NULL, phase TEXT NOT NULL, source_record_id_hash TEXT NOT NULL DEFAULT '',
 target_record_id_hash TEXT NOT NULL DEFAULT '', outcome TEXT NOT NULL,
 state_version INTEGER NOT NULL CHECK(state_version>=1), state_mac BLOB NOT NULL,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 UNIQUE(migration_id,phase,source_record_id_hash,target_record_id_hash)
);
"""


V2_DDL = build_v2_ddl(shadow=False)
V2_SHADOW_DDL = build_v2_ddl(shadow=True)


def inspect_schema(connection: sqlite3.Connection) -> SchemaInspection:
    version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    names = {str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    has_shadow = _table("sessions", True) in names
    if version > SCHEMA_V2:
        return SchemaInspection(SchemaState.NEWER, version, has_shadow, "SCHEMA_NEWER_THAN_SUPPORTED")
    if version == SCHEMA_V2:
        return SchemaInspection(SchemaState.V2, version, has_shadow)
    if version == SCHEMA_V1:
        return SchemaInspection(SchemaState.MIGRATING if has_shadow else SchemaState.V1, version, has_shadow)
    if version == 0 and not names:
        return SchemaInspection(SchemaState.UNINITIALIZED, 0, False, "SCHEMA_UNINITIALIZED")
    return SchemaInspection(SchemaState.UNKNOWN, version, has_shadow, "SCHEMA_UNRECOGNIZED")


def inspect_database_path(path: Path) -> SchemaInspection:
    if not path.is_file():
        return SchemaInspection(SchemaState.UNINITIALIZED, 0, False, "SCHEMA_UNINITIALIZED")
    uri = f"file:{path.resolve().as_posix()}?mode=ro"
    connection = sqlite3.connect(uri, uri=True)
    try:
        return inspect_schema(connection)
    finally:
        connection.close()


def create_v2_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(V2_DDL)
    connection.execute(
        """CREATE TABLE IF NOT EXISTS memory_audit (
        event_id TEXT PRIMARY KEY, action TEXT NOT NULL, outcome TEXT NOT NULL,
        workspace_id TEXT NOT NULL, memory_id_hash TEXT, reason_code TEXT NOT NULL,
        created_at TEXT NOT NULL)"""
    )
    connection.execute(f"PRAGMA user_version={SCHEMA_V2}")


def create_v2_shadow(connection: sqlite3.Connection) -> None:
    inspection = inspect_schema(connection)
    if inspection.user_version != SCHEMA_V1:
        raise MemorySchemaUnsupported("v2 shadow requires a schema v1 authority")
    if not inspection.has_shadow:
        connection.executescript(V2_SHADOW_DDL)


def drop_unactivated_shadow(connection: sqlite3.Connection) -> None:
    if int(connection.execute("PRAGMA user_version").fetchone()[0]) != SCHEMA_V1:
        raise MemorySchemaUnsupported("activated v2 schema cannot be dropped as shadow")
    connection.execute("PRAGMA foreign_keys=OFF")
    try:
        for name in reversed(TABLES):
            connection.execute(f"DROP TABLE IF EXISTS {_table(name, True)}")
    finally:
        connection.execute("PRAGMA foreign_keys=ON")


def validate_v2_structure(connection: sqlite3.Connection, *, shadow: bool = False) -> SchemaValidation:
    names = {str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    indexes = {str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    missing_tables = tuple(_table(name, shadow) for name in TABLES if _table(name, shadow) not in names)
    missing_indexes = tuple(_index(name, shadow) for name in INDEXES if _index(name, shadow) not in indexes)
    foreign_key_issues = tuple(tuple(row) for row in connection.execute("PRAGMA foreign_key_check"))
    return SchemaValidation(not missing_tables and not missing_indexes and not foreign_key_issues, missing_tables, missing_indexes, foreign_key_issues)


def require_supported_runtime(connection: sqlite3.Connection, *, allow_v2: bool = False) -> SchemaInspection:
    inspection = inspect_schema(connection)
    if inspection.state is SchemaState.NEWER:
        raise MemorySchemaUnsupported("memory database schema is newer than supported")
    if inspection.state is SchemaState.V2 and not allow_v2:
        raise MemorySchemaUnsupported("schema v2 runtime is not enabled")
    if inspection.state is SchemaState.UNKNOWN:
        raise MemorySchemaUnsupported("memory database schema is unrecognized")
    return inspection
