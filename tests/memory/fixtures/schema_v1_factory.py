from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from secminiagent.memory.crypto import ALGORITHM, build_memory_aad_v1
from secminiagent.memory.models import (
    IndexStatus,
    MemoryAction,
    MemoryClassification,
    MemoryMetadata,
    MemoryScope,
    MemoryType,
)


V1_DDL = """
CREATE TABLE memories (
 id TEXT PRIMARY KEY, schema_version INTEGER NOT NULL, workspace_id TEXT NOT NULL, session_id TEXT,
 scope TEXT NOT NULL, memory_type TEXT NOT NULL, classification TEXT NOT NULL, source_type TEXT NOT NULL,
 policy_action TEXT NOT NULL, policy_reason_codes TEXT NOT NULL, key_version INTEGER NOT NULL,
 algorithm TEXT NOT NULL, ciphertext BLOB NOT NULL, nonce BLOB NOT NULL, index_status TEXT NOT NULL,
 sequence_no INTEGER, created_at TEXT NOT NULL, expires_at TEXT, deleted_at TEXT
);
CREATE INDEX idx_memories_workspace ON memories(workspace_id,deleted_at,created_at);
CREATE INDEX idx_memories_session ON memories(workspace_id,session_id,deleted_at,sequence_no);
CREATE TABLE memory_audit (
 event_id TEXT PRIMARY KEY, action TEXT NOT NULL, outcome TEXT NOT NULL, workspace_id TEXT NOT NULL,
 memory_id_hash TEXT, reason_code TEXT NOT NULL, created_at TEXT NOT NULL
);
PRAGMA user_version=1;
"""


class FixtureKeyProvider:
    def __init__(self, workspace_id: str) -> None:
        self.workspace_id = workspace_id
        self._key = sha256(f"fixture-key:{workspace_id}".encode()).digest()

    def get_key(self, workspace_id: str) -> tuple[bytes, int]:
        return self.get_existing_key(workspace_id)

    def get_existing_key(self, workspace_id: str) -> tuple[bytes, int]:
        if workspace_id != self.workspace_id:
            raise ValueError("unknown fixture workspace")
        return self._key, 1

    def derive_key(self, workspace_id: str, purpose: str, *, create: bool = False) -> tuple[bytes, int]:
        key, version = self.get_existing_key(workspace_id)
        return (
            HKDF(
                algorithm=hashes.SHA256(), length=32, salt=bytes.fromhex(workspace_id),
                info=f"secminiagent.memory.{purpose}.v1:key-version={version}".encode("ascii"),
            ).derive(key),
            version,
        )


@dataclass(frozen=True, slots=True)
class SchemaV1Fixture:
    root: Path
    database_path: Path
    workspace_id: str
    session_id: str
    expected_message_order: tuple[str, ...]
    expected_tool_pairs: tuple[tuple[str, str], ...]
    expected_workspace_ids: tuple[str, ...]
    key_provider: FixtureKeyProvider


def create_schema_v1_fixture(root: Path) -> SchemaV1Fixture:
    root = root.resolve()
    database_path = root / "memory.db"
    workspace_id = "a" * 64
    session_id = "fixture-session"
    provider = FixtureKeyProvider(workspace_id)
    connection = sqlite3.connect(database_path)
    connection.executescript(V1_DDL)
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    messages = (
        {"role": "user", "content": "synthetic first request"},
        {"role": "assistant", "content": None, "tool_calls": [{"id": "call-1", "type": "function", "function": {"name": "read_file", "arguments": "{\"file_path\":\"README.md\"}"}}]},
        {"role": "tool", "tool_call_id": "call-1", "content": "synthetic tool output"},
        {"role": "assistant", "content": "synthetic first answer"},
        {"role": "user", "content": "synthetic second request"},
        {"role": "assistant", "content": "synthetic second answer"},
    )
    rows: list[tuple[str, MemoryScope, MemoryType, str, dict[str, object], int | None]] = [
        ("session-meta", MemoryScope.SESSION, MemoryType.SESSION_META, json.dumps({"session_id": session_id}), {"event_type": "meta", "_sequence_no": 0}, 0),
    ]
    for index, message in enumerate(messages, 1):
        rows.append((f"message-{index}", MemoryScope.SESSION, MemoryType.MESSAGE, json.dumps(message, separators=(",", ":")), {"event_type": "message", "_sequence_no": index}, index))
    rows.extend(
        (
            ("workspace-fact", MemoryScope.WORKSPACE, MemoryType.PROJECT_FACT, "synthetic project fact", {}, None),
            ("workspace-finding", MemoryScope.WORKSPACE, MemoryType.SECURITY_FINDING, "synthetic security finding", {}, None),
            ("workspace-note", MemoryScope.WORKSPACE, MemoryType.USER_NOTE, "synthetic user note", {}, None),
        )
    )
    for offset, (memory_id, scope, memory_type, content, attributes, sequence) in enumerate(rows):
        created = base + timedelta(seconds=offset)
        metadata = MemoryMetadata(
            id=memory_id, workspace_id=workspace_id, session_id=session_id if scope is MemoryScope.SESSION else None,
            scope=scope, memory_type=memory_type, classification=MemoryClassification.INTERNAL,
            source_type="fixture", policy_action=MemoryAction.ALLOW,
            policy_reason_codes=("FIXTURE_ALLOW",), index_status=IndexStatus.NOT_INDEXED,
            sequence_no=sequence, created_at=created,
        )
        plaintext = json.dumps({"content": content, "attributes": attributes}, ensure_ascii=False, separators=(",", ":")).encode()
        key, version = provider.get_key(workspace_id)
        nonce = os.urandom(12)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, build_memory_aad_v1(metadata))
        connection.execute(
            "INSERT INTO memories VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                memory_id, 1, workspace_id, metadata.session_id, scope.value, memory_type.value,
                metadata.classification.value, metadata.source_type, metadata.policy_action.value,
                "|".join(metadata.policy_reason_codes), version, ALGORITHM, ciphertext, nonce,
                metadata.index_status.value, sequence, created.isoformat(), None, None,
            ),
        )
    connection.commit()
    connection.close()
    return SchemaV1Fixture(
        root, database_path, workspace_id, session_id,
        tuple(str(message["content"]) for message in messages if message.get("content")),
        (("call-1", "call-1"),),
        ("workspace-fact", "workspace-finding", "workspace-note"),
        provider,
    )
