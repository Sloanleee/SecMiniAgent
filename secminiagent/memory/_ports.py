"""Internal dependency ports for the memory service.

These protocols freeze M0 boundaries. They are deliberately not re-exported
from ``secminiagent.memory``; application code must use ``MemoryService``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Sequence

from .models import (
    DetectionSignal,
    MemoryAccessContext,
    MemoryCandidate,
    MemoryMetadata,
    MemoryQuery,
    PolicyDecision,
)


@dataclass(frozen=True, slots=True)
class EncryptedPayload:
    ciphertext: bytes
    nonce: bytes
    key_version: int
    algorithm: str


class SensitiveDataDetector(Protocol):
    def detect(self, candidate: MemoryCandidate) -> Sequence[DetectionSignal]: ...


class SemanticDetector(Protocol):
    """Optional local-only semantic detector introduced after the M1 baseline."""

    def detect(self, candidate: MemoryCandidate) -> Sequence[DetectionSignal]: ...


class MemoryPolicyEngine(Protocol):
    def decide(
        self,
        candidate: MemoryCandidate,
        signals: Sequence[DetectionSignal],
        context: MemoryAccessContext,
    ) -> PolicyDecision: ...


class MemoryCipher(Protocol):
    def encrypt(self, plaintext: bytes, *, aad: bytes, workspace_id: str) -> EncryptedPayload: ...

    def decrypt(self, payload: EncryptedPayload, *, aad: bytes, workspace_id: str) -> bytes: ...


class PurposeKeyProvider(Protocol):
    """Internal v2-only purpose-separated key access."""

    def get_existing_key(self, workspace_id: str) -> tuple[bytes, int]: ...

    def derive_key(self, workspace_id: str, purpose: str, *, create: bool = False) -> tuple[bytes, int]: ...


class V2MemoryCipher(Protocol):
    def encrypt_memory(self, plaintext: bytes, metadata: MemoryMetadata) -> EncryptedPayload: ...

    def decrypt_memory(self, payload: EncryptedPayload, metadata: MemoryMetadata) -> bytes: ...


class KeyProtector(Protocol):
    def protect(self, plaintext: bytes) -> bytes: ...

    def unprotect(self, ciphertext: bytes) -> bytes: ...


class AuthoritativeMemoryStore(Protocol):
    """Ciphertext and lifecycle store; never returns plaintext."""

    def insert(self, metadata: MemoryMetadata, payload: EncryptedPayload) -> None: ...

    def fetch(self, memory_id: str, context: MemoryAccessContext) -> tuple[MemoryMetadata, EncryptedPayload] | None: ...

    def list_metadata(self, query: MemoryQuery, context: MemoryAccessContext) -> Sequence[MemoryMetadata]: ...

    def mark_pending_delete(self, memory_id: str, context: MemoryAccessContext) -> MemoryMetadata: ...

    def purge_ciphertext(self, memory_id: str, context: MemoryAccessContext) -> None: ...


class DerivedMemoryIndex(Protocol):
    """A rebuildable, redacted candidate index; never an authority."""

    def index(self, metadata: MemoryMetadata, redacted_text: str) -> None: ...

    def candidate_ids(self, query: MemoryQuery, context: MemoryAccessContext) -> Sequence[str]: ...

    def delete(self, memory_id: str, context: MemoryAccessContext) -> None: ...


class MemoryAuditSink(Protocol):
    def record(
        self,
        *,
        action: str,
        outcome: str,
        workspace_id: str,
        memory_id_hash: str | None,
        reason_code: str,
    ) -> None: ...
