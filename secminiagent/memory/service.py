from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Sequence

from .errors import MemoryValidationError
from .models import MemoryAccessContext, MemoryCandidate, MemoryMetadata, MemoryQuery, MemoryRecord


@dataclass(frozen=True, slots=True)
class DeletionReceipt:
    memory_id: str
    requested_at: datetime
    authoritative_access_revoked: bool
    derived_index_deleted: bool
    cleanup_pending: bool
    audit_event_id: str

    def __post_init__(self) -> None:
        if not self.memory_id.strip():
            raise MemoryValidationError("memory_id must not be empty")
        if not self.audit_event_id.strip():
            raise MemoryValidationError("audit_event_id must not be empty")
        if not self.authoritative_access_revoked:
            raise MemoryValidationError("a deletion receipt requires authoritative access revocation")
        if not self.derived_index_deleted and not self.cleanup_pending:
            raise MemoryValidationError("failed derived-index deletion must remain pending")


class MemoryService(ABC):
    """The sole public boundary for memory content and lifecycle operations.

    Implementations introduced in later milestones compose internal detector,
    policy, crypto, store, index, and audit ports. No consumer may bypass this
    service to access plaintext memory.
    """

    @abstractmethod
    def remember(self, candidate: MemoryCandidate, context: MemoryAccessContext) -> MemoryMetadata:
        """Evaluate policy and persist an allowed candidate."""

    @abstractmethod
    def recall(self, memory_id: str, context: MemoryAccessContext) -> MemoryRecord:
        """Return one authorized, live, policy-approved plaintext record."""

    @abstractmethod
    def list_metadata(self, query: MemoryQuery, context: MemoryAccessContext) -> Sequence[MemoryMetadata]:
        """List safe metadata without decrypting memory content."""

    @abstractmethod
    def search(self, query: MemoryQuery, context: MemoryAccessContext) -> Sequence[MemoryRecord]:
        """Search within scope and return only records approved for disclosure."""

    @abstractmethod
    def forget(self, memory_id: str, context: MemoryAccessContext) -> DeletionReceipt:
        """Revoke authoritative access first, then remove derived and encrypted data."""

    @abstractmethod
    def clear_session(self, context: MemoryAccessContext) -> Sequence[DeletionReceipt]:
        """Delete all accessible memories for the context's current session."""

    @abstractmethod
    def clear_workspace(self, context: MemoryAccessContext) -> Sequence[DeletionReceipt]:
        """Delete all accessible memories for the current workspace."""
