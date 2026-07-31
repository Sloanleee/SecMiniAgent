from __future__ import annotations

import hmac
import os
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

from .errors import MemoryAccessDenied, MemoryValidationError


class MemoryScope(str, Enum):
    THREAD = "thread"
    SESSION = "session"
    WORKSPACE = "workspace"


class MemoryClassification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"


class MemoryAction(str, Enum):
    ALLOW = "allow"
    REDACT = "redact"
    SESSION_ONLY = "session_only"
    REQUIRE_CONFIRMATION = "require_confirmation"
    DENY = "deny"


class MemoryType(str, Enum):
    SESSION_META = "session_meta"
    MESSAGE = "message"
    TOOL_RESULT = "tool_result"
    SESSION_SUMMARY = "session_summary"
    SECURITY_FINDING = "security_finding"
    PROJECT_FACT = "project_fact"
    USER_NOTE = "user_note"
    THREAD_SUMMARY = "thread_summary"


class NoteKind(str, Enum):
    GOAL = "goal"
    FACT = "fact"
    DECISION = "decision"
    FINDING = "finding"
    TODO = "todo"
    QUESTION = "question"
    CONSTRAINT = "constraint"


class SessionStatus(str, Enum):
    ACTIVE = "active"
    DELETING = "deleting"
    DELETED = "deleted"


class ThreadStatus(str, Enum):
    ACTIVE = "active"
    ARCHIVED = "archived"
    DELETING = "deleting"
    DELETED = "deleted"


class RunStatus(str, Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    INTERRUPTED = "interrupted"
    DELETING = "deleting"
    DELETED = "deleted"


class NoteStatus(str, Enum):
    CANDIDATE = "candidate"
    ACTIVE = "active"
    REJECTED = "rejected"
    RESOLVED = "resolved"
    SUPERSEDED = "superseded"
    DISPUTED = "disputed"
    RETRACTED = "retracted"
    EXPIRED = "expired"
    PENDING_REBUILD = "pending_rebuild"
    PENDING_DELETE = "pending_delete"
    DELETED = "deleted"


class VerificationStatus(str, Enum):
    UNKNOWN = "unknown"
    MODEL_INFERRED = "model_inferred"
    TOOL_VERIFIED = "tool_verified"
    USER_CONFIRMED = "user_confirmed"


class MemoryRelationType(str, Enum):
    DERIVED_FROM = "derived_from"
    SUMMARIZES = "summarizes"
    SUPERSEDES = "supersedes"
    CONFLICTS_WITH = "conflicts_with"
    PROMOTED_FROM = "promoted_from"
    SUPPORTS = "supports"


class IndexStatus(str, Enum):
    NOT_INDEXED = "not_indexed"
    PENDING_INDEX = "pending_index"
    INDEXED = "indexed"
    PENDING_DELETE = "pending_delete"
    INDEX_FAILED = "index_failed"


def _require_text(value: str, field_name: str) -> None:
    if not value or not value.strip():
        raise MemoryValidationError(f"{field_name} must not be empty")


def _require_unit_interval(value: float, field_name: str) -> None:
    if not 0.0 <= value <= 1.0:
        raise MemoryValidationError(f"{field_name} must be between 0 and 1")


@dataclass(frozen=True, slots=True)
class MemoryAccessContext:
    workspace_id: str
    session_id: str | None
    provider: str
    thread_id: str | None = field(default=None, kw_only=True)

    def __post_init__(self) -> None:
        _require_text(self.workspace_id, "workspace_id")
        _require_text(self.provider, "provider")
        if self.session_id is not None:
            _require_text(self.session_id, "session_id")
        if self.thread_id is not None:
            _require_text(self.thread_id, "thread_id")
            if self.session_id is None:
                raise MemoryValidationError("thread_id requires session_id")


@dataclass(frozen=True, slots=True)
class MemorySource:
    source_type: str
    source_ref: str | None = None
    trust_level: str = "untrusted"
    is_test_data: bool = False
    user_confirmed: bool = False

    def __post_init__(self) -> None:
        _require_text(self.source_type, "source_type")
        _require_text(self.trust_level, "trust_level")


@dataclass(frozen=True, slots=True)
class DetectionSignal:
    detector: str
    category: str
    confidence: float
    severity: float
    reason_code: str
    evidence_span: tuple[int, int] | None = None

    def __post_init__(self) -> None:
        _require_text(self.detector, "detector")
        _require_text(self.category, "category")
        _require_text(self.reason_code, "reason_code")
        _require_unit_interval(self.confidence, "confidence")
        _require_unit_interval(self.severity, "severity")
        if self.evidence_span is not None:
            start, end = self.evidence_span
            if start < 0 or end <= start:
                raise MemoryValidationError("evidence_span must be a non-empty, non-negative range")


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    action: MemoryAction
    classification: MemoryClassification
    reason_codes: tuple[str, ...]
    explanation: str
    signals: tuple[DetectionSignal, ...] = ()
    target_scope: MemoryScope | None = None

    def __post_init__(self) -> None:
        if not self.reason_codes or any(not code.strip() for code in self.reason_codes):
            raise MemoryValidationError("policy decisions require non-empty reason_codes")
        _require_text(self.explanation, "explanation")
        if self.action is MemoryAction.SESSION_ONLY and self.target_scope not in {
            MemoryScope.THREAD,
            MemoryScope.SESSION,
        }:
            raise MemoryValidationError("SESSION_ONLY must explicitly target thread or session scope")
        if self.action in {MemoryAction.ALLOW, MemoryAction.REDACT} and self.target_scope is None:
            raise MemoryValidationError(f"{self.action.value} decisions require a target scope")
        if self.action in {MemoryAction.DENY, MemoryAction.REQUIRE_CONFIRMATION} and self.target_scope is not None:
            raise MemoryValidationError(f"{self.action.value} decisions cannot assign a target scope")


@dataclass(frozen=True, slots=True)
class MemoryCandidate:
    memory_type: MemoryType
    content: str = field(repr=False)
    requested_scope: MemoryScope = MemoryScope.SESSION
    source: MemorySource = field(default_factory=lambda: MemorySource("unknown"))
    attributes: Mapping[str, Any] = field(default_factory=dict, repr=False)
    expires_at: datetime | None = None

    def __post_init__(self) -> None:
        _require_text(self.content, "content")


@dataclass(frozen=True, slots=True)
class MemoryMetadata:
    id: str
    workspace_id: str
    session_id: str | None
    scope: MemoryScope
    memory_type: MemoryType
    classification: MemoryClassification
    source_type: str
    policy_action: MemoryAction
    policy_reason_codes: tuple[str, ...]
    index_status: IndexStatus
    created_at: datetime
    sequence_no: int | None = None
    expires_at: datetime | None = None
    deleted_at: datetime | None = None
    schema_version: int = 1
    thread_id: str | None = None
    run_id: str | None = None
    record_revision: int = 1
    thread_sequence: int | None = None
    run_sequence: int | None = None
    lifecycle_status: NoteStatus = NoteStatus.ACTIVE
    verification_status: VerificationStatus = VerificationStatus.UNKNOWN
    note_kind: str | None = None
    provenance_digest: bytes = b""
    state_version: int = 1
    updated_at: datetime | None = None
    retention_policy_id: str | None = None
    pinned: bool = False
    last_recalled_at: datetime | None = None
    last_validated_at: datetime | None = None

    def __post_init__(self) -> None:
        _require_text(self.id, "id")
        _require_text(self.workspace_id, "workspace_id")
        _require_text(self.source_type, "source_type")
        if not self.policy_reason_codes:
            raise MemoryValidationError("memory metadata requires policy reason codes")
        if self.schema_version not in {1, 2}:
            raise MemoryValidationError("unsupported memory metadata schema")
        if self.scope is MemoryScope.SESSION and self.session_id is None:
            raise MemoryValidationError("session-scoped memory requires session_id")
        if self.scope is MemoryScope.THREAD and (self.session_id is None or self.thread_id is None):
            raise MemoryValidationError("thread-scoped memory requires session_id and thread_id")
        if self.policy_action in {MemoryAction.DENY, MemoryAction.REQUIRE_CONFIRMATION}:
            raise MemoryValidationError(f"{self.policy_action.value} decisions cannot produce persisted metadata")
        if self.policy_action is MemoryAction.SESSION_ONLY and self.scope not in {
            MemoryScope.THREAD,
            MemoryScope.SESSION,
        }:
            raise MemoryValidationError("SESSION_ONLY metadata cannot use workspace scope")
        if self.sequence_no is not None and self.sequence_no < 0:
            raise MemoryValidationError("sequence_no must be non-negative")
        if self.record_revision < 1 or self.state_version < 1:
            raise MemoryValidationError("revision and state_version must be positive")
        if self.schema_version == 2:
            self._validate_v2_shape()

    def _validate_v2_shape(self) -> None:
        if self.scope is MemoryScope.WORKSPACE:
            if any(value is not None for value in (self.session_id, self.thread_id, self.run_id)):
                raise MemoryValidationError("workspace memory cannot have session/thread/run parents")
            if self.thread_sequence is not None or self.run_sequence is not None:
                raise MemoryValidationError("workspace memory cannot have thread/run sequence")
        elif self.scope is MemoryScope.SESSION:
            if self.thread_id is not None or self.run_id is not None:
                raise MemoryValidationError("session memory cannot have thread/run parents")
            if self.thread_sequence is not None or self.run_sequence is not None:
                raise MemoryValidationError("session memory cannot have thread/run sequence")
        else:
            if self.thread_sequence is None:
                raise MemoryValidationError("thread memory requires thread_sequence")
            if (self.run_id is None) != (self.run_sequence is None):
                raise MemoryValidationError("run_id and run_sequence must be supplied together")
        if self.memory_type in {MemoryType.MESSAGE, MemoryType.TOOL_RESULT}:
            if self.scope is not MemoryScope.THREAD or self.run_id is None or self.run_sequence is None:
                raise MemoryValidationError("message/tool_result requires a thread run")

    @property
    def is_live(self) -> bool:
        return self.deleted_at is None


@dataclass(frozen=True, slots=True)
class MemoryRecord:
    metadata: MemoryMetadata
    content: str = field(repr=False)
    attributes: Mapping[str, Any] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        _require_text(self.content, "content")


@dataclass(frozen=True, slots=True)
class MemoryQuery:
    text: str | None = field(default=None, repr=False)
    memory_types: tuple[MemoryType, ...] = ()
    classifications: tuple[MemoryClassification, ...] = ()
    limit: int = 20

    def __post_init__(self) -> None:
        if self.limit < 1 or self.limit > 10_000:
            raise MemoryValidationError("query limit must be between 1 and 10000")


def normalize_workspace_path(path: Path) -> str:
    """Return the platform-normalized absolute path used only for HMAC input."""

    resolved = path.expanduser().resolve()
    return os.path.normcase(os.path.normpath(str(resolved)))


def derive_workspace_id(path: Path, local_salt: bytes) -> str:
    """Derive a stable opaque workspace id without persisting the clear path."""

    if len(local_salt) < 16:
        raise MemoryValidationError("workspace-id salt must contain at least 16 bytes")
    normalized = normalize_workspace_path(path).encode("utf-8")
    return hmac.new(local_salt, normalized, sha256).hexdigest()


def enforce_scope_access(metadata: MemoryMetadata, context: MemoryAccessContext) -> None:
    """Fail closed unless the access context is authorized for this memory."""

    if not metadata.is_live:
        raise MemoryAccessDenied("deleted memories are not readable")
    if not hmac.compare_digest(metadata.workspace_id, context.workspace_id):
        raise MemoryAccessDenied("memory belongs to another workspace")
    if metadata.scope is MemoryScope.SESSION:
        if context.session_id is None or not hmac.compare_digest(metadata.session_id or "", context.session_id):
            raise MemoryAccessDenied("memory belongs to another session")
    if metadata.scope is MemoryScope.THREAD:
        if (
            context.session_id is None
            or context.thread_id is None
            or not hmac.compare_digest(metadata.session_id or "", context.session_id)
            or not hmac.compare_digest(metadata.thread_id or "", context.thread_id)
        ):
            raise MemoryAccessDenied("memory belongs to another thread")


@dataclass(frozen=True, slots=True)
class SessionMetadata:
    workspace_id: str
    session_id: str
    status: SessionStatus = SessionStatus.ACTIVE
    revision: int = 1
    state_version: int = 1

    def __post_init__(self) -> None:
        _require_text(self.workspace_id, "workspace_id")
        _require_text(self.session_id, "session_id")
        if self.revision < 1 or self.state_version < 1:
            raise MemoryValidationError("session revision and state_version must be positive")


@dataclass(frozen=True, slots=True)
class ThreadMetadata:
    workspace_id: str
    session_id: str
    thread_id: str
    status: ThreadStatus = ThreadStatus.ACTIVE
    revision: int = 1
    next_run_no: int = 1
    next_thread_sequence: int = 1
    state_version: int = 1
    created_at: datetime | None = None
    updated_at: datetime | None = None

    def __post_init__(self) -> None:
        _require_text(self.workspace_id, "workspace_id")
        _require_text(self.session_id, "session_id")
        _require_text(self.thread_id, "thread_id")
        if min(self.revision, self.next_run_no, self.next_thread_sequence, self.state_version) < 1:
            raise MemoryValidationError("thread counters and versions must be positive")


@dataclass(frozen=True, slots=True)
class RunMetadata:
    workspace_id: str
    session_id: str
    thread_id: str
    run_id: str
    run_no: int
    status: RunStatus
    next_run_sequence: int = 1
    state_version: int = 1
    input_message_id: str | None = None
    final_message_id: str | None = None
    turn_count: int = 0
    migration_origin: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    interruption_reason_code: str | None = None

    def __post_init__(self) -> None:
        for value, name in (
            (self.workspace_id, "workspace_id"), (self.session_id, "session_id"),
            (self.thread_id, "thread_id"), (self.run_id, "run_id"),
        ):
            _require_text(value, name)
        if min(self.run_no, self.next_run_sequence, self.state_version) < 1 or self.turn_count < 0:
            raise MemoryValidationError("run counters and versions are invalid")
        terminal = self.status in {RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.INTERRUPTED}
        if terminal and self.completed_at is None:
            raise MemoryValidationError("terminal run requires completed_at")
        if self.status is RunStatus.RUNNING and self.completed_at is not None:
            raise MemoryValidationError("running run cannot have completed_at")


@dataclass(frozen=True, slots=True)
class MessageEnvelope:
    message_id: str
    workspace_id: str
    session_id: str
    thread_id: str
    run_id: str
    thread_sequence: int
    run_sequence: int
    role: str
    memory_type: MemoryType
    created_at: datetime
    message: Mapping[str, Any] = field(repr=False)
    tool_call_ids: tuple[str, ...] = ()
    tool_result_call_id: str | None = None
    source_type: str = "transcript"
    classification: MemoryClassification = MemoryClassification.INTERNAL
    verification_status: VerificationStatus = VerificationStatus.UNKNOWN

    def __post_init__(self) -> None:
        for value, name in (
            (self.message_id, "message_id"), (self.workspace_id, "workspace_id"),
            (self.session_id, "session_id"), (self.thread_id, "thread_id"),
            (self.run_id, "run_id"), (self.role, "role"), (self.source_type, "source_type"),
        ):
            _require_text(value, name)
        if self.thread_sequence < 1 or self.run_sequence < 1:
            raise MemoryValidationError("message sequences must be positive")
        if self.role not in {"user", "assistant", "tool"}:
            raise MemoryValidationError("unsupported transcript role")
        if self.role == "tool" and not self.tool_result_call_id:
            raise MemoryValidationError("tool result requires tool_call_id")
        if self.role != "tool" and self.tool_result_call_id is not None:
            raise MemoryValidationError("only tool results may bind tool_result_call_id")
        if self.memory_type is MemoryType.TOOL_RESULT and self.role != "tool":
            raise MemoryValidationError("tool_result memory requires tool role")
        if self.role == "tool" and self.memory_type is not MemoryType.TOOL_RESULT:
            raise MemoryValidationError("tool role requires tool_result memory")


@dataclass(frozen=True, slots=True)
class StructuredNote:
    note_id: str
    workspace_id: str
    session_id: str | None
    thread_id: str | None
    kind: NoteKind
    content: str = field(repr=False)
    status: NoteStatus = NoteStatus.CANDIDATE
    verification: VerificationStatus = VerificationStatus.UNKNOWN
    confidence: float = 0.0
    importance: float = 0.5
    revision: int = 1
    source_refs: tuple[str, ...] = ()
    supersedes_id: str | None = None
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    expires_at: datetime | None = None
    created_by: str = "user"
    classification: MemoryClassification = MemoryClassification.INTERNAL
    created_at: datetime | None = None
    scope: MemoryScope = MemoryScope.THREAD

    def __post_init__(self) -> None:
        for value, name in (
            (self.note_id, "note_id"), (self.workspace_id, "workspace_id"),
            (self.content, "content"), (self.created_by, "created_by"),
        ):
            _require_text(value, name)
        _require_unit_interval(self.confidence, "confidence")
        _require_unit_interval(self.importance, "importance")
        if self.revision < 1:
            raise MemoryValidationError("note revision must be positive")
        if self.created_by not in {"user", "model", "tool", "migration", "system"}:
            raise MemoryValidationError("note created_by is invalid")
        if self.created_by in {"model", "tool"} and not self.source_refs:
            raise MemoryValidationError("derived note requires source_refs")
        if len(set(self.source_refs)) != len(self.source_refs):
            raise MemoryValidationError("note source_refs must be unique")
        if self.scope is MemoryScope.THREAD and (not self.session_id or not self.thread_id):
            raise MemoryValidationError("thread note requires session and thread")
        if self.scope is MemoryScope.SESSION and (not self.session_id or self.thread_id is not None):
            raise MemoryValidationError("session note requires only session parent")
        if self.scope is MemoryScope.WORKSPACE and (self.session_id is not None or self.thread_id is not None):
            raise MemoryValidationError("workspace note cannot have session/thread parent")


@dataclass(frozen=True, slots=True)
class SearchFeature:
    name: str
    value_millis: int
    contribution_millis: int

    def __post_init__(self) -> None:
        _require_text(self.name, "search feature name")
        if not 0 <= self.value_millis <= 1000 or not 0 <= self.contribution_millis <= 1000:
            raise MemoryValidationError("search feature values must be bounded")


@dataclass(frozen=True, slots=True)
class MemorySearchHit:
    memory_id: str
    scope: MemoryScope
    memory_type: MemoryType
    classification: MemoryClassification
    verification: VerificationStatus
    status: NoteStatus
    content: str = field(repr=False)
    score_millis: int = 0
    features: tuple[SearchFeature, ...] = ()
    reason_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_text(self.memory_id, "search memory_id")
        _require_text(self.content, "search content")
        if not 0 <= self.score_millis <= 1000:
            raise MemoryValidationError("search score must be bounded")
        if not self.reason_codes:
            raise MemoryValidationError("search hits require reason codes")


@dataclass(frozen=True, slots=True)
class CandidateProposal:
    kind: NoteKind
    content: str = field(repr=False)
    source_refs: tuple[str, ...] = ()
    confidence: float = 0.0
    importance: float = 0.5
    relationship: str = "novel"
    related_note_id: str | None = None

    def __post_init__(self) -> None:
        _require_text(self.content, "candidate proposal content")
        _require_unit_interval(self.confidence, "candidate proposal confidence")
        _require_unit_interval(self.importance, "candidate proposal importance")
        if not self.source_refs:
            raise MemoryValidationError("automatic candidate requires persisted sources")
        if self.relationship not in {"novel", "revision", "conflict"}:
            raise MemoryValidationError("candidate relationship is invalid")
        if (self.relationship == "novel") != (self.related_note_id is None):
            raise MemoryValidationError("related_note_id must match candidate relationship")


@dataclass(frozen=True, slots=True)
class ThreadSummary:
    summary_id: str
    workspace_id: str
    session_id: str
    thread_id: str
    version: int
    goal: str = field(repr=False)
    verified_facts: tuple[str, ...] = field(default=(), repr=False)
    decisions: tuple[str, ...] = field(default=(), repr=False)
    completed_actions: tuple[str, ...] = field(default=(), repr=False)
    pending_actions: tuple[str, ...] = field(default=(), repr=False)
    findings: tuple[str, ...] = field(default=(), repr=False)
    entities: tuple[str, ...] = field(default=(), repr=False)
    open_questions: tuple[str, ...] = field(default=(), repr=False)
    source_memory_ids: tuple[str, ...] = ()
    covered_through_sequence: int = 0
    generation_method: str = "local_deterministic"
    classification: MemoryClassification = MemoryClassification.INTERNAL
    status: NoteStatus = NoteStatus.ACTIVE
    verification: VerificationStatus = VerificationStatus.MODEL_INFERRED
    created_at: datetime | None = None

    def __post_init__(self) -> None:
        for value, name in (
            (self.summary_id, "summary_id"), (self.workspace_id, "workspace_id"),
            (self.session_id, "session_id"), (self.thread_id, "thread_id"),
            (self.generation_method, "generation_method"),
        ):
            _require_text(value, name)
        if self.version < 1 or self.covered_through_sequence < 1:
            raise MemoryValidationError("summary version and watermark must be positive")
        if not self.source_memory_ids:
            raise MemoryValidationError("summary requires source memory ids")
