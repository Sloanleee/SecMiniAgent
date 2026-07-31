"""Public contracts for SecMiniAgent's privacy-first memory subsystem.

The service boundary, value objects, and local pre-persistence safety
evaluation API are exported here. Storage, crypto, key, audit, and
vector-index ports are intentionally internal so callers cannot treat them as
an alternative memory API.
"""

from .models import (
    DetectionSignal,
    IndexStatus,
    MemoryAccessContext,
    MemoryAction,
    MemoryCandidate,
    MemoryClassification,
    MemoryMetadata,
    MessageEnvelope,
    MemoryQuery,
    MemoryRecord,
    MemoryScope,
    MemorySource,
    MemoryType,
    MemoryRelationType,
    NoteStatus,
    NoteKind,
    PolicyDecision,
    RunMetadata,
    RunStatus,
    SessionMetadata,
    SessionStatus,
    ThreadMetadata,
    ThreadSummary,
    StructuredNote,
    ThreadStatus,
    VerificationStatus,
)
from .classifier import MemoryEvaluation, MemorySafetyEvaluator
from .confirmation import (
    ConfirmationOutcome,
    ConfirmationRequest,
    MemoryConfirmationHandler,
    apply_confirmation,
    build_confirmation_request,
)
from .detectors import (
    EntityDetector,
    EntropyDetector,
    MultiLayerDetector,
    PlaceholderDetector,
    SecretPatternDetector,
    SourceRiskDetector,
)
from .normalizer import ContentNormalizer, NormalizationLimits, NormalizedContent
from .policy import RiskPolicyEngine
from .redactor import MemoryRedactor, RedactionResult
from .service import DeletionReceipt, MemoryService
from .migration import MigrationPlan, MigrationReport, MigrationVerification
from .thread_run_service import ThreadRunService

__all__ = [
    "ConfirmationOutcome",
    "ConfirmationRequest",
    "ContentNormalizer",
    "DeletionReceipt",
    "DetectionSignal",
    "EntityDetector",
    "EntropyDetector",
    "IndexStatus",
    "MemoryAccessContext",
    "MemoryAction",
    "MemoryCandidate",
    "MemoryClassification",
    "MemoryConfirmationHandler",
    "MemoryEvaluation",
    "MemoryMetadata",
    "MessageEnvelope",
    "MemoryQuery",
    "MemoryRecord",
    "MemoryRedactor",
    "MemorySafetyEvaluator",
    "MemoryScope",
    "MemoryService",
    "MemorySource",
    "MemoryType",
    "MemoryRelationType",
    "MigrationPlan",
    "MigrationReport",
    "MigrationVerification",
    "MultiLayerDetector",
    "NormalizationLimits",
    "NormalizedContent",
    "PlaceholderDetector",
    "PolicyDecision",
    "NoteStatus",
    "NoteKind",
    "RunMetadata",
    "RunStatus",
    "SessionMetadata",
    "SessionStatus",
    "ThreadMetadata",
    "ThreadSummary",
    "StructuredNote",
    "ThreadStatus",
    "ThreadRunService",
    "VerificationStatus",
    "RedactionResult",
    "RiskPolicyEngine",
    "SecretPatternDetector",
    "SourceRiskDetector",
    "apply_confirmation",
    "build_confirmation_request",
]
