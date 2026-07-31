from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Protocol

from .errors import MemoryValidationError
from .models import MemoryAction, MemoryCandidate, MemoryClassification, PolicyDecision
from .redactor import MemoryRedactor


class ConfirmationOutcome(str, Enum):
    APPROVE = "approve"
    REJECT = "reject"


@dataclass(frozen=True, slots=True)
class ConfirmationRequest:
    request_id: str
    classification: MemoryClassification
    reason_codes: tuple[str, ...]
    sanitized_preview: str
    requested_scope: str


class MemoryConfirmationHandler(Protocol):
    def confirm(self, request: ConfirmationRequest) -> ConfirmationOutcome: ...


def build_confirmation_request(
    *,
    request_id: str,
    candidate: MemoryCandidate,
    decision: PolicyDecision,
    redactor: MemoryRedactor | None = None,
    preview_chars: int = 160,
) -> ConfirmationRequest:
    """Create a local-UI request whose preview contains no detected entity spans."""

    if decision.action is not MemoryAction.REQUIRE_CONFIRMATION:
        raise MemoryValidationError("confirmation requests require a REQUIRE_CONFIRMATION policy decision")
    if not request_id.strip():
        raise MemoryValidationError("request_id must not be empty")
    if preview_chars < 32 or preview_chars > 1000:
        raise MemoryValidationError("preview_chars must be between 32 and 1000")
    result = (redactor or MemoryRedactor()).redact(candidate.content, decision.signals)
    preview = result.content[:preview_chars]
    if len(result.content) > preview_chars:
        preview += "..."
    return ConfirmationRequest(
        request_id=request_id,
        classification=decision.classification,
        reason_codes=decision.reason_codes,
        sanitized_preview=preview,
        requested_scope=candidate.requested_scope.value,
    )


def apply_confirmation(candidate: MemoryCandidate, outcome: ConfirmationOutcome) -> MemoryCandidate | None:
    """Return an explicitly confirmed candidate, or None when rejected."""

    if outcome is ConfirmationOutcome.REJECT:
        return None
    return replace(candidate, source=replace(candidate.source, user_confirmed=True))
