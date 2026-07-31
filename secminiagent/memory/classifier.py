from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Sequence

from .detectors import MultiLayerDetector
from .errors import MemoryValidationError
from .models import (
    DetectionSignal,
    MemoryAccessContext,
    MemoryAction,
    MemoryCandidate,
    MemoryScope,
    PolicyDecision,
)
from .policy import RiskPolicyEngine
from .redactor import MemoryRedactor, RedactionResult


@dataclass(frozen=True, slots=True)
class MemoryEvaluation:
    decision: PolicyDecision
    signals: tuple[DetectionSignal, ...]
    persistable_candidate: MemoryCandidate | None = field(default=None, repr=False)
    redaction: RedactionResult | None = None

    def __post_init__(self) -> None:
        blocked = {MemoryAction.DENY, MemoryAction.REQUIRE_CONFIRMATION}
        if self.decision.action in blocked and self.persistable_candidate is not None:
            raise MemoryValidationError(
                f"{self.decision.action.value} evaluation cannot expose a persistable candidate"
            )
        allowed = {MemoryAction.ALLOW, MemoryAction.REDACT, MemoryAction.SESSION_ONLY}
        if self.decision.action in allowed and self.persistable_candidate is None:
            raise MemoryValidationError(f"{self.decision.action.value} evaluation requires a persistable candidate")
        if (
            self.decision.action is MemoryAction.SESSION_ONLY
            and self.persistable_candidate is not None
            and self.persistable_candidate.requested_scope not in {MemoryScope.THREAD, MemoryScope.SESSION}
        ):
            raise MemoryValidationError("SESSION_ONLY evaluation must expose only a thread/session candidate")
        if self.decision.action is MemoryAction.REDACT and (self.redaction is None or not self.redaction.complete):
            raise MemoryValidationError("REDACT evaluation requires a complete redaction result")

    @property
    def requires_confirmation(self) -> bool:
        return self.decision.action is MemoryAction.REQUIRE_CONFIRMATION


class MemorySafetyEvaluator:
    """Local M1 safety gate that produces a policy-approved candidate or none."""

    def __init__(
        self,
        *,
        detector: MultiLayerDetector | None = None,
        policy: RiskPolicyEngine | None = None,
        redactor: MemoryRedactor | None = None,
    ) -> None:
        self.detector = detector or MultiLayerDetector()
        self.policy = policy or RiskPolicyEngine()
        self.redactor = redactor or MemoryRedactor()

    def evaluate(self, candidate: MemoryCandidate, context: MemoryAccessContext) -> MemoryEvaluation:
        signals = tuple(self.detector.detect(candidate))
        decision = self.policy.decide(candidate, signals, context)

        if decision.action in {MemoryAction.DENY, MemoryAction.REQUIRE_CONFIRMATION}:
            return MemoryEvaluation(decision, signals)

        approved = replace(candidate, requested_scope=decision.target_scope or candidate.requested_scope)
        requires_redaction = decision.action is MemoryAction.REDACT or any(
            signal.category in {"email", "phone"} for signal in signals
        )
        if requires_redaction:
            approved, redaction = self.redactor.redact_candidate(approved, signals)
            if not redaction.complete:
                fail_closed = PolicyDecision(
                    action=MemoryAction.REQUIRE_CONFIRMATION,
                    classification=decision.classification,
                    reason_codes=("POLICY_INCOMPLETE_REDACTION", *decision.reason_codes),
                    explanation="Sensitive content could not be safely mapped back to the original text.",
                    signals=signals,
                )
                return MemoryEvaluation(fail_closed, signals, redaction=redaction)
            return MemoryEvaluation(decision, signals, approved, redaction)

        return MemoryEvaluation(decision, signals, approved)
