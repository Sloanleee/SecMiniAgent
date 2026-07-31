from __future__ import annotations

from typing import Sequence

from .models import (
    DetectionSignal,
    MemoryAccessContext,
    MemoryAction,
    MemoryCandidate,
    MemoryClassification,
    MemoryScope,
    PolicyDecision,
)


HARD_SECRET_CATEGORIES = {
    "private_key",
    "bearer_token",
    "jwt",
    "cloud_access_key",
    "api_key",
    "connection_string",
    "credential_assignment",
}
PII_CATEGORIES = {"email", "phone"}
CONFIDENTIAL_CATEGORIES = {
    "internal_ip",
    "ot_asset",
    "confidential_source",
    "high_risk_source",
    "network_topology",
    "critical_asset",
    "maintenance_weakness",
    "unpublished_vulnerability",
}
MITIGATION_CATEGORIES = {"placeholder", "test_source"}


class RiskPolicyEngine:
    """Explainable fail-closed policy for M1 detector signals."""

    def decide(
        self,
        candidate: MemoryCandidate,
        signals: Sequence[DetectionSignal],
        context: MemoryAccessContext,
    ) -> PolicyDecision:
        signal_tuple = tuple(signals)

        unmitigated_secrets = tuple(
            signal for signal in signal_tuple if self._is_unmitigated_hard_secret(signal, signal_tuple)
        )
        if unmitigated_secrets:
            return PolicyDecision(
                action=MemoryAction.DENY,
                classification=MemoryClassification.SECRET,
                reason_codes=("POLICY_HARD_SECRET_DENY", *(signal.reason_code for signal in unmitigated_secrets)),
                explanation="High-confidence credential material is forbidden from persistent memory.",
                signals=signal_tuple,
            )

        failures = tuple(signal for signal in signal_tuple if signal.category == "detector_failure")
        if failures:
            return self._session_only(
                candidate,
                context,
                MemoryClassification.CONFIDENTIAL,
                ("POLICY_DETECTOR_FAILURE_SESSION_ONLY", *(signal.reason_code for signal in failures)),
                "A local detector failed; the candidate cannot enter workspace memory.",
                signal_tuple,
            )

        entropy = tuple(signal for signal in signal_tuple if signal.category == "high_entropy_token")
        if entropy:
            return self._uncertain(
                candidate,
                context,
                signal_tuple,
                ("POLICY_UNKNOWN_TOKEN_REVIEW", *(signal.reason_code for signal in entropy)),
                "An unexplained high-entropy value cannot automatically enter workspace memory.",
            )

        pii = tuple(signal for signal in signal_tuple if signal.category in PII_CATEGORIES)
        confidential = tuple(signal for signal in signal_tuple if signal.category in CONFIDENTIAL_CATEGORIES)
        if confidential:
            if candidate.requested_scope is MemoryScope.WORKSPACE and not candidate.source.user_confirmed:
                return PolicyDecision(
                    action=MemoryAction.REQUIRE_CONFIRMATION,
                    classification=MemoryClassification.CONFIDENTIAL,
                    reason_codes=("POLICY_CONFIDENTIAL_CONFIRM", *(signal.reason_code for signal in confidential)),
                    explanation="Workspace persistence of sensitive project context requires explicit confirmation.",
                    signals=signal_tuple,
                )
            if pii:
                return PolicyDecision(
                    action=MemoryAction.REDACT,
                    classification=MemoryClassification.CONFIDENTIAL,
                    reason_codes=(
                        "POLICY_CONFIDENTIAL_CONFIRMED_PII_REDACT"
                        if candidate.source.user_confirmed
                        else "POLICY_PII_REDACT",
                        *(signal.reason_code for signal in pii),
                    ),
                    explanation="Personal identifiers must be redacted before sensitive context is persisted.",
                    signals=signal_tuple,
                    target_scope=candidate.requested_scope,
                )
            if candidate.requested_scope is MemoryScope.SESSION:
                return self._session_only(
                    candidate,
                    context,
                    MemoryClassification.CONFIDENTIAL,
                    ("POLICY_CONFIDENTIAL_SESSION_ONLY", *(signal.reason_code for signal in confidential)),
                    "Sensitive project context is limited to the active session.",
                    signal_tuple,
                )
            return PolicyDecision(
                action=MemoryAction.ALLOW,
                classification=MemoryClassification.CONFIDENTIAL,
                reason_codes=("POLICY_CONFIDENTIAL_CONFIRMED",),
                explanation="The user explicitly confirmed workspace persistence of sensitive project context.",
                signals=signal_tuple,
                target_scope=MemoryScope.WORKSPACE,
            )

        if pii:
            return PolicyDecision(
                action=MemoryAction.REDACT,
                classification=MemoryClassification.CONFIDENTIAL,
                reason_codes=("POLICY_PII_REDACT", *(signal.reason_code for signal in pii)),
                explanation="Personal identifiers must be redacted before persistence.",
                signals=signal_tuple,
                target_scope=candidate.requested_scope,
            )

        classification = (
            MemoryClassification.PUBLIC
            if signal_tuple and all(signal.category in {"public_cve", *MITIGATION_CATEGORIES} for signal in signal_tuple)
            else MemoryClassification.INTERNAL
        )
        return PolicyDecision(
            action=MemoryAction.ALLOW,
            classification=classification,
            reason_codes=("POLICY_LOW_RISK_ALLOW",),
            explanation="No unmitigated sensitive information was detected.",
            signals=signal_tuple,
            target_scope=candidate.requested_scope,
        )

    def _uncertain(
        self,
        candidate: MemoryCandidate,
        context: MemoryAccessContext,
        signals: tuple[DetectionSignal, ...],
        reason_codes: tuple[str, ...],
        explanation: str,
    ) -> PolicyDecision:
        if candidate.requested_scope in {MemoryScope.THREAD, MemoryScope.SESSION}:
            return self._session_only(candidate, context, MemoryClassification.CONFIDENTIAL, reason_codes, explanation, signals)
        return PolicyDecision(
            action=MemoryAction.REQUIRE_CONFIRMATION,
            classification=MemoryClassification.CONFIDENTIAL,
            reason_codes=reason_codes,
            explanation=explanation,
            signals=signals,
        )

    def _session_only(
        self,
        candidate: MemoryCandidate,
        context: MemoryAccessContext,
        classification: MemoryClassification,
        reason_codes: tuple[str, ...],
        explanation: str,
        signals: tuple[DetectionSignal, ...],
    ) -> PolicyDecision:
        if candidate.requested_scope is MemoryScope.THREAD:
            target_scope = MemoryScope.THREAD if context.thread_id is not None else None
        elif candidate.requested_scope is MemoryScope.SESSION:
            target_scope = MemoryScope.SESSION if context.session_id is not None else None
        elif context.thread_id is not None:
            target_scope = MemoryScope.THREAD
        elif context.session_id is not None:
            target_scope = MemoryScope.SESSION
        else:
            target_scope = None
        if target_scope is None:
            return PolicyDecision(
                action=MemoryAction.DENY,
                classification=classification,
                reason_codes=("POLICY_SESSION_CONTEXT_REQUIRED", *reason_codes),
                explanation="No active thread or session permits constrained persistence.",
                signals=signals,
            )
        return PolicyDecision(
            action=MemoryAction.SESSION_ONLY,
            classification=classification,
            reason_codes=reason_codes,
            explanation=explanation,
            signals=signals,
            target_scope=target_scope,
        )

    @staticmethod
    def _is_unmitigated_hard_secret(
        signal: DetectionSignal,
        signals: tuple[DetectionSignal, ...],
    ) -> bool:
        if signal.category not in HARD_SECRET_CATEGORIES or signal.confidence < 0.9 or signal.severity < 0.9:
            return False
        if signal.category in {"private_key", "bearer_token", "jwt", "cloud_access_key", "connection_string"}:
            return True
        return not any(
            mitigation.category == "placeholder" and _spans_overlap(signal.evidence_span, mitigation.evidence_span)
            for mitigation in signals
        )


def _spans_overlap(left: tuple[int, int] | None, right: tuple[int, int] | None) -> bool:
    if left is None or right is None:
        return False
    return max(left[0], right[0]) < min(left[1], right[1])
