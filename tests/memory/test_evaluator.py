import json
import unittest
from pathlib import Path

from secminiagent.memory import (
    ConfirmationOutcome,
    MemoryAccessContext,
    MemoryAction,
    MemoryCandidate,
    MemoryClassification,
    MemorySafetyEvaluator,
    MemoryScope,
    MemorySource,
    MemoryType,
    apply_confirmation,
    build_confirmation_request,
)
from secminiagent.memory.detectors import MultiLayerDetector


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "sensitive_cases.json"


def candidate(content, *, scope=MemoryScope.WORKSPACE, source=None):
    return MemoryCandidate(
        memory_type=MemoryType.USER_NOTE,
        content=content,
        requested_scope=scope,
        source=source or MemorySource("user_message"),
    )


CONTEXT = MemoryAccessContext("workspace-a", "session-a", "local")


class MemorySafetyEvaluatorTest(unittest.TestCase):
    def test_fixture_policy_matrix(self):
        evaluator = MemorySafetyEvaluator()
        cases = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        for case in cases:
            with self.subTest(case=case["id"]):
                result = evaluator.evaluate(candidate(case["content"]), CONTEXT)
                self.assertEqual(result.decision.action.value, case["expected_action"])
                if case["expected_category"]:
                    self.assertIn(case["expected_category"], {signal.category for signal in result.signals})

    def test_high_confidence_secret_never_exposes_persistable_candidate(self):
        result = MemorySafetyEvaluator().evaluate(candidate('password = "Synthet1c-Only-Value"'), CONTEXT)
        self.assertEqual(result.decision.action, MemoryAction.DENY)
        self.assertEqual(result.decision.classification, MemoryClassification.SECRET)
        self.assertIsNone(result.persistable_candidate)

    def test_placeholder_assignment_is_not_treated_as_production_secret(self):
        result = MemorySafetyEvaluator().evaluate(candidate('token = "<YOUR_TOKEN>"'), CONTEXT)
        self.assertEqual(result.decision.action, MemoryAction.ALLOW)
        self.assertIsNotNone(result.persistable_candidate)

    def test_pii_is_redacted_before_candidate_is_exposed(self):
        result = MemorySafetyEvaluator().evaluate(candidate("Contact operator@example.com or 13812345678."), CONTEXT)
        self.assertEqual(result.decision.action, MemoryAction.REDACT)
        self.assertIsNotNone(result.persistable_candidate)
        content = result.persistable_candidate.content
        self.assertNotIn("operator@example.com", content)
        self.assertNotIn("13812345678", content)
        self.assertIn("[REDACTED:EMAIL]", content)
        self.assertIn("[REDACTED:PHONE]", content)

    def test_pii_from_high_risk_source_requires_confirmation_then_redaction(self):
        original = candidate(
            "Contact operator@example.com.",
            source=MemorySource("file", ".env"),
        )
        first = MemorySafetyEvaluator().evaluate(original, CONTEXT)
        self.assertEqual(first.decision.action, MemoryAction.REQUIRE_CONFIRMATION)
        self.assertIsNone(first.persistable_candidate)

        confirmed = apply_confirmation(original, ConfirmationOutcome.APPROVE)
        second = MemorySafetyEvaluator().evaluate(confirmed, CONTEXT)
        self.assertEqual(second.decision.action, MemoryAction.REDACT)
        self.assertNotIn("operator@example.com", second.persistable_candidate.content)

    def test_derived_pii_with_unmappable_span_fails_closed(self):
        result = MemorySafetyEvaluator().evaluate(candidate("operator%40example.com"), CONTEXT)
        self.assertEqual(result.decision.action, MemoryAction.REQUIRE_CONFIRMATION)
        self.assertIsNone(result.persistable_candidate)
        self.assertFalse(result.redaction.complete)

    def test_confidential_workspace_memory_requires_then_accepts_confirmation(self):
        original = candidate("PLC-01 is reachable at 172.16.20.10.")
        first = MemorySafetyEvaluator().evaluate(original, CONTEXT)
        self.assertTrue(first.requires_confirmation)
        self.assertIsNone(first.persistable_candidate)
        request = build_confirmation_request(request_id="confirm-1", candidate=original, decision=first.decision)
        self.assertNotIn("172.16.20.10", request.sanitized_preview)
        self.assertNotIn("PLC-01", request.sanitized_preview)

        confirmed = apply_confirmation(original, ConfirmationOutcome.APPROVE)
        second = MemorySafetyEvaluator().evaluate(confirmed, CONTEXT)
        self.assertEqual(second.decision.action, MemoryAction.ALLOW)
        self.assertEqual(second.decision.classification, MemoryClassification.CONFIDENTIAL)
        self.assertIsNotNone(second.persistable_candidate)

    def test_rejected_confirmation_returns_no_candidate(self):
        self.assertIsNone(apply_confirmation(candidate("PLC-01"), ConfirmationOutcome.REJECT))

    def test_detector_failure_cannot_enter_workspace_memory(self):
        class BrokenDetector:
            def detect(self, _candidate):
                raise RuntimeError("synthetic failure")

        evaluator = MemorySafetyEvaluator(detector=MultiLayerDetector(detectors=(BrokenDetector(),)))
        result = evaluator.evaluate(candidate("ordinary project fact"), CONTEXT)
        self.assertEqual(result.decision.action, MemoryAction.SESSION_ONLY)
        self.assertEqual(result.persistable_candidate.requested_scope, MemoryScope.SESSION)

    def test_detected_hard_secret_remains_denied_when_another_detector_fails(self):
        from secminiagent.memory.detectors import SecretPatternDetector

        class BrokenDetector:
            def detect(self, _candidate):
                raise RuntimeError("synthetic failure")

        evaluator = MemorySafetyEvaluator(
            detector=MultiLayerDetector(detectors=(SecretPatternDetector(), BrokenDetector()))
        )
        result = evaluator.evaluate(candidate('password = "Synthet1c-Only-Value"'), CONTEXT)
        self.assertEqual(result.decision.action, MemoryAction.DENY)
        self.assertIsNone(result.persistable_candidate)

    def test_detected_pii_is_still_redacted_when_another_detector_fails(self):
        from secminiagent.memory.detectors import EntityDetector

        class BrokenDetector:
            def detect(self, _candidate):
                raise RuntimeError("synthetic failure")

        evaluator = MemorySafetyEvaluator(detector=MultiLayerDetector(detectors=(EntityDetector(), BrokenDetector())))
        result = evaluator.evaluate(candidate("Contact operator@example.com."), CONTEXT)
        self.assertEqual(result.decision.action, MemoryAction.SESSION_ONLY)
        self.assertNotIn("operator@example.com", result.persistable_candidate.content)

    def test_unknown_high_entropy_value_requires_confirmation_for_workspace(self):
        result = MemorySafetyEvaluator().evaluate(candidate("value=q9Jm2Lx7Vb4Nz8Qw6Yt1Kp5Rc3Hd"), CONTEXT)
        self.assertEqual(result.decision.action, MemoryAction.REQUIRE_CONFIRMATION)
        self.assertIsNone(result.persistable_candidate)


if __name__ == "__main__":
    unittest.main()
