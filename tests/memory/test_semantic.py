import unittest

from secminiagent.memory import MemoryAccessContext, MemoryAction, MemoryCandidate, MemoryScope, MemorySource, MemoryType
from secminiagent.memory.classifier import MemorySafetyEvaluator
from secminiagent.memory.semantic import LocalSemanticDetector


CONTEXT = MemoryAccessContext("f" * 64, "session-a", "local")


def candidate(text):
    return MemoryCandidate(
        MemoryType.PROJECT_FACT,
        text,
        MemoryScope.WORKSPACE,
        MemorySource("user_message"),
    )


class LocalSemanticDetectorTest(unittest.TestCase):
    def test_structured_semantic_classification_covers_required_ot_categories(self):
        cases = {
            "办公网通过跳板机连接生产区 PLC。": "network_topology",
            "PLC-01 是不能停机的关键控制器。": "critical_asset",
            "供应商远程维护没有启用 MFA。": "maintenance_weakness",
            "这是尚未披露的内部发现漏洞。": "unpublished_vulnerability",
        }
        detector = LocalSemanticDetector()
        self.assertFalse(detector.uses_network)
        for text, expected in cases.items():
            with self.subTest(expected):
                rows = detector.classify(candidate(text))
                selected = [row for row in rows if row.label == expected]
                self.assertTrue(selected)
                self.assertGreater(selected[0].confidence, 0.8)
                self.assertTrue(selected[0].explanation)

    def test_semantic_signal_is_fused_into_confirmation_policy(self):
        result = MemorySafetyEvaluator().evaluate(candidate("PLC-01 是不能停机的关键控制器。"), CONTEXT)
        self.assertEqual(result.decision.action, MemoryAction.REQUIRE_CONFIRMATION)
        self.assertIn("critical_asset", {signal.category for signal in result.signals})

    def test_semantic_detection_cannot_override_hard_secret(self):
        text = 'PLC-01 是关键控制器，password = "Synthet1c-Only-Value"'
        result = MemorySafetyEvaluator().evaluate(candidate(text), CONTEXT)
        self.assertEqual(result.decision.action, MemoryAction.DENY)
        self.assertIsNone(result.persistable_candidate)


if __name__ == "__main__":
    unittest.main()
