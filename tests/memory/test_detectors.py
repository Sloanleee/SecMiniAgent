import unittest

from secminiagent.memory import MemoryCandidate, MemorySource, MemoryType
from secminiagent.memory.detectors import (
    EntityDetector,
    EntropyDetector,
    MultiLayerDetector,
    PlaceholderDetector,
    SecretPatternDetector,
    SourceRiskDetector,
)


def candidate(content, *, source=None):
    return MemoryCandidate(
        memory_type=MemoryType.USER_NOTE,
        content=content,
        source=source or MemorySource("user_message"),
    )


class DetectorTest(unittest.TestCase):
    def test_detects_private_key_password_token_and_connection_string(self):
        cases = [
            ("-----BEGIN PRIVATE KEY-----", "private_key"),
            ('password = "Synthet1c-Only-Value"', "credential_assignment"),
            ("Authorization: Bearer abcdefghijklmnopqrstuvwxyz.123456", "bearer_token"),
            ("postgresql://demo:Synthet1cPass@db.internal/example", "connection_string"),
        ]
        detector = SecretPatternDetector()
        for content, expected in cases:
            with self.subTest(expected):
                categories = {signal.category for signal in detector.detect(candidate(content))}
                self.assertIn(expected, categories)

    def test_detects_internal_ip_and_ot_asset(self):
        signals = EntityDetector().detect(candidate("PLC-01 is reachable at 172.16.20.10."))
        categories = {signal.category for signal in signals}
        self.assertIn("internal_ip", categories)
        self.assertIn("ot_asset", categories)

    def test_invalid_or_public_ip_is_not_labeled_internal(self):
        signals = EntityDetector().detect(candidate("Examples: 999.1.1.1 and 8.8.8.8"))
        self.assertNotIn("internal_ip", {signal.category for signal in signals})

    def test_hash_and_uuid_are_not_high_entropy_secret_candidates(self):
        detector = EntropyDetector()
        values = [
            "a3f1c2d4e5b60718293a4b5c6d7e8f90123456789abcdef00112233445566778",
            "550e8400-e29b-41d4-a716-446655440000",
        ]
        for value in values:
            with self.subTest(value=value):
                self.assertEqual(detector.detect(candidate(value)), [])

    def test_unknown_high_entropy_value_is_detected(self):
        signals = EntropyDetector().detect(candidate("value=q9Jm2Lx7Vb4Nz8Qw6Yt1Kp5Rc3Hd"))
        self.assertIn("high_entropy_token", {signal.category for signal in signals})

    def test_placeholder_is_detected(self):
        signals = PlaceholderDetector().detect(candidate('token = "<YOUR_TOKEN>"'))
        self.assertIn("placeholder", {signal.category for signal in signals})

    def test_source_risk_distinguishes_environment_and_test_data(self):
        high = SourceRiskDetector().detect(candidate("ordinary", source=MemorySource("file", ".env")))
        test = SourceRiskDetector().detect(
            candidate("ordinary", source=MemorySource("file", "tests/fixtures/data.json", is_test_data=True))
        )
        self.assertIn("high_risk_source", {signal.category for signal in high})
        self.assertIn("test_source", {signal.category for signal in test})

    def test_detects_url_encoded_secret_through_normalized_variant(self):
        signals = MultiLayerDetector().detect(candidate("password%3D%22Synthet1c-Only-Value%22"))
        secret = [signal for signal in signals if signal.category == "credential_assignment"]
        self.assertTrue(secret)
        self.assertIsNone(secret[0].evidence_span)

    def test_detector_exception_becomes_fail_closed_signal(self):
        class BrokenDetector:
            def detect(self, _candidate):
                raise RuntimeError("synthetic detector failure with no sensitive content")

        signals = MultiLayerDetector(detectors=(BrokenDetector(),)).detect(candidate("ordinary"))
        failures = [signal for signal in signals if signal.category == "detector_failure"]
        self.assertEqual(len(failures), 1)
        self.assertNotIn("synthetic detector failure", failures[0].reason_code)


if __name__ == "__main__":
    unittest.main()
