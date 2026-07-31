import json
import unittest
from dataclasses import replace
from datetime import datetime, timezone

from secminiagent.memory.canonical import canonical_json_bytes, canonical_timestamp, digest_reason_codes
from secminiagent.memory.crypto import ALGORITHM, build_memory_aad_v1, build_memory_aad_v2
from secminiagent.memory.errors import MemoryValidationError
from secminiagent.memory.models import (
    IndexStatus, MemoryAction, MemoryClassification, MemoryMetadata, MemoryScope, MemoryType,
    NoteStatus, VerificationStatus,
)


class AADV2Test(unittest.TestCase):
    def test_v1_aad_bytes_are_unchanged(self):
        metadata = self._v1()
        expected = b'{"classification":"internal","id":"m","memory_type":"user_note","schema_version":1,"scope":"session","session_id":"s","workspace_id":"w"}'
        self.assertEqual(build_memory_aad_v1(metadata), expected)

    def test_canonical_aad_is_order_independent(self):
        self.assertEqual(canonical_json_bytes({"b": 2, "a": "\u4e2d"}), canonical_json_bytes({"a": "\u4e2d", "b": 2}))
        self.assertIn(b"\\u4e2d", canonical_json_bytes({"a": "\u4e2d"}))
        self.assertEqual(canonical_timestamp(datetime(2026, 1, 1, tzinfo=timezone.utc)), "2026-01-01T00:00:00.000000Z")

    def test_canonical_aad_rejects_float_and_unknown_types(self):
        with self.assertRaises(MemoryValidationError):
            canonical_json_bytes({"value": 0.1})
        with self.assertRaises(MemoryValidationError):
            canonical_json_bytes({"value": object()})

    def test_v2_aad_binds_every_security_field(self):
        metadata = self._v2()
        baseline = build_memory_aad_v2(metadata, key_version=1, algorithm=ALGORITHM)
        changes = {
            "id": "m2", "workspace_id": "x", "session_id": "s2", "thread_id": "t2", "run_id": "r2",
            "classification": MemoryClassification.CONFIDENTIAL, "record_revision": 2,
            "thread_sequence": 2, "run_sequence": 2, "verification_status": VerificationStatus.USER_CONFIRMED,
            "provenance_digest": b"q" * 32, "source_type": "other",
            "policy_action": MemoryAction.REDACT, "policy_reason_codes": ("OTHER",),
            "created_at": datetime(2026, 1, 2, tzinfo=timezone.utc),
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                self.assertNotEqual(baseline, build_memory_aad_v2(replace(metadata, **{field: value}), key_version=1, algorithm=ALGORITHM))
        self.assertNotEqual(baseline, build_memory_aad_v2(metadata, key_version=2, algorithm=ALGORITHM))

    def test_reason_code_digest_is_sorted_and_unambiguous(self):
        self.assertEqual(digest_reason_codes(("B", "A", "A")), digest_reason_codes(("A", "B")))

    def _v1(self):
        return MemoryMetadata("m", "w", "s", MemoryScope.SESSION, MemoryType.USER_NOTE, MemoryClassification.INTERNAL, "test", MemoryAction.ALLOW, ("TEST",), IndexStatus.NOT_INDEXED, datetime(2026, 1, 1, tzinfo=timezone.utc))

    def _v2(self):
        return MemoryMetadata(
            "m", "w", "s", MemoryScope.THREAD, MemoryType.MESSAGE, MemoryClassification.INTERNAL,
            "test", MemoryAction.ALLOW, ("TEST",), IndexStatus.NOT_INDEXED,
            datetime(2026, 1, 1, tzinfo=timezone.utc), schema_version=2, thread_id="t", run_id="r",
            thread_sequence=1, run_sequence=1, lifecycle_status=NoteStatus.ACTIVE,
            verification_status=VerificationStatus.UNKNOWN, provenance_digest=b"p" * 32,
        )


if __name__ == "__main__":
    unittest.main()
