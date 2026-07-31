import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone

from secminiagent.memory.errors import MemoryAccessDenied, MemoryValidationError
from secminiagent.memory.models import (
    IndexStatus, MemoryAccessContext, MemoryAction, MemoryClassification, MemoryMetadata,
    MemoryCandidate, MemoryScope, MemorySource, MemoryType, NoteStatus, VerificationStatus, enforce_scope_access,
)
from secminiagent.memory.models import DetectionSignal
from secminiagent.memory.policy import RiskPolicyEngine


class M7ModelTest(unittest.TestCase):
    def test_existing_three_positional_access_context_args_remain_compatible(self):
        context = MemoryAccessContext("w", "s", "local")
        self.assertIsNone(context.thread_id)

    def test_thread_id_is_keyword_only(self):
        with self.assertRaises(TypeError):
            MemoryAccessContext("w", "s", "local", "t")  # type: ignore[misc]
        self.assertEqual(MemoryAccessContext("w", "s", "local", thread_id="t").thread_id, "t")

    def test_thread_scope_requires_session_and_thread(self):
        with self.assertRaises(MemoryValidationError):
            MemoryAccessContext("w", None, "local", thread_id="t")
        metadata = self._metadata()
        enforce_scope_access(metadata, MemoryAccessContext("w", "s", "local", thread_id="t"))
        with self.assertRaises(MemoryAccessDenied):
            enforce_scope_access(metadata, MemoryAccessContext("w", "s", "local", thread_id="other"))

    def test_run_requires_matching_thread_ancestry_fields(self):
        with self.assertRaises(MemoryValidationError):
            self._metadata(run_id="r", run_sequence=None)

    def test_session_only_keeps_thread_scope(self):
        metadata = self._metadata(policy_action=MemoryAction.SESSION_ONLY)
        self.assertIs(metadata.scope, MemoryScope.THREAD)

    def test_workspace_session_only_uses_narrowest_context_and_without_context_is_denied(self):
        candidate = MemoryCandidate(
            MemoryType.USER_NOTE, "synthetic", MemoryScope.WORKSPACE, MemorySource("test")
        )
        failure = DetectionSignal("test", "detector_failure", 1.0, 1.0, "TEST_FAILURE")
        policy = RiskPolicyEngine()
        thread = policy.decide(candidate, (failure,), MemoryAccessContext("w", "s", "local", thread_id="t"))
        self.assertIs(thread.target_scope, MemoryScope.THREAD)
        denied = policy.decide(candidate, (failure,), MemoryAccessContext("w", None, "local"))
        self.assertIs(denied.action, MemoryAction.DENY)

    def _metadata(self, **changes):
        values = dict(
            id="m", workspace_id="w", session_id="s", thread_id="t", run_id="r",
            scope=MemoryScope.THREAD, memory_type=MemoryType.MESSAGE,
            classification=MemoryClassification.INTERNAL, source_type="test",
            policy_action=MemoryAction.ALLOW, policy_reason_codes=("TEST",),
            index_status=IndexStatus.NOT_INDEXED, created_at=datetime.now(timezone.utc),
            schema_version=2, record_revision=1, thread_sequence=1, run_sequence=1,
            lifecycle_status=NoteStatus.ACTIVE, verification_status=VerificationStatus.UNKNOWN,
            provenance_digest=b"p" * 32, state_version=1,
        )
        values.update(changes)
        return MemoryMetadata(**values)


if __name__ == "__main__":
    unittest.main()
