import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from secminiagent.memory import (
    DetectionSignal,
    IndexStatus,
    MemoryAccessContext,
    MemoryAction,
    MemoryClassification,
    MemoryMetadata,
    MemoryScope,
    MemoryType,
    PolicyDecision,
)
from secminiagent.memory.errors import MemoryAccessDenied, MemoryValidationError
from secminiagent.memory.models import derive_workspace_id, enforce_scope_access


def metadata(*, scope=MemoryScope.SESSION, workspace_id="workspace-a", session_id="session-a", deleted=False):
    return MemoryMetadata(
        id="memory-1",
        workspace_id=workspace_id,
        session_id=session_id,
        scope=scope,
        memory_type=MemoryType.MESSAGE,
        classification=MemoryClassification.INTERNAL,
        source_type="user_message",
        policy_action=MemoryAction.ALLOW,
        policy_reason_codes=("POLICY_ALLOW_INTERNAL",),
        index_status=IndexStatus.NOT_INDEXED,
        created_at=datetime.now(timezone.utc),
        deleted_at=datetime.now(timezone.utc) if deleted else None,
    )


class MemoryModelContractTest(unittest.TestCase):
    def test_session_memory_requires_session_id(self):
        with self.assertRaises(MemoryValidationError):
            metadata(session_id=None)

    def test_detection_signal_validates_score_range_and_span(self):
        with self.assertRaises(MemoryValidationError):
            DetectionSignal("entropy", "token", 1.1, 0.5, "ENTROPY_TOKEN")
        with self.assertRaises(MemoryValidationError):
            DetectionSignal("regex", "secret", 1.0, 1.0, "PRIVATE_KEY", (4, 4))

    def test_policy_decision_rejects_invalid_session_only_target(self):
        with self.assertRaises(MemoryValidationError):
            PolicyDecision(
                action=MemoryAction.SESSION_ONLY,
                classification=MemoryClassification.CONFIDENTIAL,
                reason_codes=("CONFIDENTIAL_SESSION_ONLY",),
                explanation="Keep only in the active session.",
                target_scope=MemoryScope.WORKSPACE,
            )

    def test_policy_allow_requires_explicit_target_scope(self):
        with self.assertRaises(MemoryValidationError):
            PolicyDecision(
                action=MemoryAction.ALLOW,
                classification=MemoryClassification.INTERNAL,
                reason_codes=("POLICY_ALLOW_INTERNAL",),
                explanation="Allowed.",
            )

    def test_denied_decision_cannot_be_represented_as_persisted_metadata(self):
        with self.assertRaises(MemoryValidationError):
            MemoryMetadata(
                id="memory-denied",
                workspace_id="workspace-a",
                session_id="session-a",
                scope=MemoryScope.SESSION,
                memory_type=MemoryType.MESSAGE,
                classification=MemoryClassification.SECRET,
                source_type="user_message",
                policy_action=MemoryAction.DENY,
                policy_reason_codes=("PRIVATE_KEY_DENY",),
                index_status=IndexStatus.NOT_INDEXED,
                created_at=datetime.now(timezone.utc),
            )

    def test_scope_access_allows_matching_session(self):
        enforce_scope_access(metadata(), MemoryAccessContext("workspace-a", "session-a", "local"))

    def test_scope_access_rejects_other_session_and_workspace(self):
        record = metadata()
        with self.assertRaises(MemoryAccessDenied):
            enforce_scope_access(record, MemoryAccessContext("workspace-a", "session-b", "local"))
        with self.assertRaises(MemoryAccessDenied):
            enforce_scope_access(record, MemoryAccessContext("workspace-b", "session-a", "local"))

    def test_workspace_memory_allows_another_session_in_same_workspace(self):
        record = metadata(scope=MemoryScope.WORKSPACE)
        enforce_scope_access(record, MemoryAccessContext("workspace-a", "session-b", "local"))

    def test_deleted_memory_is_never_readable(self):
        with self.assertRaises(MemoryAccessDenied):
            enforce_scope_access(metadata(deleted=True), MemoryAccessContext("workspace-a", "session-a", "local"))

    def test_workspace_id_is_stable_opaque_and_salt_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            first = derive_workspace_id(path, b"a" * 32)
            second = derive_workspace_id(path / ".", b"a" * 32)
            other_salt = derive_workspace_id(path, b"b" * 32)
        self.assertEqual(first, second)
        self.assertNotEqual(first, other_salt)
        self.assertNotIn(path.name, first)
        self.assertEqual(len(first), 64)

    def test_workspace_id_rejects_short_salt(self):
        with self.assertRaises(MemoryValidationError):
            derive_workspace_id(Path("."), b"short")


if __name__ == "__main__":
    unittest.main()
