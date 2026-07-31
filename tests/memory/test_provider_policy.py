import tempfile
import unittest
from pathlib import Path

from secminiagent.memory import MemoryAccessContext, MemoryCandidate, MemoryQuery, MemoryScope, MemorySource, MemoryType
from secminiagent.memory.errors import MemoryAccessDenied

from tests.memory.helpers import build_test_service


WORKSPACE = "1" * 64
LOCAL = MemoryAccessContext(WORKSPACE, "session-a", "local")
REMOTE = MemoryAccessContext(WORKSPACE, "session-a", "openai")


class ProviderPolicyTest(unittest.TestCase):
    def test_remote_provider_cannot_recall_confidential_memory(self):
        with tempfile.TemporaryDirectory() as tmp:
            service, _, _ = build_test_service(Path(tmp))
            metadata = service.remember(
                MemoryCandidate(
                    MemoryType.PROJECT_FACT,
                    "PLC-01 is reachable at 172.16.20.10.",
                    MemoryScope.WORKSPACE,
                    MemorySource("unit_test", user_confirmed=True),
                ),
                LOCAL,
            )
            self.assertEqual(service.recall(metadata.id, LOCAL).metadata.classification.value, "confidential")
            with self.assertRaises(MemoryAccessDenied):
                service.recall(metadata.id, REMOTE)
            self.assertEqual(service.list_metadata(MemoryQuery(), REMOTE), ())


if __name__ == "__main__":
    unittest.main()
