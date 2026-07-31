import tempfile
import unittest
from pathlib import Path

from secminiagent.memory import MemoryAccessContext, MemoryCandidate, MemoryScope, MemorySource, MemoryType
from secminiagent.memory.errors import MemoryPolicyDenied

from tests.memory.helpers import build_test_service


class LogLeakageTest(unittest.TestCase):
    def test_policy_exception_and_audit_do_not_contain_secret_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            service, store, _ = build_test_service(Path(tmp))
            context = MemoryAccessContext("2" * 64, "session-a", "local")
            secret = "Synthet1c-Only-Value"
            candidate = MemoryCandidate(
                MemoryType.USER_NOTE,
                f'password = "{secret}"',
                MemoryScope.WORKSPACE,
                MemorySource("unit_test", user_confirmed=True),
            )
            with self.assertRaises(MemoryPolicyDenied) as raised:
                service.remember(candidate, context)
            self.assertNotIn(secret, str(raised.exception))
            self.assertNotIn(secret, repr(store.list_audit(context.workspace_id)))


if __name__ == "__main__":
    unittest.main()
