import inspect
import unittest
from datetime import datetime
from pathlib import Path

import secminiagent.memory as public_memory
from secminiagent.memory import DeletionReceipt, MemoryService
from secminiagent.memory.errors import MemoryValidationError


class MemoryServiceContractTest(unittest.TestCase):
    def test_plaintext_operations_require_access_context(self):
        for method_name in ["remember", "recall", "search", "forget", "clear_session", "clear_workspace"]:
            parameters = inspect.signature(getattr(MemoryService, method_name)).parameters
            self.assertIn("context", parameters, method_name)
            self.assertIs(parameters["context"].default, inspect.Parameter.empty, method_name)

    def test_service_cannot_be_instantiated_without_implementation(self):
        with self.assertRaises(TypeError):
            MemoryService()

    def test_internal_storage_crypto_and_index_ports_are_not_public_exports(self):
        for internal_name in [
            "AuthoritativeMemoryStore",
            "DerivedMemoryIndex",
            "KeyProtector",
            "MemoryCipher",
            "MemoryPolicyEngine",
            "SemanticDetector",
            "SensitiveDataDetector",
        ]:
            self.assertFalse(hasattr(public_memory, internal_name), internal_name)
            self.assertNotIn(internal_name, public_memory.__all__)

    def test_no_unscoped_public_search_all_contract_exists(self):
        self.assertFalse(hasattr(MemoryService, "search_all"))
        self.assertFalse(hasattr(MemoryService, "read_all"))

    def test_business_modules_do_not_import_internal_memory_ports(self):
        package_root = Path(__file__).resolve().parents[2] / "secminiagent"
        offenders = []
        for path in package_root.rglob("*.py"):
            if path.parent.name == "memory":
                continue
            text = path.read_text(encoding="utf-8")
            if "memory._ports" in text:
                offenders.append(str(path.relative_to(package_root)))
        self.assertEqual(offenders, [])

    def test_deletion_receipt_requires_revocation_and_pending_cleanup(self):
        with self.assertRaises(MemoryValidationError):
            DeletionReceipt("memory-1", datetime.now(), False, True, False, "audit-1")
        with self.assertRaises(MemoryValidationError):
            DeletionReceipt("memory-1", datetime.now(), True, False, False, "audit-1")


if __name__ == "__main__":
    unittest.main()
