import shutil
import sqlite3
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from secminiagent.memory import (
    MemoryAccessContext,
    MemoryCandidate,
    MemoryQuery,
    MemoryScope,
    MemorySource,
    MemoryType,
)
from secminiagent.memory.crypto import AesGcmMemoryCipher, build_memory_aad
from secminiagent.memory.errors import MemoryIntegrityError, MemoryNotFound
from secminiagent.memory.keys import DPAPIKeyProtector, WorkspaceKeyManager

from tests.memory.helpers import ReversingProtector, build_test_service


WORKSPACE_A = "a" * 64
WORKSPACE_B = "b" * 64


def context(workspace=WORKSPACE_A, session="session-a", provider="local"):
    return MemoryAccessContext(workspace, session, provider)


def candidate(content="ordinary project fact", scope=MemoryScope.SESSION):
    return MemoryCandidate(
        MemoryType.USER_NOTE,
        content,
        scope,
        MemorySource("unit_test", user_confirmed=True),
    )


class CryptoStoreTest(unittest.TestCase):
    def test_cipher_rejects_ciphertext_nonce_and_aad_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = WorkspaceKeyManager(Path(tmp) / "keys", ReversingProtector())
            cipher = AesGcmMemoryCipher(manager)
            payload = cipher.encrypt(b"synthetic plaintext", aad=b"aad", workspace_id=WORKSPACE_A)
            self.assertEqual(cipher.decrypt(payload, aad=b"aad", workspace_id=WORKSPACE_A), b"synthetic plaintext")

            tampered = replace(payload, ciphertext=bytes([payload.ciphertext[0] ^ 1]) + payload.ciphertext[1:])
            with self.assertRaises(MemoryIntegrityError):
                cipher.decrypt(tampered, aad=b"aad", workspace_id=WORKSPACE_A)
            with self.assertRaises(MemoryIntegrityError):
                cipher.decrypt(payload, aad=b"other-aad", workspace_id=WORKSPACE_A)
            with self.assertRaises(MemoryIntegrityError):
                cipher.decrypt(replace(payload, nonce=b"0" * 12), aad=b"aad", workspace_id=WORKSPACE_A)

    @unittest.skipUnless(sys.platform == "win32", "DPAPI is Windows-only")
    def test_dpapi_round_trip_and_wrong_entropy_failure(self):
        protected = DPAPIKeyProtector(entropy=b"scope-a").protect(b"k" * 32)
        self.assertNotIn(b"k" * 32, protected)
        self.assertEqual(DPAPIKeyProtector(entropy=b"scope-a").unprotect(protected), b"k" * 32)
        with self.assertRaises(MemoryIntegrityError):
            DPAPIKeyProtector(entropy=b"scope-b").unprotect(protected)

    def test_database_contains_no_plaintext_and_schema_is_versioned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            service, store, _ = build_test_service(root)
            secret_text = "nonsecret-memory-marker-unique-9472"
            metadata = service.remember(candidate(secret_text), context())
            self.assertEqual(service.recall(metadata.id, context()).content, secret_text)
            for database_file in store.path.parent.glob("memory.db*"):
                self.assertNotIn(secret_text.encode(), database_file.read_bytes(), database_file.name)
            connection = sqlite3.connect(store.path)
            try:
                self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 1)
            finally:
                connection.close()

    def test_aad_binds_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            service, store, _ = build_test_service(Path(tmp))
            metadata = service.remember(candidate(), context())
            fetched_metadata, payload = store.fetch(metadata.id, context())
            altered = replace(fetched_metadata, session_id="other-session")
            with self.assertRaises(MemoryIntegrityError):
                service.cipher.decrypt(payload, aad=build_memory_aad(altered), workspace_id=WORKSPACE_A)

    def test_workspace_and_session_isolation(self):
        with tempfile.TemporaryDirectory() as tmp:
            service, _, _ = build_test_service(Path(tmp))
            metadata = service.remember(candidate(), context())
            with self.assertRaises(MemoryNotFound):
                service.recall(metadata.id, context(WORKSPACE_B))
            with self.assertRaises(MemoryNotFound):
                service.recall(metadata.id, context(WORKSPACE_A, "session-b"))

    def test_database_copy_without_protected_key_cannot_decrypt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "original"
            copied = root / "copied"
            service, store, _ = build_test_service(original)
            metadata = service.remember(candidate(), context())
            copied.mkdir()
            shutil.copy2(store.path, copied / "memory.db")

            copied_service, _, _ = build_test_service(copied)
            with self.assertRaises(MemoryIntegrityError):
                copied_service.recall(metadata.id, context())

    def test_audit_rows_contain_no_memory_plaintext(self):
        with tempfile.TemporaryDirectory() as tmp:
            service, store, _ = build_test_service(Path(tmp))
            text = "audit-plaintext-must-not-appear-3819"
            service.remember(candidate(text), context())
            events = store.list_audit(WORKSPACE_A)
            self.assertTrue(events)
            self.assertNotIn(text, repr(events))


if __name__ == "__main__":
    unittest.main()
