from pathlib import Path

from secminiagent.memory.crypto import AesGcmMemoryCipher
from secminiagent.memory.keys import WorkspaceKeyManager
from secminiagent.memory.local_service import LocalMemoryService
from secminiagent.memory.store import SQLiteMemoryStore


class ReversingProtector:
    """Test-only reversible key protector; never used by production factory."""

    def protect(self, plaintext: bytes) -> bytes:
        return b"test-protected:" + plaintext[::-1]

    def unprotect(self, ciphertext: bytes) -> bytes:
        if not ciphertext.startswith(b"test-protected:"):
            raise ValueError("invalid protected key")
        return ciphertext[len(b"test-protected:") :][::-1]


def build_test_service(root: Path, *, index=None):
    store = SQLiteMemoryStore(root / "memory.db")
    keys = WorkspaceKeyManager(root / "keys", ReversingProtector())
    cipher = AesGcmMemoryCipher(keys)
    return LocalMemoryService(store=store, cipher=cipher, index=index), store, keys
