from __future__ import annotations

import ctypes
import os
import sys
from ctypes import wintypes
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .errors import MemoryDependencyUnavailable, MemoryIntegrityError


class KeyProvider(Protocol):
    def get_key(self, workspace_id: str) -> tuple[bytes, int]: ...


class DPAPIKeyProtector:
    """Protect keys for the current Windows user using DPAPI."""

    CRYPTPROTECT_UI_FORBIDDEN = 0x1

    def __init__(self, *, entropy: bytes | None = None) -> None:
        if sys.platform != "win32":
            raise MemoryDependencyUnavailable("Windows DPAPI is unavailable on this platform")
        self.entropy = entropy

    def protect(self, plaintext: bytes) -> bytes:
        return self._crypt(plaintext, decrypt=False)

    def unprotect(self, ciphertext: bytes) -> bytes:
        return self._crypt(ciphertext, decrypt=True)

    def _crypt(self, value: bytes, *, decrypt: bool) -> bytes:
        class DataBlob(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

        def blob(data: bytes) -> tuple[DataBlob, ctypes.Array[ctypes.c_char]]:
            buffer = ctypes.create_string_buffer(data)
            return (
                DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))),
                buffer,
            )

        input_blob, input_buffer = blob(value)
        entropy_blob = None
        entropy_buffer = None
        if self.entropy:
            entropy_blob, entropy_buffer = blob(self.entropy)
        output_blob = DataBlob()
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        try:
            if decrypt:
                ok = crypt32.CryptUnprotectData(
                    ctypes.byref(input_blob),
                    None,
                    ctypes.byref(entropy_blob) if entropy_blob else None,
                    None,
                    None,
                    self.CRYPTPROTECT_UI_FORBIDDEN,
                    ctypes.byref(output_blob),
                )
            else:
                ok = crypt32.CryptProtectData(
                    ctypes.byref(input_blob),
                    "SecMiniAgent workspace key",
                    ctypes.byref(entropy_blob) if entropy_blob else None,
                    None,
                    None,
                    self.CRYPTPROTECT_UI_FORBIDDEN,
                    ctypes.byref(output_blob),
                )
            if not ok:
                raise MemoryIntegrityError(f"DPAPI operation failed with Windows error {ctypes.get_last_error()}")
            return ctypes.string_at(output_blob.pbData, output_blob.cbData)
        finally:
            _ = input_buffer, entropy_buffer
            if output_blob.pbData:
                kernel32.LocalFree(output_blob.pbData)


class WorkspaceKeyManager:
    """Create and load one DPAPI-protected AES-256 key per workspace."""

    def __init__(self, keys_dir: Path, protector: object, *, create: bool = True) -> None:
        self.keys_dir = keys_dir
        self.protector = protector
        if create:
            self.keys_dir.mkdir(parents=True, exist_ok=True)

    def get_key(self, workspace_id: str) -> tuple[bytes, int]:
        path = self._path(workspace_id)
        if not path.exists():
            self.keys_dir.mkdir(parents=True, exist_ok=True)
            key = os.urandom(32)
            protected = self.protector.protect(key)
            temporary = path.with_suffix(".tmp")
            temporary.write_bytes(protected)
            temporary.replace(path)
            return key, 1
        try:
            key = self.protector.unprotect(path.read_bytes())
        except Exception as exc:
            raise MemoryIntegrityError("workspace key could not be unprotected") from exc
        if len(key) != 32:
            raise MemoryIntegrityError("workspace key has an invalid length")
        return key, 1

    def get_existing_key(self, workspace_id: str) -> tuple[bytes, int]:
        path = self._path(workspace_id)
        if not path.exists():
            raise MemoryIntegrityError("workspace key is unavailable")
        try:
            key = self.protector.unprotect(path.read_bytes())
        except Exception as exc:
            raise MemoryIntegrityError("workspace key could not be unprotected") from exc
        if len(key) != 32:
            raise MemoryIntegrityError("workspace key has an invalid length")
        return key, 1

    def derive_key(self, workspace_id: str, purpose: str, *, create: bool = False) -> tuple[bytes, int]:
        if not purpose or not purpose.isascii():
            raise MemoryIntegrityError("key purpose must be non-empty ASCII")
        root, version = self.get_key(workspace_id) if create else self.get_existing_key(workspace_id)
        info = f"secminiagent.memory.{purpose}.v1:key-version={version}".encode("ascii")
        derived = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=bytes.fromhex(workspace_id),
            info=info,
        ).derive(root)
        return derived, version

    def key_exists(self, workspace_id: str) -> bool:
        return self._path(workspace_id).is_file()

    def delete_key(self, workspace_id: str) -> bool:
        path = self._path(workspace_id)
        if not path.exists():
            return False
        path.unlink()
        return True

    def _path(self, workspace_id: str) -> Path:
        if len(workspace_id) != 64 or any(char not in "0123456789abcdef" for char in workspace_id.lower()):
            raise MemoryIntegrityError("invalid workspace id for key lookup")
        return self.keys_dir / f"{workspace_id}.key"


def load_or_create_local_salt(path: Path) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        value = path.read_bytes()
        if len(value) != 32:
            raise MemoryIntegrityError("workspace salt has an invalid length")
        return value
    value = os.urandom(32)
    temporary = path.with_suffix(".tmp")
    temporary.write_bytes(value)
    temporary.replace(path)
    return value


def load_existing_local_salt(path: Path) -> bytes:
    if not path.is_file():
        raise MemoryIntegrityError("workspace salt is unavailable")
    value = path.read_bytes()
    if len(value) != 32:
        raise MemoryIntegrityError("workspace salt has an invalid length")
    return value
