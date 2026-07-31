from __future__ import annotations

import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ._ports import EncryptedPayload
from .canonical import canonical_domain_payload, digest_reason_codes
from .errors import MemoryIntegrityError, MemorySchemaUnsupported
from .models import MemoryMetadata


ALGORITHM = "AES-256-GCM"


def build_memory_aad_v1(metadata: MemoryMetadata) -> bytes:
    fields = {
        "classification": metadata.classification.value,
        "id": metadata.id,
        "memory_type": metadata.memory_type.value,
        "schema_version": 1,
        "scope": metadata.scope.value,
        "session_id": metadata.session_id,
        "workspace_id": metadata.workspace_id,
    }
    return json.dumps(fields, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")


def build_memory_aad_v2(
    metadata: MemoryMetadata,
    *,
    key_version: int,
    algorithm: str,
) -> bytes:
    if metadata.schema_version != 2:
        raise MemorySchemaUnsupported("v2 AAD requires schema version 2 metadata")
    return canonical_domain_payload(
        "secminiagent.memory.v2",
        {
            "schema_version": 2,
            "memory_id": metadata.id,
            "workspace_id": metadata.workspace_id,
            "session_id": metadata.session_id,
            "thread_id": metadata.thread_id,
            "run_id": metadata.run_id,
            "scope": metadata.scope.value,
            "memory_type": metadata.memory_type.value,
            "classification": metadata.classification.value,
            "revision": metadata.record_revision,
            "thread_sequence": metadata.thread_sequence,
            "run_sequence": metadata.run_sequence,
            "verification_status": metadata.verification_status.value,
            "provenance_digest": metadata.provenance_digest,
            "source_type": metadata.source_type,
            "policy_action": metadata.policy_action.value,
            "policy_reason_codes_digest": digest_reason_codes(metadata.policy_reason_codes),
            "created_at": metadata.created_at,
            "algorithm": algorithm,
            "key_version": key_version,
        },
    )


def build_memory_aad(
    metadata: MemoryMetadata,
    *,
    key_version: int | None = None,
    algorithm: str | None = None,
) -> bytes:
    if metadata.schema_version == 1:
        return build_memory_aad_v1(metadata)
    if metadata.schema_version == 2:
        if key_version is None or algorithm is None:
            raise MemoryIntegrityError("v2 AAD requires encryption parameters")
        return build_memory_aad_v2(metadata, key_version=key_version, algorithm=algorithm)
    raise MemorySchemaUnsupported("memory metadata schema is unsupported")


class AesGcmMemoryCipher:
    def __init__(self, key_provider: object) -> None:
        self.key_provider = key_provider

    def encrypt(self, plaintext: bytes, *, aad: bytes, workspace_id: str) -> EncryptedPayload:
        key, version = self.key_provider.get_key(workspace_id)
        if len(key) != 32:
            raise MemoryIntegrityError("AES-256-GCM requires a 32-byte key")
        nonce = os.urandom(12)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
        return EncryptedPayload(ciphertext, nonce, version, ALGORITHM)

    def encrypt_memory(self, plaintext: bytes, metadata: MemoryMetadata) -> EncryptedPayload:
        key, version = self.key_provider.get_key(metadata.workspace_id)
        if len(key) != 32:
            raise MemoryIntegrityError("AES-256-GCM requires a 32-byte key")
        aad = build_memory_aad(metadata, key_version=version, algorithm=ALGORITHM)
        nonce = os.urandom(12)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
        return EncryptedPayload(ciphertext, nonce, version, ALGORITHM)

    def decrypt(self, payload: EncryptedPayload, *, aad: bytes, workspace_id: str) -> bytes:
        if payload.algorithm != ALGORITHM or len(payload.nonce) != 12:
            raise MemoryIntegrityError("unsupported or malformed encrypted payload")
        key, version = self.key_provider.get_key(workspace_id)
        if version != payload.key_version:
            raise MemoryIntegrityError("encrypted payload key version is unavailable")
        try:
            return AESGCM(key).decrypt(payload.nonce, payload.ciphertext, aad)
        except InvalidTag as exc:
            raise MemoryIntegrityError("memory authentication failed") from exc

    def decrypt_memory(self, payload: EncryptedPayload, metadata: MemoryMetadata) -> bytes:
        aad = build_memory_aad(
            metadata,
            key_version=payload.key_version,
            algorithm=payload.algorithm,
        )
        return self.decrypt(payload, aad=aad, workspace_id=metadata.workspace_id)
