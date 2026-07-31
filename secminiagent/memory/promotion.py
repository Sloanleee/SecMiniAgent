from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Mapping

from .canonical import canonical_json_bytes
from .errors import MemoryConfirmationRequired, MemoryValidationError
from .models import MemoryClassification, MemoryScope


@dataclass(frozen=True, slots=True)
class PromotionPreview:
    source_note_id: str
    source_revision: int
    target_scope: MemoryScope
    classification: MemoryClassification
    requires_confirmation: bool
    confirmation_token: str
    expires_unix: int
    purpose: str = "promotion"


class PromotionConfirmation:
    def __init__(self, key: bytes, *, ttl_seconds: int = 300) -> None:
        if len(key) < 32 or not 30 <= ttl_seconds <= 3600:
            raise MemoryValidationError("promotion confirmation configuration is invalid")
        self.key = key
        self.ttl_seconds = ttl_seconds

    def issue(
        self, *, workspace_id: str, note_id: str, revision: int,
        target_scope: MemoryScope, classification: MemoryClassification,
        purpose: str = "promotion",
    ) -> PromotionPreview:
        expires = int(time.time()) + self.ttl_seconds
        fields = {
            "workspace_id": workspace_id, "note_id": note_id, "revision": revision,
            "target_scope": target_scope.value, "classification": classification.value,
            "purpose": purpose, "expires": expires,
        }
        payload = canonical_json_bytes(fields)
        mac = hmac.new(self.key, payload, hashlib.sha256).digest()
        token = base64.urlsafe_b64encode(len(payload).to_bytes(4, "big") + payload + mac).decode().rstrip("=")
        return PromotionPreview(note_id, revision, target_scope, classification, True, token, expires, purpose)

    def verify(
        self, token: str, *, workspace_id: str, note_id: str, revision: int,
        target_scope: MemoryScope, classification: MemoryClassification,
        purpose: str = "promotion",
    ) -> str:
        try:
            raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
            size = int.from_bytes(raw[:4], "big")
            payload, supplied = raw[4:4 + size], raw[4 + size:]
            fields = json.loads(payload.decode("ascii"))
        except Exception as exc:
            raise MemoryConfirmationRequired("PROMOTION_CONFIRMATION_INVALID") from exc
        expected = hmac.new(self.key, payload, hashlib.sha256).digest()
        if len(supplied) != 32 or not hmac.compare_digest(supplied, expected):
            raise MemoryConfirmationRequired("PROMOTION_CONFIRMATION_INVALID")
        required = {
            "workspace_id": workspace_id, "note_id": note_id, "revision": revision,
            "target_scope": target_scope.value, "classification": classification.value,
            "purpose": purpose,
        }
        if any(fields.get(key) != value for key, value in required.items()):
            raise MemoryConfirmationRequired("PROMOTION_CONFIRMATION_BINDING_MISMATCH")
        if not isinstance(fields.get("expires"), int) or fields["expires"] < int(time.time()):
            raise MemoryConfirmationRequired("PROMOTION_CONFIRMATION_EXPIRED")
        return hashlib.sha256(raw).hexdigest()
