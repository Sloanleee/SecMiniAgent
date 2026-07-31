from __future__ import annotations

import hashlib
import hmac
import re
import unicodedata

from .canonical import canonical_domain_payload
from .models import NoteKind


NORMALIZATION_VERSION = 1


def normalize_semantic_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold().strip()
    return re.sub(r"\s+", " ", normalized)


def note_fingerprint(key: bytes, kind: NoteKind, content: str) -> bytes:
    payload = canonical_domain_payload(
        "secminiagent.memory.dedup",
        {"normalization_version": NORMALIZATION_VERSION, "kind": kind.value, "content": normalize_semantic_text(content)},
    )
    return hmac.new(key, payload, hashlib.sha256).digest()
