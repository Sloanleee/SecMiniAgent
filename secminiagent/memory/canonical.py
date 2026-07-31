from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Mapping, Sequence

from .errors import MemoryValidationError


def canonical_timestamp(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise MemoryValidationError("canonical timestamps require timezone information")
    normalized = value.astimezone(timezone.utc)
    return normalized.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _normalize(value: object) -> object:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        raise MemoryValidationError("floating-point values are forbidden in authenticated canonical data")
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, datetime):
        return canonical_timestamp(value)
    if isinstance(value, Mapping):
        normalized: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise MemoryValidationError("canonical object keys must be ASCII strings")
            normalized[key] = _normalize(item)
        return normalized
    if isinstance(value, (tuple, list)):
        return [_normalize(item) for item in value]
    raise MemoryValidationError("unsupported value type in authenticated canonical data")


def canonical_json_bytes(fields: Mapping[str, object]) -> bytes:
    normalized = _normalize(fields)
    try:
        return json.dumps(
            normalized,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise MemoryValidationError("canonical JSON encoding failed") from exc


def digest_reason_codes(reason_codes: Sequence[str]) -> str:
    codes = sorted(set(reason_codes))
    if not codes or any(not isinstance(code, str) or not code.strip() for code in codes):
        raise MemoryValidationError("reason codes must be non-empty strings")
    encoded = json.dumps(codes, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def digest_provenance(
    source_relations: Sequence[tuple[str, str]],
    key: bytes,
) -> bytes:
    ordered = sorted({(str(memory_id), str(relation_type)) for memory_id, relation_type in source_relations})
    payload = canonical_json_bytes(
        {"sources": [{"memory_id": memory_id, "relation_type": relation_type} for memory_id, relation_type in ordered]}
    )
    return hmac.new(key, payload, hashlib.sha256).digest()


def canonical_domain_payload(domain: str, fields: Mapping[str, object]) -> bytes:
    if not domain or not domain.isascii():
        raise MemoryValidationError("canonical domains must be non-empty ASCII")
    return canonical_json_bytes({"domain": domain, **dict(fields)})
