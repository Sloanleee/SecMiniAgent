from __future__ import annotations

from typing import Sequence

from .canonical import digest_provenance
from .models import MemoryRelationType


def provenance_digest(
    source_ids: Sequence[str], relation_type: MemoryRelationType, key: bytes,
) -> bytes:
    return digest_provenance(tuple((source_id, relation_type.value) for source_id in source_ids), key)
