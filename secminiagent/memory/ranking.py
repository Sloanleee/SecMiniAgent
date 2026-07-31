from __future__ import annotations

import math
import re
from datetime import datetime, timezone

from .models import SearchFeature, VerificationStatus


TOKEN_RE = re.compile(r"[\w.-]+", re.UNICODE)


def tokens(value: str) -> set[str]:
    return {item.casefold() for item in TOKEN_RE.findall(value) if len(item) > 1}


def rank_features(
    query: str, content: str, *, semantic: bool, importance_millis: int,
    verification: VerificationStatus, created_at: datetime,
) -> tuple[int, tuple[SearchFeature, ...], tuple[str, ...]]:
    query_tokens = tokens(query)
    content_tokens = tokens(content)
    overlap = len(query_tokens & content_tokens) / max(1, len(query_tokens))
    lexical = min(1000, round(overlap * 1000))
    entities = {item for item in query_tokens if any(char.isdigit() for char in item) or "." in item or "-" in item}
    entity = round(1000 * len(entities & content_tokens) / max(1, len(entities))) if entities else 0
    semantic_value = 1000 if semantic else 0
    trust = {
        VerificationStatus.USER_CONFIRMED: 1000,
        VerificationStatus.TOOL_VERIFIED: 850,
        VerificationStatus.MODEL_INFERRED: 450,
        VerificationStatus.UNKNOWN: 250,
    }[verification]
    age_days = max(0.0, (datetime.now(timezone.utc) - created_at).total_seconds() / 86400)
    recency = round(1000 * math.exp(-age_days / 90))
    values = (
        ("lexical", lexical, 300), ("semantic", semantic_value, 250),
        ("entity", entity, 150), ("importance", max(0, min(1000, importance_millis)), 100),
        ("trust", trust, 150), ("recency", recency, 50),
    )
    features = tuple(SearchFeature(name, value, round(value * weight / 1000)) for name, value, weight in values)
    score = min(1000, sum(item.contribution_millis for item in features))
    reasons = tuple(f"SEARCH_{item.name.upper()}" for item in features if item.value_millis > 0)
    return score, features, reasons or ("SEARCH_METADATA_MATCH",)
