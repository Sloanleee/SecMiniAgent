from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Sequence

from .models import DetectionSignal, MemoryCandidate


DEFAULT_REDACT_CATEGORIES = {
    "email",
    "phone",
    "internal_ip",
    "ot_asset",
    "private_key",
    "bearer_token",
    "jwt",
    "cloud_access_key",
    "api_key",
    "connection_string",
    "credential_assignment",
    "high_entropy_token",
}


@dataclass(frozen=True, slots=True)
class Redaction:
    category: str
    replacement: str
    span: tuple[int, int]


@dataclass(frozen=True, slots=True)
class RedactionResult:
    content: str = field(repr=False)
    redactions: tuple[Redaction, ...]
    complete: bool
    unresolved_categories: tuple[str, ...] = ()


class MemoryRedactor:
    def __init__(self, categories: set[str] | None = None) -> None:
        self.categories = categories or set(DEFAULT_REDACT_CATEGORIES)

    def redact(self, content: str, signals: Sequence[DetectionSignal]) -> RedactionResult:
        selected = [signal for signal in signals if signal.category in self.categories]
        unresolved = sorted({signal.category for signal in selected if signal.evidence_span is None})
        spans = self._non_overlapping_spans(signal for signal in selected if signal.evidence_span is not None)
        rendered = content
        redactions: list[Redaction] = []
        for start, end, category in reversed(spans):
            replacement = f"[REDACTED:{category.upper()}]"
            rendered = rendered[:start] + replacement + rendered[end:]
            redactions.append(Redaction(category, replacement, (start, end)))
        redactions.reverse()
        return RedactionResult(rendered, tuple(redactions), not unresolved, tuple(unresolved))

    def redact_candidate(
        self,
        candidate: MemoryCandidate,
        signals: Sequence[DetectionSignal],
    ) -> tuple[MemoryCandidate, RedactionResult]:
        result = self.redact(candidate.content, signals)
        return replace(candidate, content=result.content), result

    @staticmethod
    def _non_overlapping_spans(signals: Sequence[DetectionSignal]) -> list[tuple[int, int, str]]:
        ordered = sorted(
            (
                (signal.evidence_span[0], signal.evidence_span[1], signal.category, signal.severity)
                for signal in signals
                if signal.evidence_span is not None
            ),
            key=lambda item: (item[0], -(item[1] - item[0]), -item[3]),
        )
        accepted: list[tuple[int, int, str]] = []
        for start, end, category, _severity in ordered:
            if any(max(start, existing_start) < min(end, existing_end) for existing_start, existing_end, _ in accepted):
                continue
            accepted.append((start, end, category))
        return accepted
