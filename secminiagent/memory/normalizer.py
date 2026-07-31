from __future__ import annotations

import base64
import binascii
import json
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote

from .errors import MemoryValidationError


ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"), None)
PERCENT_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")
BASE64_CANDIDATE = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{24,}={0,2}(?![A-Za-z0-9+/=_-])")
QUOTED_CONCAT = re.compile(
    r"(?P<first>['\"])(?P<head>[^'\"]{1,256})(?P=first)"
    r"(?:\s*\+\s*(?P<quote>['\"])(?P<tail>[^'\"]{1,256})(?P=quote))+"
)
QUOTED_PART = re.compile(r"['\"]([^'\"]*)['\"]")


@dataclass(frozen=True, slots=True)
class NormalizationLimits:
    max_input_chars: int = 200_000
    max_variants: int = 16
    max_decoded_chars: int = 16_384
    max_json_depth: int = 5
    max_json_nodes: int = 256


@dataclass(frozen=True, slots=True)
class NormalizedVariant:
    text: str
    transformation: str
    span_matches_original: bool


@dataclass(frozen=True, slots=True)
class NormalizedContent:
    primary: str
    variants: tuple[NormalizedVariant, ...]
    transformations: tuple[str, ...]


class ContentNormalizer:
    """Build bounded local representations for detectors.

    Decoding is deliberately shallow and size-limited. Variants are detection
    aids only; callers must never persist a decoded variant as user content.
    """

    def __init__(self, limits: NormalizationLimits | None = None) -> None:
        self.limits = limits or NormalizationLimits()

    def normalize(self, content: str) -> NormalizedContent:
        if len(content) > self.limits.max_input_chars:
            raise MemoryValidationError("memory candidate exceeds normalization size limit")

        primary = unicodedata.normalize("NFKC", content).translate(ZERO_WIDTH)
        primary = primary.replace("\r\n", "\n").replace("\r", "\n")
        variants: list[NormalizedVariant] = [NormalizedVariant(primary, "unicode_nfkc", primary == content)]
        transformations = ["unicode_nfkc"]

        if PERCENT_ESCAPE.search(primary):
            decoded = unquote(primary)
            self._append_variant(variants, decoded, "url_decode")

        joined = self._join_quoted_literals(primary)
        if joined != primary:
            self._append_variant(variants, joined, "quoted_literal_join")

        for value in self._json_strings(primary):
            self._append_variant(variants, value, "json_string_extract")

        for match in BASE64_CANDIDATE.finditer(primary):
            decoded = self._decode_base64(match.group(0))
            if decoded is not None:
                self._append_variant(variants, decoded, "base64_decode")

        for variant in variants[1:]:
            if variant.transformation not in transformations:
                transformations.append(variant.transformation)
        return NormalizedContent(primary, tuple(variants), tuple(transformations))

    def _append_variant(self, variants: list[NormalizedVariant], text: str, transformation: str) -> None:
        if len(variants) >= self.limits.max_variants:
            return
        if not text or len(text) > self.limits.max_decoded_chars:
            return
        if any(existing.text == text for existing in variants):
            return
        variants.append(NormalizedVariant(text, transformation, False))

    def _decode_base64(self, value: str) -> str | None:
        padded = value + "=" * (-len(value) % 4)
        try:
            raw = base64.b64decode(padded, altchars=b"-_", validate=True)
            decoded = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return None
        if not decoded.isprintable() and "\n" not in decoded:
            return None
        return decoded

    def _join_quoted_literals(self, text: str) -> str:
        def join(match: re.Match[str]) -> str:
            return "".join(QUOTED_PART.findall(match.group(0)))

        return QUOTED_CONCAT.sub(join, text)

    def _json_strings(self, text: str) -> tuple[str, ...]:
        stripped = text.strip()
        if not stripped or stripped[0] not in "[{":
            return ()
        try:
            root = json.loads(stripped)
        except (json.JSONDecodeError, RecursionError):
            return ()

        values: list[str] = []
        nodes = 0

        def visit(value: object, depth: int) -> None:
            nonlocal nodes
            if depth > self.limits.max_json_depth or nodes >= self.limits.max_json_nodes:
                return
            nodes += 1
            if isinstance(value, str):
                values.append(value)
            elif isinstance(value, dict):
                for key, nested in value.items():
                    if isinstance(key, str):
                        values.append(key)
                    visit(nested, depth + 1)
            elif isinstance(value, list):
                for nested in value:
                    visit(nested, depth + 1)

        visit(root, 0)
        return tuple(values)
