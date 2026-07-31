from __future__ import annotations

import ipaddress
import math
import re
from dataclasses import dataclass, replace
from pathlib import PurePath
from typing import Iterable, Sequence

from .errors import MemoryDependencyUnavailable
from .models import DetectionSignal, MemoryCandidate
from .normalizer import ContentNormalizer, NormalizedVariant


@dataclass(frozen=True, slots=True)
class PatternSpec:
    reason_code: str
    category: str
    pattern: re.Pattern[str]
    confidence: float
    severity: float


SECRET_PATTERNS = (
    PatternSpec(
        "SECRET_PRIVATE_KEY",
        "private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)?PRIVATE KEY-----"),
        1.0,
        1.0,
    ),
    PatternSpec(
        "SECRET_BEARER_TOKEN",
        "bearer_token",
        re.compile(r"(?i)\bAuthorization\s*:\s*Bearer\s+[A-Za-z0-9._~+/=-]{12,}"),
        0.99,
        1.0,
    ),
    PatternSpec(
        "SECRET_JWT",
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"),
        0.99,
        1.0,
    ),
    PatternSpec(
        "SECRET_AWS_ACCESS_KEY",
        "cloud_access_key",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        0.99,
        1.0,
    ),
    PatternSpec(
        "SECRET_OPENAI_STYLE_KEY",
        "api_key",
        re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
        0.98,
        0.98,
    ),
    PatternSpec(
        "SECRET_CONNECTION_STRING",
        "connection_string",
        re.compile(
            r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://"
            r"[^/\s:@]+:[^@\s/]+@[^/\s]+"
        ),
        0.99,
        1.0,
    ),
    PatternSpec(
        "SECRET_SENSITIVE_ASSIGNMENT",
        "credential_assignment",
        re.compile(
            r"""(?ix)
            \b(?:api[_-]?key|access[_-]?key|client[_-]?secret|secret|token|password|passwd|pwd)
            \b\s*[:=]\s*
            (?P<quote>['"])?(?P<value>[^\s,'"};]{8,})(?P=quote)?
            """
        ),
        0.94,
        0.96,
    ),
)

EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b")
PHONE_PATTERN = re.compile(r"(?<!\d)(?:\+?86[- ]?)?1[3-9]\d{9}(?!\d)")
IPV4_PATTERN = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)")
OT_ASSET_PATTERN = re.compile(
    r"(?i)\b(?:PLC|HMI|SCADA|DCS|RTU|OPC(?:\s*UA)?|工程师站|控制器|安全联锁)"
    r"(?:[-_ ]?[A-Za-z0-9]{1,24})?\b"
)
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
UUID_PATTERN = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
HASH_PATTERN = re.compile(r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|[0-9a-fA-F]{128})$")
ENTROPY_TOKEN_PATTERN = re.compile(r"(?<![A-Za-z0-9_+/=-])[A-Za-z0-9_+/=-]{20,}(?![A-Za-z0-9_+/=-])")

PLACEHOLDER_VALUE_PATTERN = re.compile(
    r"""(?ix)^
    (?:
        example|sample|dummy|fake|test|testing|changeme|replace[_-]?me|
        your[_-]?(?:api[_-]?)?(?:key|token|secret|password)|
        <[^>]{1,80}>|\$\{[^}]{1,80}\}|x{8,}|0{8,}|
        (?:abc|123){3,}
    )$
    """
)


def _signal(spec: PatternSpec, match: re.Match[str], *, keep_span: bool = True) -> DetectionSignal:
    return DetectionSignal(
        detector="secret_pattern",
        category=spec.category,
        confidence=spec.confidence,
        severity=spec.severity,
        reason_code=spec.reason_code,
        evidence_span=match.span() if keep_span else None,
    )


class SecretPatternDetector:
    def detect(self, candidate: MemoryCandidate) -> Sequence[DetectionSignal]:
        signals: list[DetectionSignal] = []
        for spec in SECRET_PATTERNS:
            signals.extend(_signal(spec, match) for match in spec.pattern.finditer(candidate.content))
        return signals


class EntityDetector:
    def detect(self, candidate: MemoryCandidate) -> Sequence[DetectionSignal]:
        text = candidate.content
        signals: list[DetectionSignal] = []
        signals.extend(self._matches(EMAIL_PATTERN, text, "email", "ENTITY_EMAIL", 0.98, 0.65))
        signals.extend(self._matches(PHONE_PATTERN, text, "phone", "ENTITY_PHONE", 0.97, 0.7))
        signals.extend(self._matches(OT_ASSET_PATTERN, text, "ot_asset", "ENTITY_OT_ASSET", 0.88, 0.78))
        signals.extend(self._matches(CVE_PATTERN, text, "public_cve", "ENTITY_PUBLIC_CVE", 0.99, 0.05))

        for match in IPV4_PATTERN.finditer(text):
            try:
                address = ipaddress.ip_address(match.group(0))
            except ValueError:
                continue
            if address.is_private:
                signals.append(
                    DetectionSignal(
                        "entity",
                        "internal_ip",
                        0.99,
                        0.8,
                        "ENTITY_INTERNAL_IP",
                        match.span(),
                    )
                )
        return signals

    @staticmethod
    def _matches(
        pattern: re.Pattern[str],
        text: str,
        category: str,
        reason_code: str,
        confidence: float,
        severity: float,
    ) -> Iterable[DetectionSignal]:
        for match in pattern.finditer(text):
            yield DetectionSignal("entity", category, confidence, severity, reason_code, match.span())


class PlaceholderDetector:
    def detect(self, candidate: MemoryCandidate) -> Sequence[DetectionSignal]:
        signals: list[DetectionSignal] = []
        for match in re.finditer(r"(?P<value><[^>\n]+>|\$\{[^}\n]+}|[A-Za-z0-9_-]{4,80})", candidate.content):
            value = match.group("value").strip("'\"")
            if PLACEHOLDER_VALUE_PATTERN.fullmatch(value):
                signals.append(
                    DetectionSignal(
                        "placeholder",
                        "placeholder",
                        0.96,
                        0.0,
                        "PLACEHOLDER_EXAMPLE_VALUE",
                        match.span("value"),
                    )
                )
        return signals


class EntropyDetector:
    def __init__(self, *, minimum_entropy: float = 3.6) -> None:
        self.minimum_entropy = minimum_entropy

    def detect(self, candidate: MemoryCandidate) -> Sequence[DetectionSignal]:
        signals: list[DetectionSignal] = []
        for match in ENTROPY_TOKEN_PATTERN.finditer(candidate.content):
            token = match.group(0).rstrip("=")
            if UUID_PATTERN.fullmatch(token) or HASH_PATTERN.fullmatch(token):
                continue
            if PLACEHOLDER_VALUE_PATTERN.fullmatch(token):
                continue
            entropy = shannon_entropy(token)
            if entropy < self.minimum_entropy:
                continue
            confidence = min(0.9, 0.55 + (entropy - self.minimum_entropy) * 0.18 + min(len(token), 80) / 400)
            signals.append(
                DetectionSignal(
                    "entropy",
                    "high_entropy_token",
                    confidence,
                    0.72,
                    "ENTROPY_UNKNOWN_TOKEN",
                    match.span(),
                )
            )
        return signals


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {character: value.count(character) for character in set(value)}
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


class SourceRiskDetector:
    HIGH_RISK_TYPES = {"environment", "shell_output", "private_key_file", "credential_file"}
    HIGH_RISK_NAMES = {".env", ".npmrc", ".pypirc", "id_rsa", "id_ed25519", "credentials"}
    CONFIDENTIAL_TYPES = {"asset_inventory", "security_alert", "firewall_log", "ids_log", "tool_result"}

    def detect(self, candidate: MemoryCandidate) -> Sequence[DetectionSignal]:
        source = candidate.source
        reference_name = PurePath(source.source_ref).name.lower() if source.source_ref else ""
        if source.source_type.lower() in self.HIGH_RISK_TYPES or reference_name in self.HIGH_RISK_NAMES:
            return (DetectionSignal("source", "high_risk_source", 0.98, 0.9, "SOURCE_HIGH_RISK"),)
        if source.source_type.lower() in self.CONFIDENTIAL_TYPES:
            return (DetectionSignal("source", "confidential_source", 0.9, 0.65, "SOURCE_CONFIDENTIAL"),)
        if source.is_test_data:
            return (DetectionSignal("source", "test_source", 0.95, 0.0, "SOURCE_TEST_DATA"),)
        return ()


class MultiLayerDetector:
    """Run bounded local detectors and turn component failures into signals."""

    def __init__(
        self,
        *,
        normalizer: ContentNormalizer | None = None,
        detectors: Sequence[object] | None = None,
    ) -> None:
        self.normalizer = normalizer or ContentNormalizer()
        self.detectors = tuple(
            detectors
            or (
                SecretPatternDetector(),
                EntityDetector(),
                EntropyDetector(),
                PlaceholderDetector(),
                SourceRiskDetector(),
                self._local_semantic_detector(),
            )
        )

    def detect(self, candidate: MemoryCandidate) -> Sequence[DetectionSignal]:
        try:
            normalized = self.normalizer.normalize(candidate.content)
        except Exception:
            return (self._failure_signal("normalizer"),)

        signals: list[DetectionSignal] = []
        failed = False
        for detector in self.detectors:
            detector_name = type(detector).__name__
            try:
                variant_signals = self._run_detector(detector, candidate, normalized.variants)
                signals.extend(variant_signals)
            except Exception:
                failed = True
                signals.append(self._failure_signal(detector_name))

        deduplicated = self._deduplicate(signals)
        if failed and not any(signal.category == "detector_failure" for signal in deduplicated):
            raise MemoryDependencyUnavailable("sensitive-data detector failed")
        return deduplicated

    def _run_detector(
        self,
        detector: object,
        original: MemoryCandidate,
        variants: Sequence[NormalizedVariant],
    ) -> list[DetectionSignal]:
        detect = getattr(detector, "detect")
        output: list[DetectionSignal] = []
        for variant in variants:
            variant_candidate = replace(original, content=variant.text)
            for signal in detect(variant_candidate):
                if not variant.span_matches_original and signal.evidence_span is not None:
                    signal = replace(signal, evidence_span=None)
                output.append(signal)
        return output

    @staticmethod
    def _failure_signal(detector_name: str) -> DetectionSignal:
        safe_name = re.sub(r"[^A-Za-z0-9_]+", "_", detector_name).upper()
        return DetectionSignal(
            "pipeline",
            "detector_failure",
            1.0,
            1.0,
            f"DETECTOR_FAILURE_{safe_name}",
        )

    @staticmethod
    def _deduplicate(signals: Sequence[DetectionSignal]) -> tuple[DetectionSignal, ...]:
        unique: dict[tuple[str, str, str, tuple[int, int] | None], DetectionSignal] = {}
        for signal in signals:
            key = (signal.detector, signal.category, signal.reason_code, signal.evidence_span)
            previous = unique.get(key)
            if previous is None or (signal.confidence, signal.severity) > (previous.confidence, previous.severity):
                unique[key] = signal
        return tuple(unique.values())

    @staticmethod
    def _local_semantic_detector() -> object:
        from .semantic import LocalSemanticDetector

        return LocalSemanticDetector()
