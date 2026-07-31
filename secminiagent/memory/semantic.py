from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Sequence

from .models import DetectionSignal, MemoryCandidate


@dataclass(frozen=True, slots=True)
class SemanticClassification:
    label: str
    confidence: float
    explanation: str
    reason_code: str
    evidence_span: tuple[int, int] | None


@dataclass(frozen=True, slots=True)
class SemanticRule:
    label: str
    reason_code: str
    explanation: str
    confidence: float
    severity: float
    pattern: re.Pattern[str]


SEMANTIC_RULES = (
    SemanticRule(
        "network_topology",
        "SEMANTIC_INTERNAL_TOPOLOGY",
        "Describes internal zones, routes, or connectivity between IT and OT assets.",
        0.88,
        0.82,
        re.compile(
            r"(?i)(?:办公网|生产区|控制区|DMZ|跳板机|internal network|office network|production zone)"
            r".{0,80}(?:访问|连接|路由|reachable|connect|route|PLC|HMI|SCADA)"
        ),
    ),
    SemanticRule(
        "critical_asset",
        "SEMANTIC_CRITICAL_ASSET",
        "Identifies an industrial asset as critical or essential to production.",
        0.91,
        0.88,
        re.compile(
            r"(?i)(?:关键|核心|唯一|不能停机|critical|core|sole|cannot be shut down)"
            r".{0,60}(?:PLC|HMI|SCADA|DCS|控制器|联锁|asset)"
            r"|(?:PLC|HMI|SCADA|DCS|控制器|联锁).{0,60}(?:关键|核心|不能停机|critical|core)"
        ),
    ),
    SemanticRule(
        "maintenance_weakness",
        "SEMANTIC_MAINTENANCE_WEAKNESS",
        "Reveals a remote-maintenance or access-control weakness.",
        0.9,
        0.9,
        re.compile(
            r"(?i)(?:远程维护|供应商访问|remote maintenance|vendor access).{0,100}"
            r"(?:无|未|没有|without|disabled|no ).{0,30}(?:MFA|多因素|审计|限制|authentication|audit)"
        ),
    ),
    SemanticRule(
        "unpublished_vulnerability",
        "SEMANTIC_UNPUBLISHED_VULNERABILITY",
        "Describes a non-public vulnerability or internal security finding.",
        0.93,
        0.94,
        re.compile(
            r"(?i)(?:未公开|尚未披露|内部发现|zero[- ]day|unpublished|not yet disclosed|internal finding)"
            r".{0,100}(?:漏洞|弱点|vulnerability|security flaw|CVE)?"
        ),
    ),
)


class LocalSemanticDetector:
    """Deterministic local semantic baseline; performs no network or model calls."""

    uses_network = False

    def classify(self, candidate: MemoryCandidate) -> tuple[SemanticClassification, ...]:
        rows: list[SemanticClassification] = []
        for rule in SEMANTIC_RULES:
            for match in rule.pattern.finditer(candidate.content):
                rows.append(
                    SemanticClassification(
                        label=rule.label,
                        confidence=rule.confidence,
                        explanation=rule.explanation,
                        reason_code=rule.reason_code,
                        evidence_span=match.span(),
                    )
                )
        return tuple(rows)

    def detect(self, candidate: MemoryCandidate) -> Sequence[DetectionSignal]:
        by_reason = {rule.reason_code: rule for rule in SEMANTIC_RULES}
        return tuple(
            DetectionSignal(
                detector="local_semantic",
                category=classification.label,
                confidence=classification.confidence,
                severity=by_reason[classification.reason_code].severity,
                reason_code=classification.reason_code,
                evidence_span=classification.evidence_span,
            )
            for classification in self.classify(candidate)
        )
