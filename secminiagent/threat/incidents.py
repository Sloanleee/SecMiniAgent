from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class ThreatIncident:
    incident_id: str
    title: str
    severity: str
    affected_assets: list[str] = field(default_factory=list)
    related_alerts: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    recommendation: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "severity": self.severity,
            "affected_assets": self.affected_assets,
            "related_alerts": self.related_alerts,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }
