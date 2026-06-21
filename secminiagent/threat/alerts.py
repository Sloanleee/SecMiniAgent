from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class SecurityAlert:
    alert_id: str
    timestamp: str
    source_ip: str
    destination_ip: str
    destination_port: int
    protocol: str
    rule_name: str
    severity: str
    message: str = ""
    raw: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "message": self.message,
        }
