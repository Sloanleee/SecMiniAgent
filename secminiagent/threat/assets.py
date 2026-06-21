from __future__ import annotations

from dataclasses import dataclass, field


CRITICAL_ASSET_TYPES = {"PLC", "HMI", "SCADA", "DCS", "ENGINEERING_STATION", "OPC_SERVER"}


@dataclass(slots=True)
class IndustrialAsset:
    asset_id: str
    name: str
    ip: str
    asset_type: str
    zone: str
    owner: str = ""
    criticality: str = "medium"
    protocols: list[str] = field(default_factory=list)
    vendor: str = ""
    model: str = ""
    version: str = ""

    @property
    def normalized_type(self) -> str:
        return self.asset_type.strip().upper().replace(" ", "_")

    @property
    def is_critical_ot(self) -> bool:
        return self.normalized_type in CRITICAL_ASSET_TYPES or self.criticality.lower() == "high"

    def to_dict(self) -> dict[str, object]:
        return {
            "asset_id": self.asset_id,
            "name": self.name,
            "ip": self.ip,
            "asset_type": self.asset_type,
            "zone": self.zone,
            "owner": self.owner,
            "criticality": self.criticality,
            "protocols": self.protocols,
            "vendor": self.vendor,
            "model": self.model,
            "version": self.version,
            "is_critical_ot": self.is_critical_ot,
        }
