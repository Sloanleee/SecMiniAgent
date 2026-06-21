from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class Indicator:
    value: str
    indicator_type: str
    source: str = "local"
    description: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "value": self.value,
            "indicator_type": self.indicator_type,
            "source": self.source,
            "description": self.description,
        }
