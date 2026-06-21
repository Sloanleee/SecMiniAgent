from __future__ import annotations

import ipaddress
import re
from pathlib import Path

from secminiagent.threat.indicators import Indicator


HASH_RE = re.compile(r"^[A-Fa-f0-9]{32,64}$")


def parse_iocs(path: Path) -> list[Indicator]:
    indicators: list[Indicator] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indicators.append(Indicator(value=stripped, indicator_type=_classify_ioc(stripped)))
    return indicators


def _classify_ioc(value: str) -> str:
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if value.startswith("http://") or value.startswith("https://"):
        return "url"
    if HASH_RE.match(value):
        return "hash"
    if "." in value:
        return "domain"
    return "unknown"
