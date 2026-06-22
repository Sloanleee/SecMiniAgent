from __future__ import annotations

import csv
from pathlib import Path

from secminiagent.threat.alerts import SecurityAlert


ALIASES = {
    "timestamp": ("鏃堕棿", "timestamp", "time", "鍛婅鏃堕棿"),
    "source_ip": ("婧怚P", "婧恑p", "source_ip", "src_ip", "src"),
    "destination_ip": ("鐩殑IP", "鐩殑ip", "destination_ip", "dest_ip", "dst"),
    "destination_port": ("鐩殑绔彛", "destination_port", "dest_port", "dpt", "port"),
    "protocol": ("鍗忚", "protocol", "proto"),
    "action": ("鍔ㄤ綔", "action"),
    "severity": ("绾у埆", "severity", "level"),
    "description": ("鎻忚堪", "description", "message"),
}


def parse_alerts_csv(path: Path) -> list[SecurityAlert]:
    alerts: list[SecurityAlert] = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        for index, row in enumerate(reader, start=1):
            alerts.append(normalize_alert_row(row, index))
    return alerts


def normalize_alert_row(row: dict[str, str], index: int) -> SecurityAlert:
    action = _get(row, "action") or "observed"
    return SecurityAlert(
        alert_id=f"csv-{index}",
        timestamp=_get(row, "timestamp"),
        source_ip=_get(row, "source_ip"),
        destination_ip=_get(row, "destination_ip"),
        destination_port=_int_or_zero(_get(row, "destination_port")),
        protocol=_get(row, "protocol") or "tcp",
        rule_name=f"csv_{action.lower()}",
        severity=(_get(row, "severity") or "medium").lower(),
        message=_get(row, "description"),
        raw=dict(row),
    )


def _get(row: dict[str, str], canonical: str) -> str:
    for key in ALIASES[canonical]:
        value = row.get(key)
        if value is not None:
            return str(value).strip()
    return ""


def _int_or_zero(value: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
