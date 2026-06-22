from __future__ import annotations

import csv
from pathlib import Path

from secminiagent.threat.alerts import SecurityAlert


ALIASES = {
    "timestamp": ("\u65f6\u95f4", "timestamp", "time", "event_time"),
    "source_ip": ("\u6e90IP", "\u6e90ip", "source_ip", "src_ip", "src"),
    "destination_ip": ("\u76ee\u7684IP", "\u76ee\u7684ip", "destination_ip", "dest_ip", "dst"),
    "destination_port": ("\u76ee\u7684\u7aef\u53e3", "destination_port", "dest_port", "dpt", "port"),
    "protocol": ("\u534f\u8bae", "protocol", "proto"),
    "action": ("\u52a8\u4f5c", "action"),
    "severity": ("\u7ea7\u522b", "severity", "level"),
    "description": ("\u63cf\u8ff0", "description", "message"),
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
