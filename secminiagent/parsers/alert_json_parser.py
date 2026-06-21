from __future__ import annotations

import json
from pathlib import Path

from secminiagent.threat.alerts import SecurityAlert


def parse_alerts_json(path: Path) -> list[SecurityAlert]:
    data = json.loads(path.read_text(encoding="utf-8"))
    items = data.get("alerts", data) if isinstance(data, dict) else data
    alerts: list[SecurityAlert] = []
    for index, item in enumerate(items, start=1):
        if not isinstance(item, dict):
            continue
        alerts.append(
            SecurityAlert(
                alert_id=str(item.get("alert_id") or item.get("id") or f"alert-{index}"),
                timestamp=str(item.get("timestamp") or item.get("time") or ""),
                source_ip=str(item.get("source_ip") or item.get("src_ip") or item.get("src") or ""),
                destination_ip=str(item.get("destination_ip") or item.get("dest_ip") or item.get("dst") or ""),
                destination_port=int(item.get("destination_port") or item.get("dest_port") or item.get("port") or 0),
                protocol=str(item.get("protocol") or ""),
                rule_name=str(item.get("rule_name") or item.get("signature") or item.get("rule") or ""),
                severity=str(item.get("severity") or "medium"),
                message=str(item.get("message") or item.get("description") or ""),
                raw=item,
            )
        )
    return alerts
