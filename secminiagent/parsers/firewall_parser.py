from __future__ import annotations

import re
from pathlib import Path

from secminiagent.threat.alerts import SecurityAlert


LOG_RE = re.compile(
    r"(?P<timestamp>\S+\s+\S+).*?src=(?P<src>\d+\.\d+\.\d+\.\d+).*?dst=(?P<dst>\d+\.\d+\.\d+\.\d+).*?dpt=(?P<port>\d+).*?(?:proto=(?P<proto>\w+))?.*?(?:action=(?P<action>\w+))?",
    re.I,
)


def parse_firewall_log(path: Path) -> list[SecurityAlert]:
    alerts: list[SecurityAlert] = []
    for index, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        match = LOG_RE.search(line)
        if not match:
            continue
        action = match.group("action") or "observed"
        alerts.append(
            SecurityAlert(
                alert_id=f"fw-{index}",
                timestamp=match.group("timestamp"),
                source_ip=match.group("src"),
                destination_ip=match.group("dst"),
                destination_port=int(match.group("port")),
                protocol=match.group("proto") or "tcp",
                rule_name=f"firewall_{action}",
                severity="medium" if action.lower() != "deny" else "low",
                message=line.strip(),
                raw={"line": line},
            )
        )
    return alerts
