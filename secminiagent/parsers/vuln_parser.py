from __future__ import annotations

import json
from pathlib import Path


def parse_vulns_json(path: Path) -> list[dict[str, object]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    items = data.get("vulnerabilities", data) if isinstance(data, dict) else data
    return [item for item in items if isinstance(item, dict)]
