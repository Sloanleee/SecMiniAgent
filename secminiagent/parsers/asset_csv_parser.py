from __future__ import annotations

import csv
from pathlib import Path

from secminiagent.threat.assets import IndustrialAsset


def parse_assets_csv(path: Path) -> list[IndustrialAsset]:
    assets: list[IndustrialAsset] = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        for index, row in enumerate(reader, start=1):
            protocols = [
                item.strip()
                for item in str(row.get("protocols", "")).replace(";", ",").split(",")
                if item.strip()
            ]
            assets.append(
                IndustrialAsset(
                    asset_id=str(row.get("asset_id") or f"asset-{index}"),
                    name=str(row.get("name") or row.get("hostname") or f"asset-{index}"),
                    ip=str(row.get("ip") or row.get("address") or ""),
                    asset_type=str(row.get("asset_type") or row.get("type") or "unknown"),
                    zone=str(row.get("zone") or "unknown"),
                    owner=str(row.get("owner") or ""),
                    criticality=str(row.get("criticality") or "medium"),
                    protocols=protocols,
                    vendor=str(row.get("vendor") or ""),
                    model=str(row.get("model") or ""),
                    version=str(row.get("version") or ""),
                )
            )
    return assets
