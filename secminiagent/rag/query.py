from __future__ import annotations

from collections.abc import Mapping


OT_PORT_HINTS = {
    502: "Modbus PLC industrial control protocol suspicious OT access",
    102: "S7comm Siemens PLC industrial control protocol access",
    4840: "OPC UA industrial data exchange OT access",
    3389: "RDP remote maintenance brute force access",
}

SUPPORTED_QUERY_STRATEGIES = ("description_only", "description_port", "description_port_hint")


def build_query(sample: Mapping[str, object], strategy: str) -> str:
    description = str(sample.get("description") or "").strip()
    port = _port_or_zero(sample.get("destination_port"))

    if strategy == "description_only":
        return description
    if strategy == "description_port":
        return " ".join(part for part in [description, _port_phrase(port)] if part).strip()
    if strategy == "description_port_hint":
        return " ".join(
            part for part in [description, _port_phrase(port), OT_PORT_HINTS.get(port, "")] if part
        ).strip()
    raise ValueError(f"Unknown RAG query strategy: {strategy}")


def _port_phrase(port: int) -> str:
    return f"traffic to port {port}" if port else ""


def _port_or_zero(value: object) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
