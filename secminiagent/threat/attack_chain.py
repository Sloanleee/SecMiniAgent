from __future__ import annotations

from secminiagent.threat.incidents import ThreatIncident


def render_attack_chain_hypothesis(incidents: list[ThreatIncident]) -> str:
    if not incidents:
        return "No attack chain hypothesis was generated from the available evidence."
    steps: list[str] = []
    for index, incident in enumerate(incidents, start=1):
        assets = ", ".join(incident.affected_assets) or "unknown assets"
        steps.append(f"{index}. {incident.title} affecting {assets} ({incident.severity}).")
    return "\n".join(steps)
