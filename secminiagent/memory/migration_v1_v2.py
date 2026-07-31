from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence


def deterministic_hex_id(key: bytes, label: str) -> str:
    return hmac.new(key, label.encode("utf-8"), hashlib.sha256).hexdigest()


def legacy_main_thread_id(key: bytes, session_id: str) -> str:
    return deterministic_hex_id(key, f"legacy-main-thread:{session_id}")


def legacy_run_id(key: bytes, session_id: str, run_no: int, *, unassigned: bool = False) -> str:
    kind = "unassigned" if unassigned else "inferred"
    return deterministic_hex_id(key, f"legacy-run:{kind}:{session_id}:{run_no}")


@dataclass(frozen=True, slots=True)
class LegacyEvent:
    memory_id: str
    sequence_no: int
    memory_type: str
    role: str | None = None
    has_tool_calls: bool = False
    tool_call_id: str | None = None


@dataclass(frozen=True, slots=True)
class LegacyRun:
    run_id: str
    run_no: int
    status: str
    migration_origin: str
    input_message_id: str | None
    final_message_id: str | None
    event_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class LegacyRunInference:
    runs: tuple[LegacyRun, ...]
    event_assignments: Mapping[str, tuple[str, int]]


def decode_v1_envelope(plaintext: bytes) -> tuple[str, dict[str, object]]:
    value = json.loads(plaintext.decode("utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("content"), str):
        raise ValueError("legacy encrypted envelope is malformed")
    attributes = value.get("attributes")
    return str(value["content"]), dict(attributes) if isinstance(attributes, dict) else {}


def event_from_plaintext(
    *,
    memory_id: str,
    sequence_no: int,
    memory_type: str,
    plaintext: bytes,
) -> LegacyEvent:
    content, attributes = decode_v1_envelope(plaintext)
    role = None
    has_tool_calls = False
    tool_call_id = None
    if memory_type == "message":
        try:
            message = json.loads(content)
        except json.JSONDecodeError:
            message = None
        if isinstance(message, dict):
            role = str(message.get("role")) if message.get("role") is not None else None
            has_tool_calls = bool(message.get("tool_calls"))
            if message.get("tool_call_id") is not None:
                tool_call_id = str(message["tool_call_id"])
    elif memory_type == "tool_result":
        role = "tool"
        if attributes.get("tool_call_id") is not None:
            tool_call_id = str(attributes["tool_call_id"])
    return LegacyEvent(memory_id, sequence_no, memory_type, role, has_tool_calls, tool_call_id)


def infer_legacy_runs(events: Sequence[LegacyEvent], *, key: bytes, session_id: str) -> LegacyRunInference:
    ordered = sorted(events, key=lambda item: (item.sequence_no, item.memory_id))
    mutable_runs: list[dict[str, object]] = []
    assignments: dict[str, tuple[str, int]] = {}
    current: dict[str, object] | None = None
    unassigned: dict[str, object] | None = None
    next_run_no = 1

    def new_run(*, orphan: bool) -> dict[str, object]:
        nonlocal next_run_no
        run = {
            "run_id": legacy_run_id(key, session_id, next_run_no, unassigned=orphan),
            "run_no": next_run_no,
            "status": "running",
            "migration_origin": "legacy_unassigned" if orphan else "legacy_inferred",
            "input_message_id": None,
            "final_message_id": None,
            "event_ids": [],
        }
        next_run_no += 1
        mutable_runs.append(run)
        return run

    for event in ordered:
        if event.role == "user":
            if current is not None and current["status"] == "running":
                current["status"] = "interrupted"
            current = new_run(orphan=False)
            current["input_message_id"] = event.memory_id
        elif current is None:
            if unassigned is None:
                unassigned = new_run(orphan=True)
            current_for_event = unassigned
            current_for_event["status"] = "interrupted"
            event_ids = current_for_event["event_ids"]
            assert isinstance(event_ids, list)
            event_ids.append(event.memory_id)
            assignments[event.memory_id] = (str(current_for_event["run_id"]), len(event_ids))
            continue

        assert current is not None
        event_ids = current["event_ids"]
        assert isinstance(event_ids, list)
        event_ids.append(event.memory_id)
        assignments[event.memory_id] = (str(current["run_id"]), len(event_ids))
        if event.role == "assistant" and not event.has_tool_calls:
            current["status"] = "completed"
            current["final_message_id"] = event.memory_id
            current = None

    if current is not None and current["status"] == "running":
        current["status"] = "interrupted"
    runs = tuple(
        LegacyRun(
            run_id=str(item["run_id"]),
            run_no=int(item["run_no"]),
            status=str(item["status"]),
            migration_origin=str(item["migration_origin"]),
            input_message_id=str(item["input_message_id"]) if item["input_message_id"] else None,
            final_message_id=str(item["final_message_id"]) if item["final_message_id"] else None,
            event_ids=tuple(str(value) for value in item["event_ids"]),
        )
        for item in mutable_runs
    )
    return LegacyRunInference(runs, assignments)


def legacy_note_mapping(memory_type: str) -> tuple[str | None, str, str, str | None]:
    if memory_type == "security_finding":
        return "finding", "unknown", "active", None
    if memory_type == "project_fact":
        return "fact", "unknown", "active", None
    if memory_type == "user_note":
        return None, "unknown", "candidate", "legacy_unknown"
    if memory_type == "session_summary":
        return None, "unknown", "candidate", "legacy_unknown"
    return None, "unknown", "active", None


def source_snapshot(rows: Iterable[Mapping[str, object]]) -> str:
    digest = hashlib.sha256()
    for row in sorted(rows, key=lambda item: str(item["id"])):
        stable = {
            "id": str(row["id"]),
            "schema_version": int(row["schema_version"]),
            "workspace_id": str(row["workspace_id"]),
            "session_id": str(row["session_id"]) if row["session_id"] is not None else None,
            "scope": str(row["scope"]),
            "memory_type": str(row["memory_type"]),
            "classification": str(row["classification"]),
            "source_type": str(row["source_type"]),
            "policy_action": str(row["policy_action"]),
            "policy_reason_codes": str(row["policy_reason_codes"]),
            "key_version": int(row["key_version"]),
            "algorithm": str(row["algorithm"]),
            "index_status": str(row["index_status"]),
            "sequence_no": int(row["sequence_no"]) if row["sequence_no"] is not None else None,
            "created_at": str(row["created_at"]),
            "expires_at": str(row["expires_at"]) if row["expires_at"] is not None else None,
            "deleted_at": str(row["deleted_at"]) if row["deleted_at"] is not None else None,
            "nonce_sha256": hashlib.sha256(bytes(row["nonce"])).hexdigest(),
            "ciphertext_sha256": hashlib.sha256(bytes(row["ciphertext"])).hexdigest(),
        }
        digest.update(json.dumps(stable, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii"))
    return digest.hexdigest()
