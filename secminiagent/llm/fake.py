from __future__ import annotations

from typing import Any

from .base import LLMResponse, Message, ToolCall


class FakeLLMClient:
    provider = "fake"

    def __init__(self, responses: list[LLMResponse] | None = None) -> None:
        self.responses = responses or []
        self.requests: list[dict[str, Any]] = []

    async def complete(
        self,
        *,
        messages: list[Message],
        tools: list[Any],
        system_prompt: str,
    ) -> LLMResponse:
        self.requests.append(
            {"messages": messages, "tools": tools, "system_prompt": system_prompt}
        )
        if self.responses:
            return self.responses.pop(0)
        tool_result = _last_tool_result(messages)
        if tool_result is not None:
            content = _summarize_tool_result(tool_result)
            return LLMResponse(
                content=content,
                tool_calls=[],
                assistant_message={"role": "assistant", "content": content},
                raw={},
            )
        prompt = _last_user_text(messages)
        call = _tool_call_for_prompt(prompt)
        if call is not None:
            return LLMResponse(
                content="",
                tool_calls=[call],
                assistant_message={
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": call.id,
                            "type": "function",
                            "function": {
                                "name": call.name,
                                "arguments": "{}",
                            },
                        }
                    ],
                },
                raw={},
            )
        return LLMResponse(
            content="SecMiniAgent fake response: no model call was made.",
            tool_calls=[],
            assistant_message={
                "role": "assistant",
                "content": "SecMiniAgent fake response: no model call was made.",
            },
            raw={},
        )

    def user_message(self, content: str) -> Message:
        return {"role": "user", "content": content}

    def tool_result_message(self, call: ToolCall, content: str) -> Message:
        return {"role": "tool", "tool_call_id": call.id, "content": content}


def _last_user_text(messages: list[Message]) -> str:
    for message in reversed(messages):
        if message.get("role") == "user" and isinstance(message.get("content"), str):
            return str(message["content"]).lower()
    return ""


def _last_tool_result(messages: list[Message]) -> str | None:
    for message in reversed(messages):
        if message.get("role") == "tool":
            return str(message.get("content") or "")
    return None


def _tool_call_for_prompt(prompt: str) -> ToolCall | None:
    industrial_args = {
        "assets_path": "examples/industrial/assets.csv",
        "alerts_path": "examples/industrial/ids_alerts.json",
        "ioc_path": "examples/industrial/ioc.txt",
        "vuln_path": "examples/industrial/vulns.json",
    }
    if any(word in prompt for word in ["bruteforce", "brute force", "暴力", "爆破"]):
        return ToolCall(
            "fake_call_1",
            "detect_bruteforce",
            {"alerts_path": "examples/industrial/ids_alerts.json", "threshold": 3},
        )
    if any(word in prompt for word in ["lateral", "横向"]):
        return ToolCall("fake_call_1", "detect_lateral_movement", industrial_args)
    if any(word in prompt for word in ["suspicious ot", "可疑 ot", "可疑工业", "异常工业"]):
        return ToolCall("fake_call_1", "detect_suspicious_ot_access", industrial_args)
    if any(word in prompt for word in ["parse assets", "asset inventory", "资产清单"]):
        return ToolCall("fake_call_1", "parse_assets", {"assets_path": "examples/industrial/assets.csv"})
    if any(word in prompt for word in ["parse alerts", "alert json", "告警"]):
        return ToolCall("fake_call_1", "parse_alerts", {"alerts_path": "examples/industrial/ids_alerts.json"})
    if any(word in prompt for word in ["ioc", "indicator", "威胁情报"]):
        return ToolCall(
            "fake_call_1",
            "match_iocs",
            {"alerts_path": "examples/industrial/ids_alerts.json", "ioc_path": "examples/industrial/ioc.txt"},
        )
    if any(word in prompt for word in ["evaluate rag", "rag benchmark", "rag evaluation"]):
        return ToolCall(
            "fake_call_1",
            "evaluate_rag",
            {
                "eval_path": "tests/fixtures/rag_eval.json",
                "knowledge_path": "knowledge",
                "backend": "local",
                "top_k_values": [1, 3, 5, 8],
                "query_strategies": ["description_only", "description_port", "description_port_hint"],
            },
        )
    if any(word in prompt for word in ["rag", "knowledge", "知识库", "风电", "鐭ヨ瘑搴?", "椋庣數", "wind"]):
        return ToolCall(
            "fake_call_1",
            "generate_rag_threat_report",
            {
                "alerts_path": "examples/wind_power/alerts.csv",
                "knowledge_path": "knowledge",
                "top_k": 8,
            },
        )
    if any(word in prompt for word in ["industrial", "ot", "ics", "plc", "scada", "firewall", "threat", "工控", "工业"]):
        return ToolCall("fake_call_1", "generate_threat_report", industrial_args)
    if any(word in prompt for word in ["secret", "credential", "api key", "token", "password"]):
        return ToolCall("fake_call_1", "scan_secrets", {"path": "."})
    if "diff" in prompt or "git" in prompt:
        return ToolCall("fake_call_1", "git_diff", {})
    if any(word in prompt for word in ["dependency", "dependencies", "package", "requirements"]):
        return ToolCall("fake_call_1", "scan_dependency_files", {"path": "."})
    if "report" in prompt:
        return ToolCall("fake_call_1", "generate_security_report", {"path": "."})
    if any(word in prompt for word in ["security", "scan", "insecure", "risk", "audit"]):
        return ToolCall("fake_call_1", "scan_insecure_patterns", {"path": "."})
    if any(word in prompt for word in ["structure", "files", "directory"]):
        return ToolCall("fake_call_1", "list_dir", {"path": "."})
    return None


def _summarize_tool_result(tool_result: str) -> str:
    if len(tool_result) > 4000:
        tool_result = tool_result[:4000] + "\n...[truncated]..."
    return (
        "Local analysis completed.\n\n"
        "Tool result:\n"
        f"{tool_result}\n\n"
        "Review the listed findings, evidence, and recommended next actions before making operational changes."
    )
