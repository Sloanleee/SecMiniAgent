from __future__ import annotations

import asyncio
import json
import os
import urllib.error
import urllib.request
from typing import Any, Awaitable, Callable

from .base import LLMResponse, Message, ToolCall, parse_json_object


DeltaCallback = Callable[[str], Awaitable[None]]
FUNCTION_CALL_END = "<|FunctionCallEnd|>"


def _first_env(names: tuple[str, ...]) -> str | None:
    for name in names:
        value = os.getenv(name)
        if value:
            return value
    return None


class OpenAIClient:
    provider = "openai"

    def __init__(
        self,
        *,
        model: str,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout: int = 120,
        api_key_envs: tuple[str, ...] = ("OPENAI_API_KEY",),
        base_url_envs: tuple[str, ...] = ("OPENAI_BASE_URL",),
        default_base_url: str = "https://api.openai.com/v1",
        error_label: str = "OpenAI",
        extra_headers: dict[str, str] | None = None,
        extra_body: dict[str, Any] | None = None,
        stream_options: dict[str, Any] | None = None,
    ) -> None:
        self.model = model
        self.api_key_envs = api_key_envs
        self.error_label = error_label
        self.api_key = api_key or _first_env(api_key_envs)
        self.base_url = (base_url or _first_env(base_url_envs) or default_base_url).rstrip("/")
        self.timeout = timeout
        self.extra_headers = extra_headers or {}
        self.extra_body = extra_body or {}
        self.stream_options = stream_options or {}

    async def complete(
        self,
        *,
        messages: list[Message],
        tools: list[Any],
        system_prompt: str,
    ) -> LLMResponse:
        self._ensure_api_key()
        payload = self._build_payload(messages=messages, tools=tools, system_prompt=system_prompt)
        data = await asyncio.to_thread(self._post_json, "/chat/completions", payload)
        return self._response_from_message(data)

    async def stream_complete(
        self,
        *,
        messages: list[Message],
        tools: list[Any],
        system_prompt: str,
        on_delta: DeltaCallback,
    ) -> LLMResponse:
        self._ensure_api_key()
        payload = self._build_payload(messages=messages, tools=tools, system_prompt=system_prompt)
        payload["stream"] = True
        if self.stream_options:
            payload["stream_options"] = self.stream_options

        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[tuple[str, Any]] = asyncio.Queue()

        def put(kind: str, data: Any) -> None:
            loop.call_soon_threadsafe(queue.put_nowait, (kind, data))

        def worker() -> None:
            try:
                response = self._post_stream_json("/chat/completions", payload, lambda text: put("delta", text))
            except Exception as exc:
                put("error", exc)
                return
            put("done", response)

        worker_task = asyncio.create_task(asyncio.to_thread(worker))
        while True:
            kind, data = await queue.get()
            if kind == "delta":
                await on_delta(str(data))
            elif kind == "error":
                await worker_task
                raise data
            elif kind == "done":
                await worker_task
                if data.content or data.tool_calls:
                    return data
                fallback_payload = self._build_payload(messages=messages, tools=tools, system_prompt=system_prompt)
                fallback_data = await asyncio.to_thread(self._post_json, "/chat/completions", fallback_payload)
                fallback_response = self._response_from_message(fallback_data)
                if fallback_response.content:
                    await on_delta(fallback_response.content)
                return fallback_response

    def user_message(self, content: str) -> Message:
        return {"role": "user", "content": content}

    def tool_result_message(self, call: ToolCall, content: str) -> Message:
        return {"role": "tool", "tool_call_id": call.id, "content": content}

    def _ensure_api_key(self) -> None:
        if not self.api_key:
            names = " or ".join(self.api_key_envs)
            raise RuntimeError(f"{names} is not set.")

    def _build_payload(
        self,
        *,
        messages: list[Message],
        tools: list[Any],
        system_prompt: str,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "system", "content": system_prompt}, *messages],
            "temperature": 0,
        }
        if tools:
            payload["tools"] = [tool.to_openai_schema() for tool in tools]
            payload["tool_choice"] = "auto"
        if self.extra_body:
            payload.update(self.extra_body)
        return payload

    def _response_from_message(self, data: dict[str, Any]) -> LLMResponse:
        choice = data["choices"][0]
        message = choice["message"]
        calls: list[ToolCall] = []
        for raw_call in message.get("tool_calls") or []:
            fn = raw_call.get("function") or {}
            calls.append(
                ToolCall(
                    id=raw_call.get("id", ""),
                    name=fn.get("name", ""),
                    arguments=parse_json_object(fn.get("arguments")),
                )
            )
        content = message.get("content") or ""
        if not calls:
            calls = self._parse_content_tool_calls(content)
            if calls:
                message = self._assistant_message_for_calls(calls)
                content = ""
        return LLMResponse(content=content, tool_calls=calls, assistant_message=message, raw=data)

    def _post_json(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.base_url + path,
            data=body,
            headers=self._headers(),
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"{self.error_label} API error {exc.code}: {detail}") from exc

    def _post_stream_json(
        self,
        path: str,
        payload: dict[str, Any],
        emit_delta: Callable[[str], None],
    ) -> LLMResponse:
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.base_url + path,
            data=body,
            headers=self._headers(),
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return self._consume_stream(resp, emit_delta)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"{self.error_label} API error {exc.code}: {detail}") from exc

    def _consume_stream(self, resp: Any, emit_delta: Callable[[str], None]) -> LLMResponse:
        content_parts: list[str] = []
        tool_chunks: dict[int, dict[str, str]] = {}
        raw_chunks: list[dict[str, Any]] = []
        defer_content: bool | None = None

        for raw_line in resp:
            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line or not line.startswith("data:"):
                continue
            data_text = line[len("data:") :].strip()
            if data_text == "[DONE]":
                break
            chunk = json.loads(data_text)
            raw_chunks.append(chunk)
            choices = chunk.get("choices") or []
            if not choices:
                continue
            delta = choices[0].get("delta") or {}
            content = delta.get("content")
            if content:
                content_parts.append(content)
                if defer_content is None:
                    current = "".join(content_parts).lstrip()
                    if current:
                        defer_content = current[0] in {"[", "{"}
                if not defer_content:
                    emit_delta(content)
            for raw_call in delta.get("tool_calls") or []:
                index = int(raw_call.get("index") or 0)
                state = tool_chunks.setdefault(index, {"id": "", "name": "", "arguments": ""})
                if raw_call.get("id"):
                    state["id"] = raw_call["id"]
                fn = raw_call.get("function") or {}
                if fn.get("name"):
                    state["name"] += fn["name"]
                if fn.get("arguments"):
                    state["arguments"] += fn["arguments"]

        calls: list[ToolCall] = []
        raw_calls: list[dict[str, Any]] = []
        for index in sorted(tool_chunks):
            state = tool_chunks[index]
            call_id = state["id"] or f"call_{index}"
            raw_calls.append(
                {
                    "id": call_id,
                    "type": "function",
                    "function": {"name": state["name"], "arguments": state["arguments"]},
                }
            )
            calls.append(
                ToolCall(
                    id=call_id,
                    name=state["name"],
                    arguments=parse_json_object(state["arguments"]),
                )
            )

        content = "".join(content_parts)
        if not calls:
            calls = self._parse_content_tool_calls(content)
            if calls:
                return LLMResponse(
                    content="",
                    tool_calls=calls,
                    assistant_message=self._assistant_message_for_calls(calls),
                    raw={"stream_chunks": raw_chunks},
                )
        if defer_content:
            emit_delta(content)
        assistant_message: Message = {"role": "assistant", "content": content}
        if raw_calls:
            assistant_message["content"] = content or None
            assistant_message["tool_calls"] = raw_calls
        return LLMResponse(
            content=content,
            tool_calls=calls,
            assistant_message=assistant_message,
            raw={"stream_chunks": raw_chunks},
        )

    def _parse_content_tool_calls(self, content: str) -> list[ToolCall]:
        stripped = content.strip()
        if FUNCTION_CALL_END not in stripped:
            return []
        raw_json = stripped.split(FUNCTION_CALL_END, 1)[0].strip()
        try:
            parsed = json.loads(raw_json)
        except json.JSONDecodeError:
            return []
        items = parsed if isinstance(parsed, list) else [parsed]
        calls: list[ToolCall] = []
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                continue
            function = item.get("function") if isinstance(item.get("function"), dict) else {}
            name = str(item.get("name") or function.get("name") or "").strip()
            if not name:
                continue
            arguments = (
                item.get("arguments")
                if "arguments" in item
                else item.get("parameters")
                if "parameters" in item
                else item.get("input")
                if "input" in item
                else function.get("arguments")
            )
            calls.append(
                ToolCall(
                    id=str(item.get("id") or f"content_call_{index}"),
                    name=name,
                    arguments=parse_json_object(arguments),
                )
            )
        return calls

    def _assistant_message_for_calls(self, calls: list[ToolCall]) -> Message:
        return {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": call.id,
                    "type": "function",
                    "function": {
                        "name": call.name,
                        "arguments": json.dumps(call.arguments, ensure_ascii=False),
                    },
                }
                for call in calls
            ],
        }

    def _headers(self) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        headers.update({key: value for key, value in self.extra_headers.items() if value})
        return headers
