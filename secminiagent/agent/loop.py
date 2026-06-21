from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from secminiagent.config import AppConfig
from secminiagent.context.manager import ContextManager
from secminiagent.llm.base import LLMClient, LLMResponse
from secminiagent.safety.permissions import PermissionManager
from secminiagent.skills.loader import Skill
from secminiagent.storage.transcript import SessionState
from secminiagent.tools.base import ToolContext
from secminiagent.tools.registry import ToolRegistry

from .events import AgentEvent, AgentEventHandler
from .planner import PlanState


SYSTEM_PROMPT = """You are SecMiniAgent, a defensive local security review agent.
Your job is to inspect local code, use tools, identify common security risks, and provide concise remediation guidance.

Rules:
- Use tools for file inspection, code search, Git diff review, and local security scans.
- Focus on defensive code review. Do not provide exploit automation or destructive actions.
- Never claim a test, scan, or command passed unless you observed the tool result.
- Prefer structured findings: severity, location, evidence, recommendation.
- Respect tool errors and workspace boundaries.
"""


@dataclass(slots=True)
class AgentResult:
    final_text: str
    turns: int
    session_id: str


class AgentLoop:
    def __init__(
        self,
        *,
        client: LLMClient,
        registry: ToolRegistry,
        config: AppConfig,
        session: SessionState,
        permission_manager: PermissionManager,
        plan_state: PlanState | None = None,
        context_manager: ContextManager | None = None,
        event_handler: AgentEventHandler | None = None,
        skills: list[Skill] | None = None,
    ) -> None:
        self.client = client
        self.registry = registry
        self.config = config
        self.session = session
        self.permission_manager = permission_manager
        self.plan_state = plan_state or PlanState()
        self.context_manager = context_manager or ContextManager(max_chars=config.max_context_chars)
        self.event_handler = event_handler
        self.skills = skills or []

    async def run(self, prompt: str) -> AgentResult:
        user_message = self.client.user_message(prompt)
        self.session.record_message(user_message)
        final_text = ""

        for turn in range(1, self.config.max_turns + 1):
            await self._emit("model_start", {"turn": turn, "provider": self.config.provider, "model": self.config.model})
            prepared = self.context_manager.prepare(self.session.messages)
            response = await self._complete(prepared)
            await self._emit("model_done", {"turn": turn, "has_tool_calls": bool(response.tool_calls)})
            if response.content and not hasattr(self.client, "stream_complete"):
                await self._emit("assistant_delta", {"text": response.content})
            self.session.record_message(response.assistant_message)
            final_text = response.content

            if not response.tool_calls:
                return AgentResult(final_text=final_text, turns=turn, session_id=self.session.id)

            for call in response.tool_calls:
                await self._emit("tool_start", {"id": call.id, "name": call.name, "arguments": call.arguments})
                tool_result = await self.registry.execute(call.name, call.arguments, self._tool_context())
                await self._emit(
                    "tool_done",
                    {
                        "id": call.id,
                        "name": call.name,
                        "success": tool_result.success,
                        "output_chars": len(tool_result.output),
                    },
                )
                self.session.record(
                    "tool_call",
                    {
                        "id": call.id,
                        "name": call.name,
                        "arguments": call.arguments,
                        "success": tool_result.success,
                    },
                )
                self.session.record_message(self.client.tool_result_message(call, tool_result.to_text()))

        return AgentResult(
            final_text=final_text or "Stopped because max_turns was reached.",
            turns=self.config.max_turns,
            session_id=self.session.id,
        )

    async def _complete(self, prepared_messages: list[dict[str, Any]]) -> LLMResponse:
        stream_complete = getattr(self.client, "stream_complete", None)
        if stream_complete is None or not self.config.stream_output:
            return await self.client.complete(
                messages=prepared_messages,
                tools=self.registry.list(),
                system_prompt=self._build_system_prompt(),
            )

        async def on_delta(text: str) -> None:
            await self._emit("assistant_delta", {"text": text})

        return await stream_complete(
            messages=prepared_messages,
            tools=self.registry.list(),
            system_prompt=self._build_system_prompt(),
            on_delta=on_delta,
        )

    def _tool_context(self) -> ToolContext:
        context = ToolContext(
            cwd=self.config.cwd,
            max_output_chars=self.config.max_tool_output_chars,
            auto_approve=self.config.auto_approve,
            permission_manager=self.permission_manager,
            plan_state=self.plan_state,
        )
        return context

    def _build_system_prompt(self) -> str:
        skill_text = "\n\n".join(f"<skill name={skill.name}>\n{skill.content}\n</skill>" for skill in self.skills)
        return "\n\n".join(
            part
            for part in [
                SYSTEM_PROMPT,
                f"Workspace: {self.config.cwd}",
                f"Current plan:\n{self.plan_state.render()}",
                skill_text,
            ]
            if part
        )

    async def _emit(self, event_type: str, payload: dict[str, Any]) -> None:
        if self.event_handler is None:
            return
        await self.event_handler(AgentEvent(event_type, payload))
