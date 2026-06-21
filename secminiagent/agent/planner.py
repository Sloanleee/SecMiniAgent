from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from secminiagent.tools.base import BaseTool, ToolContext, ToolResult


@dataclass(slots=True)
class PlanState:
    items: list[dict[str, str]] = field(default_factory=list)

    def render(self) -> str:
        if not self.items:
            return "(no active plan)"
        return "\n".join(f"- [{item.get('status', 'pending')}] {item.get('step', '')}" for item in self.items)


class CreatePlanTool(BaseTool):
    name = "create_plan"
    description = "Create a short security review plan."
    read_only = False
    input_schema = {
        "type": "object",
        "required": ["steps"],
        "properties": {
            "steps": {
                "type": "array",
                "items": {"type": "string"},
            }
        },
    }

    async def execute(self, arguments: dict[str, Any], context: ToolContext) -> ToolResult:
        if not hasattr(context, "plan_state") or context.plan_state is None:
            return ToolResult(False, "No plan state is available.")
        context.plan_state.items = [
            {"step": str(step), "status": "pending"} for step in arguments.get("steps", [])
        ]
        return ToolResult(True, "Plan created:\n" + context.plan_state.render())


class UpdatePlanTool(BaseTool):
    name = "update_plan"
    description = "Replace the current security review plan with updated step statuses."
    read_only = False
    input_schema = {
        "type": "object",
        "required": ["items"],
        "properties": {
            "items": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["step", "status"],
                    "properties": {
                        "step": {"type": "string"},
                        "status": {"type": "string", "enum": ["pending", "in_progress", "completed"]},
                    },
                },
            }
        },
    }

    async def execute(self, arguments: dict[str, Any], context: ToolContext) -> ToolResult:
        if not hasattr(context, "plan_state") or context.plan_state is None:
            return ToolResult(False, "No plan state is available.")
        context.plan_state.items = [
            {"step": str(item.get("step", "")), "status": str(item.get("status", "pending"))}
            for item in arguments.get("items", [])
        ]
        return ToolResult(True, "Plan updated:\n" + context.plan_state.render())
