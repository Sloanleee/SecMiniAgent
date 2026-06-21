from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from . import __version__
from .agent.events import AgentEvent
from .agent.loop import AgentLoop
from .agent.planner import CreatePlanTool, PlanState, UpdatePlanTool
from .config import AppConfig, load_dotenv
from .llm.fake import FakeLLMClient
from .llm.openai_client import OpenAIClient
from .llm.volcengine_client import VolcengineClient
from .llm.xfyun_client import XfyunClient
from .safety.permissions import PermissionManager
from .skills.loader import SkillLoader
from .storage.transcript import TranscriptStore
from .tools.file_tools import ListDirTool, ReadFileTool, WriteFileTool
from .tools.git_tools import GitDiffTool, GitLogTool, GitStatusTool
from .tools.patch_tool import ApplyPatchTool
from .tools.registry import ToolRegistry
from .tools.search_tool import SearchCodeTool
from .tools.security_tools import GenerateSecurityReportTool, ScanDependencyFilesTool, ScanInsecurePatternsTool, ScanSecretsTool
from .tools.shell_tool import RunShellTool
from .tools.threat_tools import (
    AnalyzeAssetRiskTool,
    CorrelateAlertsTool,
    DetectBruteforceTool,
    DetectLateralMovementTool,
    DetectSuspiciousOtAccessTool,
    ExtractIocsTool,
    GenerateThreatReportTool,
    MatchIocsTool,
    ParseAlertsTool,
    ParseAssetsTool,
)


PROVIDERS = ("fake", "openai", "volcengine", "xfyun")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SecMiniAgent local security review agent prototype.")
    parser.add_argument("prompt", nargs="*", help="Security review task. If omitted, starts interactive mode later.")
    parser.add_argument("--version", action="version", version=f"secminiagent {__version__}")
    parser.add_argument("--provider", choices=PROVIDERS, help="LLM provider.")
    parser.add_argument("--model", help="Model name or provider-specific model id.")
    parser.add_argument("--cwd", help="Workspace directory. Defaults to the current directory.")
    parser.add_argument("--max-turns", type=int, default=8)
    parser.add_argument("--max-context-chars", type=int, default=80_000)
    parser.add_argument("--max-tool-output-chars", type=int, default=12_000)
    parser.add_argument("--yes", action="store_true", help="Auto-approve commands classified as ask. Deny rules still block.")
    parser.add_argument("--resume", help="Resume a saved session id from .secminiagent/sessions.")
    parser.add_argument("--skill", action="append", default=[], help="Force-load a skill by name. Repeatable.")
    parser.add_argument("--env-file", help="Load environment variables from this file instead of <cwd>/.env.")
    parser.add_argument("--no-env", action="store_true", help="Do not load .env automatically.")
    parser.add_argument("--no-stream", action="store_true", help="Print only the final assistant message.")
    parser.add_argument("--list-skills", action="store_true", help="List available built-in and local skills.")
    parser.add_argument("--show-config", action="store_true", help="Print resolved configuration and exit.")
    return parser


def build_registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(ListDirTool())
    registry.register(ReadFileTool())
    registry.register(SearchCodeTool())
    registry.register(GitStatusTool())
    registry.register(GitDiffTool())
    registry.register(GitLogTool())
    registry.register(ScanSecretsTool())
    registry.register(ScanInsecurePatternsTool())
    registry.register(ScanDependencyFilesTool())
    registry.register(GenerateSecurityReportTool())
    registry.register(ParseAssetsTool())
    registry.register(ParseAlertsTool())
    registry.register(ExtractIocsTool())
    registry.register(MatchIocsTool())
    registry.register(AnalyzeAssetRiskTool())
    registry.register(CorrelateAlertsTool())
    registry.register(DetectBruteforceTool())
    registry.register(DetectLateralMovementTool())
    registry.register(DetectSuspiciousOtAccessTool())
    registry.register(GenerateThreatReportTool())
    registry.register(RunShellTool())
    registry.register(ApplyPatchTool())
    registry.register(WriteFileTool())
    registry.register(CreatePlanTool())
    registry.register(UpdatePlanTool())
    return registry


def build_client(config: AppConfig):
    if config.provider == "fake":
        return FakeLLMClient()
    if config.provider == "openai":
        return OpenAIClient(model=config.model)
    if config.provider == "volcengine":
        return VolcengineClient(model=config.model)
    if config.provider == "xfyun":
        return XfyunClient(model=config.model)
    raise ValueError(f"Unsupported provider: {config.provider}")


def build_event_renderer():
    state = {"open_text": False}

    def close_text_line() -> None:
        if state["open_text"]:
            print()
            state["open_text"] = False

    async def render(event: AgentEvent) -> None:
        if event.type == "model_start":
            close_text_line()
            payload = event.payload
            print(f"[model] {payload['provider']}:{payload['model']} turn {payload['turn']}", flush=True)
        elif event.type == "assistant_delta":
            print(event.payload["text"], end="", flush=True)
            state["open_text"] = True
        elif event.type == "tool_start":
            close_text_line()
            payload = event.payload
            args_preview = json.dumps(payload.get("arguments", {}), ensure_ascii=False)
            if len(args_preview) > 160:
                args_preview = args_preview[:157] + "..."
            print(f"[tool] {payload['name']} {args_preview}", flush=True)
        elif event.type == "tool_done":
            close_text_line()
            payload = event.payload
            status = "OK" if payload["success"] else "ERROR"
            print(f"[tool] {payload['name']} -> {status} ({payload['output_chars']} chars)", flush=True)

    return render


async def run_once(args: argparse.Namespace) -> int:
    cwd = Path(args.cwd or Path.cwd()).resolve()
    if not args.no_env:
        env_file = Path(args.env_file).expanduser() if args.env_file else cwd / ".env"
        if not env_file.is_absolute():
            env_file = cwd / env_file
        load_dotenv(env_file)

    config = AppConfig.from_values(
        cwd=str(cwd),
        provider=args.provider,
        model=args.model,
        max_turns=args.max_turns,
        max_context_chars=args.max_context_chars,
        max_tool_output_chars=args.max_tool_output_chars,
        auto_approve=args.yes,
        session_id=args.resume,
        forced_skills=args.skill,
        stream_output=not args.no_stream,
    )

    if args.show_config:
        print(f"workspace: {config.cwd}")
        print(f"provider: {config.provider}")
        print(f"model: {config.model}")
        print(f"max_turns: {config.max_turns}")
        print(f"stream_output: {config.stream_output}")
        return 0

    skill_loader = SkillLoader(cwd=config.cwd)
    if args.list_skills:
        for skill in skill_loader.load_all():
            print(f"{skill.name}: {skill.description}")
        return 0

    prompt = " ".join(args.prompt).strip()
    interactive = not prompt
    store = TranscriptStore(config.cwd)
    session = store.load(args.resume) if args.resume else store.create()
    registry = build_registry()
    permission_manager = PermissionManager(auto_approve=config.auto_approve, interactive=interactive)
    client = build_client(config)
    event_renderer = build_event_renderer() if config.stream_output else None

    async def ask(text: str) -> None:
        skills = skill_loader.select(text, config.forced_skills)
        loop = AgentLoop(
            client=client,
            registry=registry,
            config=config,
            session=session,
            permission_manager=permission_manager,
            plan_state=PlanState(),
            skills=skills,
            event_handler=event_renderer,
        )
        result = await loop.run(text)
        if not config.stream_output:
            print(result.final_text)
        print(f"\n[session: {result.session_id}, turns: {result.turns}]")

    if not interactive:
        await ask(prompt)
        return 0

    print("SecMiniAgent interactive mode. Type /exit to quit.")
    print(f"Workspace: {config.cwd}")
    print(f"Provider: {config.provider}")
    print(f"Session: {session.id}")
    while True:
        try:
            text = await asyncio.to_thread(input, "\nsec-mini-agent> ")
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if text.strip() in {"/exit", "/quit"}:
            return 0
        if not text.strip():
            continue
        await ask(text.strip())


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        raise SystemExit(asyncio.run(run_once(args)))
    except RuntimeError as exc:
        print(f"secminiagent: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
