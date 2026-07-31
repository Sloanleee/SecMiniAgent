from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import asdict
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
from .memory.errors import MemoryConfirmationRequired, MemoryError
from .memory.migration import MigrationCapability
from .memory.factory import create_local_memory, create_schema_migrator, create_thread_run_runtime
from .memory.models import MemoryQuery, MemoryScope, NoteKind, NoteStatus
from .safety.permissions import PermissionManager
from .skills.loader import SkillLoader
from .storage.transcript import TranscriptStore
from .tools.file_tools import ListDirTool, ReadFileTool, WriteFileTool
from .tools.git_tools import GitDiffTool, GitLogTool, GitStatusTool
from .tools.patch_tool import ApplyPatchTool
from .tools.rag_eval_tools import EvaluateRagTool
from .tools.rag_tools import (
    ExplainAlertWithRagTool,
    GenerateRagThreatReportTool,
    IngestKnowledgeTool,
    SearchKnowledgeTool,
)
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
    parser.add_argument("--thread", help="Select a Thread when creating or resuming a Schema v2 transcript.")
    parser.add_argument("--skill", action="append", default=[], help="Force-load a skill by name. Repeatable.")
    parser.add_argument("--env-file", help="Load environment variables from this file instead of <cwd>/.env.")
    parser.add_argument("--no-env", action="store_true", help="Do not load .env automatically.")
    parser.add_argument("--no-stream", action="store_true", help="Print only the final assistant message.")
    parser.add_argument("--list-skills", action="store_true", help="List available built-in and local skills.")
    parser.add_argument("--show-config", action="store_true", help="Print resolved configuration and exit.")
    return parser


def build_memory_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secminiagent memory", description="Manage local encrypted memory.")
    parser.add_argument("--cwd", default=".", help="Workspace directory.")
    actions = parser.add_subparsers(dest="memory_action", required=True)
    actions.add_parser("status")
    actions.add_parser("migration-status")

    migrate_schema = actions.add_parser("migrate-schema")
    migrate_schema.add_argument("--to", type=int, default=2)
    migrate_schema.add_argument("--dry-run", action="store_true")
    migrate_schema.add_argument("--yes", action="store_true")

    listing = actions.add_parser("list")
    listing.add_argument("--session")
    listing.add_argument("--limit", type=int, default=50)

    inspect_parser = actions.add_parser("inspect")
    inspect_parser.add_argument("memory_id")
    inspect_parser.add_argument("--session")

    forget = actions.add_parser("forget")
    forget.add_argument("memory_id")
    forget.add_argument("--session")
    forget.add_argument("--yes", action="store_true")

    clear = actions.add_parser("clear")
    target = clear.add_mutually_exclusive_group(required=True)
    target.add_argument("--session")
    target.add_argument("--workspace", action="store_true")
    clear.add_argument("--yes", action="store_true")

    audit = actions.add_parser("audit")
    audit.add_argument("--limit", type=int, default=100)

    migrate = actions.add_parser("migrate-sessions")
    migrate.add_argument("--delete-source", action="store_true")
    migrate.add_argument("--yes", action="store_true")

    actions.add_parser("retry-deletions")
    actions.add_parser("rebuild-index")

    thread = actions.add_parser("thread")
    thread_actions = thread.add_subparsers(dest="thread_action", required=True)
    thread_create = thread_actions.add_parser("create")
    thread_create.add_argument("--session", required=True)
    thread_create.add_argument("--title")
    thread_create.add_argument("--goal")
    thread_list = thread_actions.add_parser("list")
    thread_list.add_argument("--session", required=True)
    thread_list.add_argument("--include-archived", action="store_true")
    thread_use = thread_actions.add_parser("use")
    thread_use.add_argument("thread_id")
    thread_use.add_argument("--session", required=True)
    thread_archive = thread_actions.add_parser("archive")
    thread_archive.add_argument("thread_id")
    thread_archive.add_argument("--session", required=True)

    run = actions.add_parser("run")
    run_actions = run.add_subparsers(dest="run_action", required=True)
    run_list = run_actions.add_parser("list")
    run_list.add_argument("--session", required=True)
    run_list.add_argument("--thread", required=True)
    run_interrupt = run_actions.add_parser("interrupt")
    run_interrupt.add_argument("run_id")
    run_interrupt.add_argument("--session", required=True)
    run_interrupt.add_argument("--thread", required=True)

    transcript = actions.add_parser("transcript")
    transcript_actions = transcript.add_subparsers(dest="transcript_action", required=True)
    transcript_inspect = transcript_actions.add_parser("inspect")
    transcript_inspect.add_argument("--session", required=True)
    transcript_inspect.add_argument("--thread", required=True)
    transcript_inspect.add_argument("--metadata-only", action="store_true")

    summary = actions.add_parser("summary")
    summary_actions = summary.add_subparsers(dest="summary_action", required=True)
    for name in ("build", "status"):
        summary_command = summary_actions.add_parser(name)
        summary_command.add_argument("--session", required=True)
        summary_command.add_argument("--thread", required=True)

    note = actions.add_parser("note")
    note_actions = note.add_subparsers(dest="note_action", required=True)
    note_add = note_actions.add_parser("add")
    note_add.add_argument("--session", required=True)
    note_add.add_argument("--thread", required=True)
    note_add.add_argument("--kind", choices=[item.value for item in NoteKind], default=NoteKind.FACT.value)
    note_list = note_actions.add_parser("list")
    note_list.add_argument("--session", required=True)
    note_list.add_argument("--thread")
    note_list.add_argument("--scope", choices=[item.value for item in MemoryScope])
    note_list.add_argument("--status", action="append", choices=[item.value for item in NoteStatus])
    for name in ("show", "confirm", "revise", "retract", "promote-preview", "promote"):
        command = note_actions.add_parser(name)
        command.add_argument("note_id")
        command.add_argument("--session", required=True)
        command.add_argument("--thread")
        if name in {"confirm", "revise", "retract"}:
            command.add_argument("--expected-version", type=int, required=True)
        if name == "retract":
            command.add_argument("--reason-code", required=True)
        if name in {"promote-preview", "promote"}:
            command.add_argument("--to", required=True, choices=[MemoryScope.SESSION.value, MemoryScope.WORKSPACE.value])
        if name == "promote":
            command.add_argument("--confirmation-token", required=True)
        if name == "show":
            command.add_argument("--show-content", action="store_true")

    search = actions.add_parser("search")
    search.add_argument("query", nargs="?")
    search.add_argument("--session", required=True)
    search.add_argument("--thread")
    search.add_argument("--scope", action="append", choices=[item.value for item in MemoryScope])
    search.add_argument("--limit", type=int, default=20)
    search.add_argument("--explain", action="store_true")
    search.add_argument("--show-content", action="store_true")

    candidate = actions.add_parser("candidate")
    candidate_actions = candidate.add_subparsers(dest="candidate_action", required=True)
    candidate_list = candidate_actions.add_parser("list")
    candidate_list.add_argument("--session", required=True)
    candidate_list.add_argument("--thread", required=True)
    for name in ("inspect", "confirm", "reject"):
        command = candidate_actions.add_parser(name)
        command.add_argument("note_id")
        command.add_argument("--session", required=True)
        command.add_argument("--thread", required=True)
        if name in {"confirm", "reject"}:
            command.add_argument("--expected-version", type=int, required=True)
        if name == "inspect":
            command.add_argument("--show-content", action="store_true")

    index_command = actions.add_parser("index")
    index_actions = index_command.add_subparsers(dest="index_action", required=True)
    reconcile = index_actions.add_parser("reconcile")
    reconcile.add_argument("--session", required=True)
    reconcile.add_argument("--thread")
    reconcile.add_argument("--dry-run", action="store_true")

    retention = actions.add_parser("retention")
    retention_actions = retention.add_subparsers(dest="retention_action", required=True)
    retention_show = retention_actions.add_parser("show")
    retention_show.add_argument("memory_id")
    retention_show.add_argument("--session", required=True)
    retention_show.add_argument("--thread")
    retention_apply = retention_actions.add_parser("apply")
    retention_apply.add_argument("--session", required=True)
    retention_apply.add_argument("--thread")
    retention_apply.add_argument("--expired", action="store_true", required=True)
    retention_apply.add_argument("--yes", action="store_true")
    for action_name in ("pin", "unpin"):
        command = actions.add_parser(action_name)
        command.add_argument("memory_id")
        command.add_argument("--session", required=True)
        command.add_argument("--thread")
    for action_name in ("clear-run", "clear-thread"):
        command = actions.add_parser(action_name)
        command.add_argument("root_id")
        command.add_argument("--session", required=True)
        command.add_argument("--thread")
        command.add_argument("--preview", action="store_true")
        command.add_argument("--yes", action="store_true")
        command.add_argument("--confirmation-token")
        command.add_argument("--retain-token", action="append", default=[])
    deletion = actions.add_parser("deletion")
    deletion_actions = deletion.add_subparsers(dest="deletion_action", required=True)
    for name in ("status", "resume"):
        command = deletion_actions.add_parser(name)
        command.add_argument("job_id")
        command.add_argument("--session", required=True)
        command.add_argument("--thread")
    return parser


def _safe_thread_json(item: object) -> dict[str, object]:
    return {
        "thread_id": item.thread_id,
        "session_id": item.session_id,
        "status": item.status.value,
        "next_run_no": item.next_run_no,
        "next_thread_sequence": item.next_thread_sequence,
        "state_version": item.state_version,
        "created_at": item.created_at.isoformat() if item.created_at else None,
        "updated_at": item.updated_at.isoformat() if item.updated_at else None,
    }


def _safe_run_json(item: object) -> dict[str, object]:
    return {
        "run_id": item.run_id,
        "thread_id": item.thread_id,
        "status": item.status.value,
        "run_no": item.run_no,
        "next_run_sequence": item.next_run_sequence,
        "state_version": item.state_version,
        "started_at": item.started_at.isoformat() if item.started_at else None,
        "completed_at": item.completed_at.isoformat() if item.completed_at else None,
        "reason_code": item.interruption_reason_code,
    }


def _safe_note_json(item: object, *, show_content: bool = False) -> dict[str, object]:
    value = {
        "note_id": item.note_id, "scope": item.scope.value,
        "session_id": item.session_id, "thread_id": item.thread_id,
        "kind": item.kind.value, "status": item.status.value,
        "verification": item.verification.value, "classification": item.classification.value,
        "revision": item.revision, "source_count": len(item.source_refs),
    }
    if show_content:
        value["content"] = item.content
    return value


def run_memory_command(argv: list[str]) -> int:
    args = build_memory_parser().parse_args(argv)
    cwd = Path(args.cwd).resolve()
    if args.memory_action in {"migration-status", "migrate-schema"}:
        try:
            migrator = create_schema_migrator(cwd)
            if args.memory_action == "migration-status":
                print(json.dumps(asdict(migrator.inspect()), ensure_ascii=False, indent=2))
                return 0
            if args.to != 2:
                raise ValueError("only target schema 2 is supported")
            if args.dry_run:
                print(json.dumps(asdict(migrator.dry_run()), ensure_ascii=False, indent=2))
                return 0
            if not args.yes:
                print("secminiagent memory: MIGRATION_CONFIRMATION_REQUIRED", file=sys.stderr)
                return 1
            capability = MigrationCapability.verified_v2_runtime()
            migrator.prepare_shadow(capability)
            report = migrator.activate(capability)
            print(json.dumps(asdict(report), ensure_ascii=False, indent=2))
            return 0
        except (MemoryError, FileNotFoundError, ValueError) as exc:
            print(f"secminiagent memory: {exc}", file=sys.stderr)
            return 1
    if args.memory_action in {"thread", "run", "transcript", "summary", "note", "search", "candidate", "index", "retention", "pin", "unpin", "clear-run", "clear-thread", "deletion"}:
        try:
            thread_id = getattr(args, "thread_id", None) or getattr(args, "thread", None)
            if args.memory_action in {"retention", "pin", "unpin", "clear-run", "clear-thread", "deletion"}:
                from .memory.factory import create_retention_deletion_runtime
                note_service, retention_service, deletion_service, context = create_retention_deletion_runtime(
                    cwd, session_id=args.session, thread_id=thread_id, provider="local",
                )
            elif args.memory_action in {"search", "candidate", "index"}:
                from .memory.factory import create_advanced_memory_runtime
                note_service, search_service, candidate_service, context = create_advanced_memory_runtime(
                    cwd, session_id=args.session, thread_id=thread_id, provider="local",
                )
            elif args.memory_action == "note":
                from .memory.factory import create_long_term_runtime
                note_service, context = create_long_term_runtime(
                    cwd, session_id=args.session, thread_id=thread_id, provider="local",
                )
            elif args.memory_action == "summary":
                from .memory.factory import create_note_summary_runtime
                service, transcript_service, notes_service, summary_service, context = create_note_summary_runtime(
                    cwd, session_id=args.session, thread_id=thread_id, provider="local",
                )
            elif args.memory_action == "transcript":
                from .memory.factory import create_thread_transcript_runtime
                service, transcript_service, context = create_thread_transcript_runtime(
                    cwd, session_id=args.session, thread_id=thread_id, provider="local",
                )
            else:
                service, context = create_thread_run_runtime(
                    cwd, session_id=args.session, thread_id=thread_id, provider="local",
                )
            if args.memory_action == "retention":
                if args.retention_action == "show":
                    item = retention_service.decision(context, args.memory_id)
                    print(json.dumps({"memory_id": item.memory_id, "expires_at": item.expires_at.isoformat() if item.expires_at else None, "pinned": item.pinned, "reason_code": item.reason_code}, ensure_ascii=False))
                elif args.retention_action == "apply":
                    ids = retention_service.scan_expired(context, dry_run=not args.yes)
                    print(json.dumps({"candidate_count" if not args.yes else "expired_count": len(ids)}, ensure_ascii=False))
            elif args.memory_action in {"pin", "unpin"}:
                item = retention_service.pin(context, args.memory_id, args.memory_action == "pin")
                print(json.dumps({"memory_id": item.memory_id, "pinned": item.pinned, "reason_code": item.reason_code}, ensure_ascii=False))
            elif args.memory_action in {"clear-run", "clear-thread"}:
                root_type = "run" if args.memory_action == "clear-run" else "thread"
                if args.preview:
                    item = deletion_service.preview(context, root_type, args.root_id)
                    print(json.dumps({
                        "root_type": item.root_type, "root_id_hash": item.root_id_hash,
                        "direct_memory_count": item.direct_memory_count,
                        "derived_memory_count": item.derived_memory_count,
                        "promoted_workspace_count": item.promoted_workspace_count,
                        "chroma_delete_count": item.chroma_delete_count,
                        "snapshot_digest": item.snapshot_digest,
                        "confirmation_token": item.confirmation_token,
                        "expires_unix": item.expires_unix,
                        "independent_retention_tokens": [preview.confirmation_token for preview in item.retention_confirmations],
                    }, ensure_ascii=False))
                else:
                    if not args.yes or not args.confirmation_token:
                        raise MemoryConfirmationRequired("DELETION_PREVIEW_CONFIRMATION_REQUIRED")
                    item = deletion_service.execute(
                        context, root_type, args.root_id, args.confirmation_token,
                        independent_retention_tokens=tuple(args.retain_token),
                    )
                    print(json.dumps(asdict(item), ensure_ascii=False))
            elif args.memory_action == "deletion":
                item = deletion_service.status(context, args.job_id) if args.deletion_action == "status" else deletion_service.resume(context, args.job_id)
                print(json.dumps(asdict(item), ensure_ascii=False))
            elif args.memory_action == "search":
                query = args.query if args.query is not None else sys.stdin.read()
                for item in search_service.search(
                    context, query, limit=args.limit,
                    scopes=tuple(MemoryScope(value) for value in (args.scope or ())),
                ):
                    value = {
                        "memory_id": item.memory_id, "scope": item.scope.value,
                        "memory_type": item.memory_type.value,
                        "classification": item.classification.value,
                        "verification": item.verification.value, "status": item.status.value,
                        "score_millis": item.score_millis,
                    }
                    if args.explain:
                        value["reason_codes"] = item.reason_codes
                        value["features"] = [{"name": feature.name, "value_millis": feature.value_millis, "contribution_millis": feature.contribution_millis} for feature in item.features]
                    if args.show_content:
                        value["content"] = item.content
                    print(json.dumps(value, ensure_ascii=False))
            elif args.memory_action == "candidate":
                if args.candidate_action == "list":
                    for item in note_service.list_notes(context, statuses=(NoteStatus.CANDIDATE,)):
                        print(json.dumps(_safe_note_json(item), ensure_ascii=False))
                elif args.candidate_action == "inspect":
                    print(json.dumps(_safe_note_json(
                        note_service.get_note(context, args.note_id), show_content=args.show_content,
                    ), ensure_ascii=False))
                elif args.candidate_action == "confirm":
                    item = note_service.confirm_note(context, args.note_id, args.expected_version)
                    print(json.dumps(_safe_note_json(item), ensure_ascii=False))
                elif args.candidate_action == "reject":
                    item = candidate_service.reject(context, args.note_id, args.expected_version)
                    print(json.dumps(_safe_note_json(item), ensure_ascii=False))
            elif args.memory_action == "index":
                ids = note_service.reconcile_index(context, dry_run=args.dry_run)
                print(json.dumps({"candidate_count" if args.dry_run else "reconciled_count": len(ids)}, ensure_ascii=False))
            elif args.memory_action == "note":
                if args.note_action == "add":
                    item = note_service.add_note(context, sys.stdin.read(), MemoryScope.THREAD, NoteKind(args.kind))
                    print(json.dumps(_safe_note_json(item), ensure_ascii=False))
                elif args.note_action == "list":
                    statuses = tuple(NoteStatus(item) for item in args.status) if args.status else (NoteStatus.ACTIVE,)
                    for item in note_service.list_notes(
                        context, scope=MemoryScope(args.scope) if args.scope else None, statuses=statuses,
                    ):
                        print(json.dumps(_safe_note_json(item), ensure_ascii=False))
                elif args.note_action == "show":
                    print(json.dumps(_safe_note_json(
                        note_service.get_note(context, args.note_id), show_content=args.show_content,
                    ), ensure_ascii=False))
                elif args.note_action == "confirm":
                    item = note_service.confirm_note(context, args.note_id, args.expected_version)
                    print(json.dumps(_safe_note_json(item), ensure_ascii=False))
                elif args.note_action == "revise":
                    item = note_service.revise_note(context, args.note_id, sys.stdin.read(), args.expected_version)
                    print(json.dumps(_safe_note_json(item), ensure_ascii=False))
                elif args.note_action == "retract":
                    item = note_service.retract_note(context, args.note_id, args.reason_code, args.expected_version)
                    print(json.dumps(_safe_note_json(item), ensure_ascii=False))
                elif args.note_action == "promote-preview":
                    preview = note_service.preview_promotion(context, args.note_id, MemoryScope(args.to))
                    print(json.dumps({
                        "source_note_id": preview.source_note_id,
                        "source_revision": preview.source_revision,
                        "target_scope": preview.target_scope.value,
                        "classification": preview.classification.value,
                        "requires_confirmation": preview.requires_confirmation,
                        "confirmation_token": preview.confirmation_token,
                        "expires_unix": preview.expires_unix,
                        "purpose": preview.purpose,
                    }, ensure_ascii=False))
                elif args.note_action == "promote":
                    item = note_service.promote_note(
                        context, args.note_id, MemoryScope(args.to), args.confirmation_token,
                    )
                    print(json.dumps(_safe_note_json(item), ensure_ascii=False))
            elif args.memory_action == "thread":
                if args.thread_action == "create":
                    item = service.create_thread(context, args.title, args.goal)
                    print(json.dumps(_safe_thread_json(item), ensure_ascii=False))
                elif args.thread_action == "list":
                    for item in service.list_threads(context, args.include_archived):
                        print(json.dumps(_safe_thread_json(item), ensure_ascii=False))
                elif args.thread_action == "use":
                    item = service.activate_thread(context, args.thread_id)
                    print(json.dumps(_safe_thread_json(item), ensure_ascii=False))
                elif args.thread_action == "archive":
                    item = service.archive_thread(context, args.thread_id)
                    print(json.dumps(_safe_thread_json(item), ensure_ascii=False))
            elif args.memory_action == "transcript" and args.transcript_action == "inspect":
                for item in transcript_service.resume(context):
                    value = {
                        "message_id": item.message_id, "thread_id": item.thread_id,
                        "run_id": item.run_id, "thread_sequence": item.thread_sequence,
                        "run_sequence": item.run_sequence, "role": item.role,
                        "created_at": item.created_at.isoformat(),
                    }
                    if not args.metadata_only:
                        value["message"] = dict(item.message)
                    print(json.dumps(value, ensure_ascii=False))
            elif args.memory_action == "summary":
                item = summary_service.build(context) if args.summary_action == "build" else summary_service.active(context)
                value = None if item is None else {
                    "summary_id": item.summary_id, "thread_id": item.thread_id,
                    "version": item.version, "status": item.status.value,
                    "verification": item.verification.value,
                    "classification": item.classification.value,
                    "covered_through_sequence": item.covered_through_sequence,
                    "source_count": len(item.source_memory_ids),
                }
                print(json.dumps(value, ensure_ascii=False))
            elif args.run_action == "list":
                for item in service.list_runs(context, args.thread):
                    print(json.dumps(_safe_run_json(item), ensure_ascii=False))
            elif args.run_action == "interrupt":
                item = service.interrupt_run(context, args.run_id)
                print(json.dumps(_safe_run_json(item), ensure_ascii=False))
            return 0
        except (MemoryError, FileNotFoundError, ValueError) as exc:
            print(f"secminiagent memory: {exc}", file=sys.stderr)
            return 1
    session_id = getattr(args, "session", None)
    service, context = create_local_memory(cwd, provider="local", session_id=session_id, enable_chroma=True)
    action = args.memory_action
    try:
        if action == "status":
            print(json.dumps(service.status(context), ensure_ascii=False, indent=2))
        elif action == "list":
            rows = service.list_metadata(MemoryQuery(limit=args.limit), context)
            for item in rows:
                print(
                    json.dumps(
                        {
                            "id": item.id,
                            "scope": item.scope.value,
                            "session_id": item.session_id,
                            "type": item.memory_type.value,
                            "classification": item.classification.value,
                            "created_at": item.created_at.isoformat(),
                            "index_status": item.index_status.value,
                        },
                        ensure_ascii=False,
                    )
                )
        elif action == "inspect":
            record = service.recall(args.memory_id, context)
            print(
                json.dumps(
                    {
                        "id": record.metadata.id,
                        "scope": record.metadata.scope.value,
                        "classification": record.metadata.classification.value,
                        "content": record.content,
                        "attributes": dict(record.attributes),
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
        elif action == "forget":
            if not _confirm_destructive(args.yes, f"Delete memory {args.memory_id}?"):
                return 1
            print(json.dumps(asdict(service.forget(args.memory_id, context)), default=str, ensure_ascii=False))
        elif action == "clear":
            label = f"session {args.session}" if args.session else "the entire workspace"
            if not _confirm_destructive(args.yes, f"Delete memories for {label}?"):
                return 1
            receipts = service.clear_session(context) if args.session else service.clear_workspace(context)
            service.vacuum()
            print(json.dumps({"deleted": len(receipts)}, ensure_ascii=False))
        elif action == "audit":
            for event in service.audit_events(context, args.limit):
                print(json.dumps(asdict(event), default=str, ensure_ascii=False))
        elif action == "migrate-sessions":
            if args.delete_source and not args.yes:
                raise RuntimeError("--delete-source requires --yes")
            report = TranscriptStore(cwd).migrate_legacy_sessions(delete_source=args.delete_source)
            print(json.dumps(asdict(report), ensure_ascii=False, indent=2))
        elif action == "retry-deletions":
            print(json.dumps({"completed": list(service.retry_pending_deletions(context))}, ensure_ascii=False))
        elif action == "rebuild-index":
            print(json.dumps({"indexed": service.rebuild_index(context)}, ensure_ascii=False))
        return 0
    except (MemoryError, FileNotFoundError, ValueError) as exc:
        print(f"secminiagent memory: {exc}", file=sys.stderr)
        return 1
    finally:
        service.close()


def _confirm_destructive(assume_yes: bool, prompt: str) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        return False
    return input(f"{prompt} [y/N] ").strip().lower() in {"y", "yes"}


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
    registry.register(IngestKnowledgeTool())
    registry.register(SearchKnowledgeTool())
    registry.register(ExplainAlertWithRagTool())
    registry.register(GenerateRagThreatReportTool())
    registry.register(EvaluateRagTool())
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
    store = TranscriptStore(config.cwd, thread_id=args.thread, provider=config.provider)
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
    if len(sys.argv) > 1 and sys.argv[1] == "memory":
        raise SystemExit(run_memory_command(sys.argv[2:]))
    parser = build_parser()
    args = parser.parse_args()
    try:
        raise SystemExit(asyncio.run(run_once(args)))
    except RuntimeError as exc:
        print(f"secminiagent: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
