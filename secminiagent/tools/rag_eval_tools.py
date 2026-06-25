from __future__ import annotations

from typing import Any

from secminiagent.rag.benchmark import render_benchmark_markdown, run_rag_benchmark

from .base import BaseTool, ToolContext, ToolResult, truncate_text
from .file_tools import resolve_workspace_path


DEFAULT_TOP_K_VALUES = [1, 3, 5, 8]
DEFAULT_QUERY_STRATEGIES = ["description_only", "description_port", "description_port_hint"]


class EvaluateRagTool(BaseTool):
    name = "evaluate_rag"
    description = (
        "Run a RAG retrieval benchmark over local industrial security knowledge. "
        "Compares backends, top_k values, and query construction strategies."
    )
    read_only = False
    input_schema = {
        "type": "object",
        "properties": {
            "eval_path": {
                "type": "string",
                "default": "tests/fixtures/rag_eval.json",
                "description": "Workspace-relative RAG evaluation dataset JSON path.",
            },
            "knowledge_path": {
                "type": "string",
                "default": "knowledge",
                "description": "Workspace-relative Markdown knowledge directory.",
            },
            "backend": {
                "type": "string",
                "default": "local",
                "enum": ["local", "chroma", "all"],
            },
            "top_k_values": {
                "type": "array",
                "items": {"type": "integer"},
                "default": DEFAULT_TOP_K_VALUES,
            },
            "query_strategies": {
                "type": "array",
                "items": {"type": "string"},
                "default": DEFAULT_QUERY_STRATEGIES,
            },
            "write_file": {"type": "boolean", "default": False},
            "output_path": {
                "type": "string",
                "default": ".secminiagent/reports/rag-evaluation.md",
            },
        },
    }

    async def execute(self, arguments: dict[str, Any], context: ToolContext) -> ToolResult:
        eval_arg = str(arguments.get("eval_path") or "tests/fixtures/rag_eval.json")
        knowledge_arg = str(arguments.get("knowledge_path") or "knowledge")
        eval_path = resolve_workspace_path(context.cwd, eval_arg)
        knowledge_path = resolve_workspace_path(context.cwd, knowledge_arg)
        backend_arg = str(arguments.get("backend") or "local").lower()
        backends = ["local", "chroma"] if backend_arg == "all" else [backend_arg]
        top_k_values = [int(item) for item in arguments.get("top_k_values") or DEFAULT_TOP_K_VALUES]
        query_strategies = [str(item) for item in arguments.get("query_strategies") or DEFAULT_QUERY_STRATEGIES]
        rows = run_rag_benchmark(
            eval_path=eval_path,
            knowledge_path=knowledge_path,
            backends=backends,
            top_k_values=top_k_values,
            query_strategies=query_strategies,
            persist_path=context.cwd / ".secminiagent" / "rag" / "chroma",
        )
        report = render_benchmark_markdown(rows, eval_path=eval_arg, knowledge_path=knowledge_arg)
        metadata: dict[str, Any] = {
            "row_count": len(rows),
            "backends": backends,
            "top_k_values": top_k_values,
            "query_strategies": query_strategies,
        }
        if bool(arguments.get("write_file", False)):
            output_arg = str(arguments.get("output_path") or ".secminiagent/reports/rag-evaluation.md")
            output_path = resolve_workspace_path(context.cwd, output_arg)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(report, encoding="utf-8")
            metadata["report_path"] = str(output_path.relative_to(context.cwd))
            report += f"\nReport written to `{output_path.relative_to(context.cwd)}`.\n"
        return ToolResult(True, truncate_text(report, context.max_output_chars), metadata)
