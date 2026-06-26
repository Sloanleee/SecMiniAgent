from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Hashable, Iterable, TypeVar

from secminiagent.rag.backends import create_backend
from secminiagent.rag.evaluator import hit_rate, mrr, precision_at_k, recall_at_k
from secminiagent.rag.query import build_query


T = TypeVar("T", bound=Hashable)


@dataclass(frozen=True, slots=True)
class BenchmarkRow:
    backend: str
    query_strategy: str
    top_k: int
    recall_at_k: float
    precision_at_k: float
    mrr: float
    hit_rate: float
    sample_count: int


def run_rag_benchmark(
    *,
    eval_path: Path,
    knowledge_path: Path,
    backends: list[str],
    top_k_values: list[int],
    query_strategies: list[str],
    persist_path: Path | None = None,
) -> list[BenchmarkRow]:
    samples = _load_eval_samples(eval_path)
    rows: list[BenchmarkRow] = []
    for backend_name in backends:
        backend = create_backend(backend_name, persist_path=persist_path)
        backend.ingest_path(knowledge_path)
        for strategy in query_strategies:
            for top_k in top_k_values:
                retrieved_ids: list[list[str]] = []
                expected_ids: list[set[str]] = []
                for sample in samples:
                    query = build_query(sample, strategy)
                    results = backend.search(query, top_k=top_k)
                    retrieved_ids.append([result.doc_id for result in results])
                    expected_ids.append(set(str(item) for item in sample.get("expected_doc_ids", [])))
                rows.append(
                    BenchmarkRow(
                        backend=backend_name,
                        query_strategy=strategy,
                        top_k=top_k,
                        recall_at_k=recall_at_k(retrieved_ids, expected_ids, k=top_k),
                        precision_at_k=precision_at_k(retrieved_ids, expected_ids, k=top_k),
                        mrr=mrr(retrieved_ids, expected_ids),
                        hit_rate=hit_rate(retrieved_ids, expected_ids, k=top_k),
                        sample_count=len(samples),
                    )
                )
    return rows


def render_benchmark_markdown(rows: list[BenchmarkRow], *, eval_path: str, knowledge_path: str) -> str:
    now = datetime.now(timezone.utc).isoformat()
    sample_count = rows[0].sample_count if rows else 0
    backends = ", ".join(_unique_in_order(row.backend for row in rows))
    top_k_values = ", ".join(str(item) for item in _unique_in_order(row.top_k for row in rows))
    query_strategies = ", ".join(_unique_in_order(row.query_strategy for row in rows))
    lines = [
        "# RAG Evaluation Report",
        "",
        f"Generated: {now}",
        "",
        "## Metadata",
        "",
        f"- Evaluation dataset: `{eval_path}`",
        f"- Knowledge path: `{knowledge_path}`",
        f"- Sample count: {sample_count}",
        f"- Backends: {backends}",
        f"- Top-K values: {top_k_values}",
        f"- Query strategies: {query_strategies}",
        "",
        "## Results",
        "",
        "| Backend | Query Strategy | Top-K | Recall@K | Precision@K | MRR | Hit Rate |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row.backend} | {row.query_strategy} | {row.top_k} | "
            f"{row.recall_at_k:.4f} | {row.precision_at_k:.4f} | {row.mrr:.4f} | {row.hit_rate:.4f} |"
        )
    return "\n".join(lines).rstrip() + "\n"


def _load_eval_samples(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("RAG eval dataset must be a JSON list.")
    return [item for item in data if isinstance(item, dict)]


def _unique_in_order(items: Iterable[T]) -> list[T]:
    values: list[T] = []
    seen: set[T] = set()
    for item in items:
        if item not in seen:
            seen.add(item)
            values.append(item)
    return values
