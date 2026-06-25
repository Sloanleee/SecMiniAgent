# SecMiniAgent RAG Benchmark Chroma Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a reproducible RAG benchmark system with `local` and optional `chroma` retrieval backends, query strategy comparison, retrieval metrics, and Markdown result tables.

**Architecture:** Keep the current deterministic local RAG path as the default baseline, then add a thin backend abstraction so benchmark code can run against `local`, `chroma`, or both. Chroma is optional and must not break default no-dependency usage; evaluation results are produced by a dedicated `evaluate_rag` tool instead of bloating the existing threat-report tool.

**Tech Stack:** Python 3.11+, `unittest`, optional `chromadb>=0.5.0`, existing Function Calling tools, JSON Schema, local deterministic embeddings.

## Global Constraints

- Chroma is an optional dependency only; default SecMiniAgent must run without `chromadb`.
- Do not add real embedding API calls in this phase.
- Keep existing local deterministic RAG behavior working.
- Store Chroma runtime data under `.secminiagent/rag/chroma/`.
- Do not commit `.secminiagent/` runtime files.
- `evaluate_rag` must support `backend=local`, `backend=chroma`, and `backend=all`.
- Benchmark must compare `top_k=1`, `top_k=3`, `top_k=5`, and `top_k=8`.
- Benchmark must compare `description_only`, `description_port`, and `description_port_hint`.
- Metrics must include `recall@k`, `precision@k`, `mrr`, and `hit_rate`.
- README result values must come from actual tool output, not hand-written fake numbers.

---

## File Structure

Create:

```text
secminiagent/rag/query.py
secminiagent/rag/backends.py
secminiagent/rag/benchmark.py
secminiagent/tools/rag_eval_tools.py
tests/test_rag_query.py
tests/test_rag_benchmark.py
tests/test_rag_eval_tools.py
```

Modify:

```text
pyproject.toml
.gitignore
README.md
secminiagent/cli.py
secminiagent/llm/fake.py
secminiagent/rag/evaluator.py
secminiagent/tools/rag_tools.py
tests/fixtures/rag_eval.json
tests/test_rag_evaluator.py
```

Optional modification:

```text
secminiagent/rag/__init__.py
```

Only export public helpers there if it improves imports without creating circular dependencies.

---

### Task 1: Add Precision@K Metric

**Files:**
- Modify: `secminiagent/rag/evaluator.py`
- Modify: `tests/test_rag_evaluator.py`

**Interfaces:**
- Consumes: existing `recall_at_k(results, expected, k)`, `mrr(results, expected)`, `hit_rate(results, expected, k)`
- Produces: `precision_at_k(results: list[list[str]], expected: list[set[str]], k: int) -> float`

- [ ] **Step 1: Add failing precision tests**

Append these tests to `tests/test_rag_evaluator.py`:

```python
    def test_precision_at_k(self):
        from secminiagent.rag.evaluator import precision_at_k

        results = [["protocol_modbus", "wrong"], ["playbook", "wrong"]]
        expected = [{"protocol_modbus"}, {"missing"}]

        self.assertEqual(precision_at_k(results, expected, k=2), 0.25)

    def test_precision_at_k_uses_returned_result_count_when_shorter_than_k(self):
        from secminiagent.rag.evaluator import precision_at_k

        results = [["protocol_modbus"], []]
        expected = [{"protocol_modbus", "s7comm"}, {"missing"}]

        self.assertEqual(precision_at_k(results, expected, k=3), 0.5)
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```powershell
python -m unittest tests.test_rag_evaluator -v
```

Expected: `ImportError` or failure because `precision_at_k` does not exist.

- [ ] **Step 3: Implement `precision_at_k`**

Add to `secminiagent/rag/evaluator.py`:

```python
def precision_at_k(results: list[list[str]], expected: list[set[str]], k: int) -> float:
    if not results:
        return 0.0
    total = 0.0
    for retrieved, relevant in zip(results, expected, strict=False):
        top = retrieved[:k]
        if not top or not relevant:
            continue
        hits = len(set(top) & relevant)
        total += hits / len(top)
    return total / len(results)
```

- [ ] **Step 4: Run evaluator tests**

Run:

```powershell
python -m unittest tests.test_rag_evaluator -v
```

Expected: all evaluator tests pass.

- [ ] **Step 5: Commit**

```powershell
git add secminiagent/rag/evaluator.py tests/test_rag_evaluator.py
git commit -m "feat: add RAG precision metric"
```

---

### Task 2: Add Query Strategy Module and Expand Eval Fixture

**Files:**
- Create: `secminiagent/rag/query.py`
- Create/Modify: `tests/test_rag_query.py`
- Modify: `tests/fixtures/rag_eval.json`
- Modify: `secminiagent/tools/rag_tools.py`

**Interfaces:**
- Produces: `OT_PORT_HINTS: dict[int, str]`
- Produces: `build_query(sample: Mapping[str, object], strategy: str) -> str`
- Produces: `SUPPORTED_QUERY_STRATEGIES = ("description_only", "description_port", "description_port_hint")`
- Consumes later: benchmark engine calls `build_query(sample, strategy)`

- [ ] **Step 1: Write query strategy tests**

Create `tests/test_rag_query.py`:

```python
import unittest

from secminiagent.rag.query import SUPPORTED_QUERY_STRATEGIES, build_query


class RagQueryTest(unittest.TestCase):
    def test_supported_query_strategies(self):
        self.assertEqual(
            SUPPORTED_QUERY_STRATEGIES,
            ("description_only", "description_port", "description_port_hint"),
        )

    def test_description_only(self):
        sample = {"description": "Office host accessed PLC Modbus service.", "destination_port": 502}

        query = build_query(sample, "description_only")

        self.assertEqual(query, "Office host accessed PLC Modbus service.")

    def test_description_port(self):
        sample = {"description": "Office host accessed PLC Modbus service.", "destination_port": 502}

        query = build_query(sample, "description_port")

        self.assertEqual(query, "Office host accessed PLC Modbus service. traffic to port 502")

    def test_description_port_hint(self):
        sample = {"description": "Office host accessed PLC Modbus service.", "destination_port": 502}

        query = build_query(sample, "description_port_hint")

        self.assertIn("Office host accessed PLC Modbus service.", query)
        self.assertIn("traffic to port 502", query)
        self.assertIn("Modbus PLC", query)

    def test_unknown_strategy_raises_value_error(self):
        with self.assertRaisesRegex(ValueError, "Unknown RAG query strategy"):
            build_query({"description": "x"}, "unknown")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run query tests to verify failure**

Run:

```powershell
python -m unittest tests.test_rag_query -v
```

Expected: import failure because `secminiagent.rag.query` does not exist.

- [ ] **Step 3: Implement query strategy module**

Create `secminiagent/rag/query.py`:

```python
from __future__ import annotations

from collections.abc import Mapping


OT_PORT_HINTS = {
    502: "Modbus PLC industrial control protocol suspicious OT access",
    102: "S7comm Siemens PLC industrial control protocol access",
    4840: "OPC UA industrial data exchange OT access",
    3389: "RDP remote maintenance brute force access",
}

SUPPORTED_QUERY_STRATEGIES = ("description_only", "description_port", "description_port_hint")


def build_query(sample: Mapping[str, object], strategy: str) -> str:
    description = str(sample.get("description") or "").strip()
    port = _port_or_zero(sample.get("destination_port"))

    if strategy == "description_only":
        return description
    if strategy == "description_port":
        return " ".join(part for part in [description, _port_phrase(port)] if part).strip()
    if strategy == "description_port_hint":
        return " ".join(
            part for part in [description, _port_phrase(port), OT_PORT_HINTS.get(port, "")] if part
        ).strip()
    raise ValueError(f"Unknown RAG query strategy: {strategy}")


def _port_phrase(port: int) -> str:
    return f"traffic to port {port}" if port else ""


def _port_or_zero(value: object) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
```

- [ ] **Step 4: Update `rag_tools.py` to reuse shared hints**

In `secminiagent/tools/rag_tools.py`, replace the local `OT_PORT_HINTS` definition with:

```python
from secminiagent.rag.query import OT_PORT_HINTS
```

Keep `build_alert_query()` behavior unchanged.

- [ ] **Step 5: Expand evaluation fixture**

Replace `tests/fixtures/rag_eval.json` with at least these samples:

```json
[
  {
    "id": "modbus_plc_access",
    "description": "Office host accessed PLC Modbus service.",
    "destination_port": 502,
    "protocol": "tcp",
    "severity": "high",
    "expected_doc_ids": [
      "knowledge/protocols/modbus.md",
      "knowledge/rules/ot_rules.md"
    ]
  },
  {
    "id": "opcua_scada_access",
    "description": "Unexpected OPC UA session to SCADA data service.",
    "destination_port": 4840,
    "protocol": "tcp",
    "severity": "medium",
    "expected_doc_ids": [
      "knowledge/protocols/opcua.md"
    ]
  },
  {
    "id": "s7comm_plc_access",
    "description": "Engineering workstation reached Siemens PLC service.",
    "destination_port": 102,
    "protocol": "tcp",
    "severity": "high",
    "expected_doc_ids": [
      "knowledge/protocols/s7comm.md"
    ]
  },
  {
    "id": "rdp_bruteforce_jump_host",
    "description": "Repeated RDP access attempts against remote maintenance jump host.",
    "destination_port": 3389,
    "protocol": "tcp",
    "severity": "high",
    "expected_doc_ids": [
      "knowledge/playbooks/brute_force_response.md",
      "knowledge/wind_power/remote_maintenance_risks.md"
    ]
  },
  {
    "id": "office_to_ot",
    "description": "Office network host accessed a critical OT controller.",
    "destination_port": 502,
    "protocol": "tcp",
    "severity": "high",
    "expected_doc_ids": [
      "knowledge/rules/ot_rules.md",
      "knowledge/playbooks/suspicious_ot_access.md"
    ]
  },
  {
    "id": "remote_maintenance_risk",
    "description": "Remote maintenance access path reached wind farm control network.",
    "destination_port": 3389,
    "protocol": "tcp",
    "severity": "high",
    "expected_doc_ids": [
      "knowledge/wind_power/remote_maintenance_risks.md"
    ]
  },
  {
    "id": "lateral_movement",
    "description": "One source reached multiple OT assets in a short time window.",
    "destination_port": 445,
    "protocol": "tcp",
    "severity": "medium",
    "expected_doc_ids": [
      "knowledge/playbooks/lateral_movement_response.md"
    ]
  },
  {
    "id": "wind_farm_scada",
    "description": "Unexpected network access to wind farm SCADA monitoring service.",
    "destination_port": 4840,
    "protocol": "tcp",
    "severity": "medium",
    "expected_doc_ids": [
      "knowledge/wind_power/wind_farm_security_context.md",
      "knowledge/protocols/opcua.md"
    ]
  }
]
```

- [ ] **Step 6: Run tests**

Run:

```powershell
python -m unittest tests.test_rag_query tests.test_rag_tools -v
```

Expected: pass.

- [ ] **Step 7: Commit**

```powershell
git add secminiagent/rag/query.py secminiagent/tools/rag_tools.py tests/test_rag_query.py tests/fixtures/rag_eval.json
git commit -m "feat: add RAG query strategies"
```

---

### Task 3: Add Backend Abstraction With Local Backend

**Files:**
- Create: `secminiagent/rag/backends.py`
- Create/Modify: `tests/test_rag_benchmark.py`

**Interfaces:**
- Produces: `BackendSearchResult` dataclass with `doc_id: str`, `score: float`, `text: str`, `metadata: dict[str, object]`
- Produces: `BaseRagBackend`
- Produces: `LocalRagBackend`
- Produces: `create_backend(name: str, *, persist_path: Path | None = None) -> BaseRagBackend`

- [ ] **Step 1: Write backend tests**

Create `tests/test_rag_benchmark.py` with the first tests:

```python
import tempfile
import unittest
from pathlib import Path

from secminiagent.rag.backends import LocalRagBackend, create_backend


class RagBackendTest(unittest.TestCase):
    def test_create_local_backend(self):
        backend = create_backend("local")

        self.assertIsInstance(backend, LocalRagBackend)

    def test_unknown_backend_raises(self):
        with self.assertRaisesRegex(ValueError, "Unknown RAG backend"):
            create_backend("missing")

    def test_local_backend_ingests_and_searches(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "protocols").mkdir()
            (root / "protocols" / "modbus.md").write_text(
                "# Modbus\n\nModbus commonly uses TCP port 502 for PLC communication.\n",
                encoding="utf-8",
            )
            backend = create_backend("local")

            count = backend.ingest_path(root)
            results = backend.search("PLC Modbus TCP 502", top_k=1)

            self.assertEqual(count, 1)
            self.assertEqual(len(results), 1)
            self.assertTrue(results[0].doc_id.endswith("protocols/modbus.md"))
            self.assertIn("Modbus", results[0].text)
```

- [ ] **Step 2: Run backend tests to verify failure**

Run:

```powershell
python -m unittest tests.test_rag_benchmark -v
```

Expected: import failure because `secminiagent.rag.backends` does not exist.

- [ ] **Step 3: Implement local backend abstraction**

Create `secminiagent/rag/backends.py`:

```python
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from secminiagent.rag.retriever import KnowledgeRetriever


@dataclass(frozen=True, slots=True)
class BackendSearchResult:
    doc_id: str
    score: float
    text: str
    metadata: dict[str, object]


class BaseRagBackend(Protocol):
    def ingest_path(self, path: Path) -> int:
        ...

    def search(
        self,
        query: str,
        top_k: int = 5,
        filters: dict[str, str] | None = None,
    ) -> list[BackendSearchResult]:
        ...


class LocalRagBackend:
    def __init__(self) -> None:
        self.retriever = KnowledgeRetriever()

    def ingest_path(self, path: Path) -> int:
        return self.retriever.ingest_path(path)

    def search(
        self,
        query: str,
        top_k: int = 5,
        filters: dict[str, str] | None = None,
    ) -> list[BackendSearchResult]:
        results = self.retriever.search(query, top_k=top_k, filters=filters)
        return [
            BackendSearchResult(
                doc_id=_relative_doc_id(result.chunk.source_path),
                score=result.score,
                text=result.chunk.text,
                metadata=dict(result.chunk.metadata),
            )
            for result in results
        ]


def create_backend(name: str, *, persist_path: Path | None = None) -> BaseRagBackend:
    normalized = name.lower()
    if normalized == "local":
        return LocalRagBackend()
    if normalized == "chroma":
        return _create_chroma_backend(persist_path)
    raise ValueError(f"Unknown RAG backend: {name}")


def _create_chroma_backend(persist_path: Path | None) -> BaseRagBackend:
    raise RuntimeError(
        "Chroma backend requires chromadb. Install with: python -m pip install -e \".[chroma]\""
    )


def _relative_doc_id(path: Path) -> str:
    text = path.as_posix()
    marker = "/knowledge/"
    if marker in text:
        return "knowledge/" + text.split(marker, 1)[1]
    return text
```

- [ ] **Step 4: Run backend tests**

Run:

```powershell
python -m unittest tests.test_rag_benchmark -v
```

Expected: pass.

- [ ] **Step 5: Commit**

```powershell
git add secminiagent/rag/backends.py tests/test_rag_benchmark.py
git commit -m "feat: add RAG backend abstraction"
```

---

### Task 4: Add Benchmark Engine for Local Backend

**Files:**
- Create: `secminiagent/rag/benchmark.py`
- Modify: `tests/test_rag_benchmark.py`

**Interfaces:**
- Produces: `BenchmarkRow` dataclass
- Produces: `run_rag_benchmark(eval_path: Path, knowledge_path: Path, backends: list[str], top_k_values: list[int], query_strategies: list[str], persist_path: Path | None = None) -> list[BenchmarkRow]`
- Produces: `render_benchmark_markdown(rows: list[BenchmarkRow], *, eval_path: str, knowledge_path: str) -> str`

- [ ] **Step 1: Add failing benchmark tests**

Append to `tests/test_rag_benchmark.py`:

```python
import json

from secminiagent.rag.benchmark import render_benchmark_markdown, run_rag_benchmark


class RagBenchmarkEngineTest(unittest.TestCase):
    def test_run_local_benchmark(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            knowledge = root / "knowledge"
            (knowledge / "protocols").mkdir(parents=True)
            (knowledge / "protocols" / "modbus.md").write_text(
                "# Modbus\n\nModbus commonly uses TCP port 502 for PLC communication.\n",
                encoding="utf-8",
            )
            eval_path = root / "rag_eval.json"
            eval_path.write_text(
                json.dumps(
                    [
                        {
                            "id": "modbus",
                            "description": "PLC Modbus service access.",
                            "destination_port": 502,
                            "expected_doc_ids": ["knowledge/protocols/modbus.md"],
                        }
                    ]
                ),
                encoding="utf-8",
            )

            rows = run_rag_benchmark(
                eval_path=eval_path,
                knowledge_path=knowledge,
                backends=["local"],
                top_k_values=[1, 3],
                query_strategies=["description_port_hint"],
            )

            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0].backend, "local")
            self.assertEqual(rows[0].query_strategy, "description_port_hint")
            self.assertEqual(rows[0].top_k, 1)
            self.assertGreaterEqual(rows[0].recall_at_k, 0.0)
            self.assertGreaterEqual(rows[0].precision_at_k, 0.0)

    def test_render_benchmark_markdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            knowledge = root / "knowledge"
            (knowledge / "protocols").mkdir(parents=True)
            (knowledge / "protocols" / "modbus.md").write_text("# Modbus\n\nTCP 502.\n", encoding="utf-8")
            eval_path = root / "rag_eval.json"
            eval_path.write_text(
                json.dumps(
                    [
                        {
                            "id": "modbus",
                            "description": "Modbus TCP 502",
                            "destination_port": 502,
                            "expected_doc_ids": ["knowledge/protocols/modbus.md"],
                        }
                    ]
                ),
                encoding="utf-8",
            )
            rows = run_rag_benchmark(
                eval_path=eval_path,
                knowledge_path=knowledge,
                backends=["local"],
                top_k_values=[1],
                query_strategies=["description_port_hint"],
            )

            markdown = render_benchmark_markdown(
                rows,
                eval_path=str(eval_path),
                knowledge_path=str(knowledge),
            )

            self.assertIn("# RAG Evaluation Report", markdown)
            self.assertIn("| Backend | Query Strategy | Top-K | Recall@K | Precision@K | MRR | Hit Rate |", markdown)
            self.assertIn("| local | description_port_hint | 1 |", markdown)
```

- [ ] **Step 2: Run benchmark tests to verify failure**

Run:

```powershell
python -m unittest tests.test_rag_benchmark -v
```

Expected: import failure because `secminiagent.rag.benchmark` does not exist.

- [ ] **Step 3: Implement benchmark engine**

Create `secminiagent/rag/benchmark.py`:

```python
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from secminiagent.rag.backends import create_backend
from secminiagent.rag.evaluator import hit_rate, mrr, precision_at_k, recall_at_k
from secminiagent.rag.query import build_query


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
                        recall_at_k=recall_at_k(retrieved_ids, expected_ids, top_k),
                        precision_at_k=precision_at_k(retrieved_ids, expected_ids, top_k),
                        mrr=mrr(retrieved_ids, expected_ids),
                        hit_rate=hit_rate(retrieved_ids, expected_ids, top_k),
                        sample_count=len(samples),
                    )
                )
    return rows


def render_benchmark_markdown(rows: list[BenchmarkRow], *, eval_path: str, knowledge_path: str) -> str:
    now = datetime.now(timezone.utc).isoformat()
    sample_count = rows[0].sample_count if rows else 0
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
```

- [ ] **Step 4: Run benchmark tests**

Run:

```powershell
python -m unittest tests.test_rag_benchmark -v
```

Expected: pass.

- [ ] **Step 5: Commit**

```powershell
git add secminiagent/rag/benchmark.py tests/test_rag_benchmark.py
git commit -m "feat: add local RAG benchmark engine"
```

---

### Task 5: Add `evaluate_rag` Tool and CLI/Fake Registration

**Files:**
- Create: `secminiagent/tools/rag_eval_tools.py`
- Create/Modify: `tests/test_rag_eval_tools.py`
- Modify: `tests/test_registry.py`
- Modify: `secminiagent/cli.py`
- Modify: `secminiagent/llm/fake.py`

**Interfaces:**
- Produces tool: `EvaluateRagTool`
- Produces tool name: `evaluate_rag`
- Consumes: `run_rag_benchmark()` and `render_benchmark_markdown()`

- [ ] **Step 1: Write tool tests**

Create `tests/test_rag_eval_tools.py`:

```python
import json
import tempfile
import unittest
from pathlib import Path

from secminiagent.tools.base import ToolContext
from secminiagent.tools.rag_eval_tools import EvaluateRagTool


class RagEvalToolsTest(unittest.IsolatedAsyncioTestCase):
    async def test_evaluate_rag_tool_outputs_markdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            knowledge = root / "knowledge"
            (knowledge / "protocols").mkdir(parents=True)
            (knowledge / "protocols" / "modbus.md").write_text(
                "# Modbus\n\nModbus commonly uses TCP port 502 for PLC communication.\n",
                encoding="utf-8",
            )
            eval_path = root / "rag_eval.json"
            eval_path.write_text(
                json.dumps(
                    [
                        {
                            "id": "modbus",
                            "description": "PLC Modbus service access.",
                            "destination_port": 502,
                            "expected_doc_ids": ["knowledge/protocols/modbus.md"],
                        }
                    ]
                ),
                encoding="utf-8",
            )
            context = ToolContext(cwd=root, max_output_chars=12000)

            result = await EvaluateRagTool().execute(
                {
                    "eval_path": "rag_eval.json",
                    "knowledge_path": "knowledge",
                    "backend": "local",
                    "top_k_values": [1, 3],
                    "query_strategies": ["description_port_hint"],
                },
                context,
            )

            self.assertTrue(result.success)
            self.assertIn("# RAG Evaluation Report", result.output)
            self.assertIn("| local | description_port_hint | 1 |", result.output)

    async def test_evaluate_rag_tool_can_write_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            knowledge = root / "knowledge"
            (knowledge / "protocols").mkdir(parents=True)
            (knowledge / "protocols" / "modbus.md").write_text("# Modbus\n\nTCP 502.\n", encoding="utf-8")
            (root / "rag_eval.json").write_text(
                json.dumps(
                    [
                        {
                            "id": "modbus",
                            "description": "Modbus TCP 502",
                            "destination_port": 502,
                            "expected_doc_ids": ["knowledge/protocols/modbus.md"],
                        }
                    ]
                ),
                encoding="utf-8",
            )
            context = ToolContext(cwd=root, max_output_chars=12000)

            result = await EvaluateRagTool().execute(
                {
                    "eval_path": "rag_eval.json",
                    "knowledge_path": "knowledge",
                    "backend": "local",
                    "write_file": True,
                    "output_path": ".secminiagent/reports/rag-evaluation.md",
                },
                context,
            )

            self.assertTrue(result.success)
            self.assertTrue((root / ".secminiagent" / "reports" / "rag-evaluation.md").exists())
```

- [ ] **Step 2: Add registry test**

Append to `tests/test_registry.py`:

```python
    async def test_cli_registry_includes_rag_eval_tool(self):
        from secminiagent.cli import build_registry

        registry = build_registry()
        names = set(registry.names())

        self.assertIn("evaluate_rag", names)
```

- [ ] **Step 3: Run tests to verify failure**

Run:

```powershell
python -m unittest tests.test_rag_eval_tools tests.test_registry -v
```

Expected: import failure for `rag_eval_tools` or registry missing `evaluate_rag`.

- [ ] **Step 4: Implement `EvaluateRagTool`**

Create `secminiagent/tools/rag_eval_tools.py`:

```python
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
```

- [ ] **Step 5: Register tool in CLI**

In `secminiagent/cli.py`, import:

```python
from .tools.rag_eval_tools import EvaluateRagTool
```

Register in `build_registry()` near other RAG tools:

```python
    registry.register(EvaluateRagTool())
```

- [ ] **Step 6: Add fake provider route**

In `secminiagent/llm/fake.py`, before generic RAG threat report routing, add:

```python
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
```

- [ ] **Step 7: Run tests**

Run:

```powershell
python -m unittest tests.test_rag_eval_tools tests.test_registry -v
```

Expected: pass.

- [ ] **Step 8: Run CLI smoke**

Run:

```powershell
python -m secminiagent --no-env "evaluate rag benchmark"
```

Expected output contains:

```text
[tool] evaluate_rag
# RAG Evaluation Report
| Backend | Query Strategy | Top-K | Recall@K | Precision@K | MRR | Hit Rate |
```

- [ ] **Step 9: Commit**

```powershell
git add secminiagent/tools/rag_eval_tools.py secminiagent/cli.py secminiagent/llm/fake.py tests/test_rag_eval_tools.py tests/test_registry.py
git commit -m "feat: add RAG evaluation tool"
```

---

### Task 6: Add Optional Chroma Backend

**Files:**
- Modify: `pyproject.toml`
- Modify: `.gitignore`
- Modify: `secminiagent/rag/backends.py`
- Modify: `tests/test_rag_benchmark.py`

**Interfaces:**
- Produces: `ChromaRagBackend`
- `create_backend("chroma", persist_path=...)` returns Chroma backend if `chromadb` is installed
- `create_backend("chroma", ...)` raises clear `RuntimeError` if `chromadb` is not installed

- [ ] **Step 1: Add pyproject optional dependency test by inspection**

No runtime test is needed for `pyproject.toml`, but the final review must verify:

```toml
[project.optional-dependencies]
chroma = ["chromadb>=0.5.0"]
```

is present.

- [ ] **Step 2: Add Chroma friendly-error test**

Append to `tests/test_rag_benchmark.py`:

```python
    def test_chroma_backend_without_dependency_has_friendly_error(self):
        import importlib.util

        if importlib.util.find_spec("chromadb") is not None:
            self.skipTest("chromadb is installed; missing dependency path is not applicable")

        with self.assertRaisesRegex(RuntimeError, "Chroma backend requires chromadb"):
            create_backend("chroma", persist_path=Path(".secminiagent/rag/chroma"))
```

- [ ] **Step 3: Add optional Chroma integration test**

Append to `tests/test_rag_benchmark.py`:

```python
    def test_chroma_backend_ingests_and_searches_when_installed(self):
        import importlib.util

        if importlib.util.find_spec("chromadb") is None:
            self.skipTest("chromadb is not installed")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            knowledge = root / "knowledge"
            (knowledge / "protocols").mkdir(parents=True)
            (knowledge / "protocols" / "modbus.md").write_text(
                "# Modbus\n\nModbus commonly uses TCP port 502 for PLC communication.\n",
                encoding="utf-8",
            )
            backend = create_backend("chroma", persist_path=root / ".secminiagent" / "rag" / "chroma")

            count = backend.ingest_path(knowledge)
            results = backend.search("PLC Modbus TCP 502", top_k=1)

            self.assertEqual(count, 1)
            self.assertEqual(len(results), 1)
            self.assertTrue(results[0].doc_id.endswith("protocols/modbus.md"))
```

- [ ] **Step 4: Run tests before implementation**

Run:

```powershell
python -m unittest tests.test_rag_benchmark -v
```

Expected: friendly-error test passes with current stub, integration test skips if Chroma is missing. If Chroma is installed, integration test fails because stub is not implemented.

- [ ] **Step 5: Update pyproject**

Add to `pyproject.toml`:

```toml
[project.optional-dependencies]
chroma = ["chromadb>=0.5.0"]
```

- [ ] **Step 6: Update `.gitignore`**

Ensure `.gitignore` includes:

```gitignore
.secminiagent/rag/
```

Do not remove existing ignore rules.

- [ ] **Step 7: Implement Chroma backend**

Update `secminiagent/rag/backends.py`:

```python
class ChromaRagBackend:
    def __init__(self, persist_path: Path | None = None, collection_name: str = "secminiagent_knowledge") -> None:
        try:
            import chromadb
        except ImportError as exc:
            raise RuntimeError(
                "Chroma backend requires chromadb. Install with: python -m pip install -e \".[chroma]\""
            ) from exc
        self.persist_path = persist_path or Path(".secminiagent") / "rag" / "chroma"
        self.client = chromadb.PersistentClient(path=str(self.persist_path))
        self.collection = self.client.get_or_create_collection(collection_name)

    def ingest_path(self, path: Path) -> int:
        from secminiagent.rag.chunker import chunk_document, load_markdown_documents
        from secminiagent.rag.embeddings import embed_text

        documents = load_markdown_documents(path)
        chunks = []
        for document in documents:
            chunks.extend(chunk_document(document))
        if not chunks:
            return 0
        ids = [_relative_doc_id(chunk.source_path) + f"#{index}" for index, chunk in enumerate(chunks)]
        embeddings = [embed_text(chunk.text) for chunk in chunks]
        metadatas = [
            {
                "doc_id": _relative_doc_id(chunk.source_path),
                "source_path": str(chunk.source_path),
                "title": chunk.title,
                **{key: str(value) for key, value in chunk.metadata.items()},
            }
            for chunk in chunks
        ]
        documents_text = [chunk.text for chunk in chunks]
        self.collection.upsert(ids=ids, embeddings=embeddings, metadatas=metadatas, documents=documents_text)
        return len(chunks)

    def search(
        self,
        query: str,
        top_k: int = 5,
        filters: dict[str, str] | None = None,
    ) -> list[BackendSearchResult]:
        from secminiagent.rag.embeddings import embed_text

        where = filters if filters else None
        result = self.collection.query(
            query_embeddings=[embed_text(query)],
            n_results=max(1, min(int(top_k), 12)),
            where=where,
        )
        ids = result.get("ids", [[]])[0]
        docs = result.get("documents", [[]])[0]
        metadatas = result.get("metadatas", [[]])[0]
        distances = result.get("distances", [[]])[0]
        output: list[BackendSearchResult] = []
        for item_id, doc, metadata, distance in zip(ids, docs, metadatas, distances, strict=False):
            metadata = dict(metadata or {})
            doc_id = str(metadata.get("doc_id") or str(item_id).split("#", 1)[0])
            score = 1.0 / (1.0 + float(distance or 0.0))
            output.append(BackendSearchResult(doc_id=doc_id, score=score, text=str(doc or ""), metadata=metadata))
        return output
```

Change `_create_chroma_backend()`:

```python
def _create_chroma_backend(persist_path: Path | None) -> BaseRagBackend:
    return ChromaRagBackend(persist_path=persist_path)
```

- [ ] **Step 8: Run backend tests**

Run:

```powershell
python -m unittest tests.test_rag_benchmark -v
```

Expected:

- If `chromadb` not installed: local tests pass, friendly-error test passes, Chroma integration skips.
- If `chromadb` installed: local tests pass, Chroma integration passes.

- [ ] **Step 9: Run full tests**

Run:

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

Expected: pass.

- [ ] **Step 10: Commit**

```powershell
git add pyproject.toml .gitignore secminiagent/rag/backends.py tests/test_rag_benchmark.py
git commit -m "feat: add optional Chroma RAG backend"
```

---

### Task 7: README Benchmark Results and Final Verification

**Files:**
- Modify: `README.md`
- Optional: create generated report by command, but do not commit `.secminiagent/`

**Interfaces:**
- Consumes: `evaluate_rag` CLI route
- Produces: README section `RAG Evaluation Benchmark`

- [ ] **Step 1: Run local benchmark**

Run:

```powershell
python -m secminiagent --no-env "evaluate rag benchmark"
```

Capture the Markdown table from output.

Expected output contains:

```text
# RAG Evaluation Report
| Backend | Query Strategy | Top-K | Recall@K | Precision@K | MRR | Hit Rate |
```

- [ ] **Step 2: Optionally run Chroma benchmark**

If Chroma is installed or you install it:

```powershell
python -m pip install -e ".[chroma]"
python -m secminiagent --no-env "evaluate rag benchmark with chroma"
```

If Chroma is not installed and you choose not to install it, README must not show fake Chroma scores. It should show local results and document the Chroma command separately.

- [ ] **Step 3: Update README**

Add or update a section:

```markdown
## RAG Evaluation Benchmark

SecMiniAgent includes a reproducible RAG benchmark for industrial security knowledge retrieval.

Compared dimensions:

- Backend: `local`, optional `chroma`
- Top-K: `1`, `3`, `5`, `8`
- Query strategy: `description_only`, `description_port`, `description_port_hint`
- Metrics: `recall@k`, `precision@k`, `mrr`, `hit_rate`

Run:

```powershell
python -m secminiagent --no-env "evaluate rag benchmark"
```

Latest local benchmark result:

[paste actual table from the command here]

Interpretation:

- `description_port_hint` should generally improve industrial protocol retrieval because it adds OT protocol context such as Modbus TCP/502 or OPC UA TCP/4840.
- `top_k` trades precision for recall: higher `top_k` may improve recall while lowering precision.
- Chroma can be enabled with `python -m pip install -e ".[chroma]"` and selected with `backend=chroma` or `backend=all`.
```

- [ ] **Step 4: Run full tests**

Run:

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

Expected: pass.

- [ ] **Step 5: Run smoke commands**

Run:

```powershell
python -m secminiagent --no-env "evaluate rag benchmark"
python -m secminiagent --no-env "generate a RAG wind power threat report"
python -m secminiagent --no-env "generate an industrial threat report"
```

Expected:

- `evaluate_rag` outputs benchmark table.
- `generate_rag_threat_report` still outputs `Knowledge Evidence`.
- `generate_threat_report` still works.

- [ ] **Step 6: Check worktree**

Run:

```powershell
git status --short
```

Expected:

- No unexpected source/test changes.
- `.secminiagent/` reports or Chroma cache are untracked/ignored and not staged.

- [ ] **Step 7: Commit**

```powershell
git add README.md
git commit -m "docs: add RAG benchmark results"
```

---

## Final Verification

After all tasks:

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
python -m secminiagent --no-env "evaluate rag benchmark"
python -m secminiagent --no-env "generate a RAG wind power threat report"
python -m secminiagent --no-env "generate an industrial threat report"
git status --short
```

Expected:

- All tests pass.
- RAG benchmark outputs Markdown table with `recall@k`, `precision@k`, `mrr`, and `hit_rate`.
- RAG threat report still includes `Knowledge Evidence`.
- Industrial threat report still works.
- Runtime files are not staged.

## Expected Resume Outcome

After implementation, the project can be described as:

```text
实现 Local 与 Chroma 双检索后端，构建工业安全 RAG Benchmark 评估集，支持 recall@k、precision@k、MRR、hit_rate 等检索指标，对 top_k 和 query 构造策略进行量化对比，并输出 Markdown 实验报告用于评估工业告警知识召回质量。
```
