from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sqlite3
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
DATASET = ROOT / "datasets" / "synthetic-memory-v1.json"
SEED = 20260731


def parser(name: str) -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(prog=name)
    value.add_argument("--output-dir", type=Path, required=True)
    return value


def load_dataset() -> tuple[dict[str, object], str]:
    raw = DATASET.read_bytes()
    return json.loads(raw.decode("utf-8")), hashlib.sha256(raw).hexdigest()


def write_report(output_dir: Path, name: str, report: dict[str, object]) -> None:
    resolved = output_dir.resolve()
    if ".secminiagent" in {part.casefold() for part in resolved.parts}:
        raise ValueError("benchmark output must not target a .secminiagent directory")
    resolved.mkdir(parents=True, exist_ok=True)
    enriched = {
        "benchmark": name, "seed": SEED,
        "python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
        **report,
    }
    (resolved / f"{name}.json").write_text(json.dumps(enriched, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    lines = [f"# {name}", "", f"- passed: `{str(bool(enriched.get('passed'))).lower()}`"]
    for key, value in enriched.items():
        if key not in {"benchmark", "passed"}:
            lines.append(f"- {key}: `{value}`")
    (resolved / f"{name}.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main_guard(run) -> None:
    try:
        raise SystemExit(run())
    except (OSError, ValueError, KeyError) as exc:
        print(f"memory benchmark: {exc}", file=sys.stderr)
        raise SystemExit(2)
