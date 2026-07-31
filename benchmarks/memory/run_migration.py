from __future__ import annotations

import subprocess
import sys
import time
import json
import os
import sqlite3
import tempfile
import tracemalloc
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from secminiagent.memory.crypto import ALGORITHM, build_memory_aad_v1
from secminiagent.memory.migration import MigrationCapability, SchemaMigrator
from secminiagent.memory.models import (
    IndexStatus, MemoryAction, MemoryClassification, MemoryMetadata, MemoryScope, MemoryType,
)
from tests.memory.fixtures.schema_v1_factory import FixtureKeyProvider, V1_DDL

from common import load_dataset, main_guard, parser, write_report


def _scaled_migration(count: int) -> dict[str, object]:
    workspace_id = "b" * 64
    provider = FixtureKeyProvider(workspace_id)
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "memory.db"
        connection = sqlite3.connect(path)
        connection.executescript(V1_DDL)
        key, version = provider.get_key(workspace_id)
        cipher = AESGCM(key)
        created = datetime(2026, 1, 1, tzinfo=timezone.utc)
        batch = []
        for index in range(count):
            metadata = MemoryMetadata(
                id=f"synthetic-{index:08d}", workspace_id=workspace_id, session_id=None,
                scope=MemoryScope.WORKSPACE, memory_type=MemoryType.PROJECT_FACT,
                classification=MemoryClassification.INTERNAL, source_type="benchmark",
                policy_action=MemoryAction.ALLOW, policy_reason_codes=("BENCHMARK_SYNTHETIC",),
                index_status=IndexStatus.NOT_INDEXED, created_at=created,
            )
            nonce = index.to_bytes(12, "big")
            plaintext = json.dumps({"content": f"synthetic fact {index}", "attributes": {}}, separators=(",", ":")).encode()
            encrypted = cipher.encrypt(nonce, plaintext, build_memory_aad_v1(metadata))
            batch.append((metadata.id, 1, workspace_id, None, "workspace", "project_fact", "internal", "benchmark", "allow", "BENCHMARK_SYNTHETIC", version, ALGORITHM, encrypted, nonce, "not_indexed", None, created.isoformat(), None, None))
            if len(batch) == 1000:
                connection.executemany("INSERT INTO memories VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", batch)
                batch.clear()
        if batch:
            connection.executemany("INSERT INTO memories VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", batch)
        connection.commit()
        source_bytes = path.stat().st_size
        connection.close()
        migrator = SchemaMigrator(path, key_provider=provider, workspace_id=workspace_id)
        tracemalloc.start()
        started = time.perf_counter()
        capability = MigrationCapability.verified_v2_runtime()
        migrator.prepare_shadow(capability)
        migrator.activate(capability)
        elapsed = time.perf_counter() - started
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        connection = sqlite3.connect(path)
        migrated = int(connection.execute("SELECT COUNT(*) FROM memories").fetchone()[0])
        connection.close()
        return {
            "records": count, "elapsed_seconds": round(elapsed, 3),
            "records_per_second": round(count / max(elapsed, 0.000001), 2),
            "peak_python_bytes": peak, "disk_amplification": round(path.stat().st_size / max(source_bytes, 1), 3),
            "migrated_records": migrated,
        }


def run() -> int:
    value = parser("memory-migration-benchmark")
    value.add_argument("--scales", default="1000,10000,100000")
    args = value.parse_args()
    _, digest = load_dataset()
    started = time.perf_counter()
    result = subprocess.run(
        [sys.executable, "-m", "unittest", "tests.memory.test_schema_migration", "tests.memory.test_schema_migration_recovery"],
        cwd=str(__import__("pathlib").Path(__file__).resolve().parents[2]),
        capture_output=True, text=True, timeout=180,
    )
    elapsed = time.perf_counter() - started
    scales = tuple(int(item) for item in args.scales.split(",") if item.strip())
    if any(item < 1 or item > 100000 for item in scales):
        raise ValueError("migration scales must be between 1 and 100000")
    measurements = tuple(_scaled_migration(item) for item in scales)
    passed = result.returncode == 0 and all(item["migrated_records"] == item["records"] for item in measurements)
    write_report(args.output_dir, "migration", {
        "dataset_digest": digest, "suite_exit_code": result.returncode,
        "elapsed_seconds": round(elapsed, 3), "output_contains_canary": "PRIVATE" in (result.stdout + result.stderr),
        "scale_measurements": measurements,
        "passed": passed and "PRIVATE" not in (result.stdout + result.stderr),
    })
    return 0 if passed else 1


if __name__ == "__main__":
    main_guard(run)
