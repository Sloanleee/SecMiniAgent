import hashlib
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from secminiagent.memory.acceptance import BENCHMARK_THRESHOLDS, DATASET_DIGEST, INVARIANT_EVIDENCE
from secminiagent.memory.schema import SchemaState, inspect_database_path


ROOT = Path(__file__).resolve().parents[2]


class M7AcceptanceMatrixTest(unittest.TestCase):
    def test_all_24_frozen_invariants_have_repository_evidence(self):
        self.assertEqual(set(INVARIANT_EVIDENCE), {f"M7-INV-{number:02d}" for number in range(1, 25)})
        for path, explanation in INVARIANT_EVIDENCE.values():
            self.assertTrue((ROOT / path).is_file(), path)
            self.assertTrue(explanation.strip())

    def test_dataset_digest_and_all_small_benchmarks_are_reproducible(self):
        dataset = ROOT / "benchmarks" / "memory" / "datasets" / "synthetic-memory-v1.json"
        self.assertEqual(hashlib.sha256(dataset.read_bytes()).hexdigest(), DATASET_DIGEST)
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            for name in ("retrieval", "summary", "auto_memory"):
                script = ROOT / "benchmarks" / "memory" / f"run_{name}.py"
                result = subprocess.run([sys.executable, str(script), "--output-dir", str(output)], cwd=ROOT, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
            retrieval = json.loads((output / "retrieval.json").read_text(encoding="utf-8"))
            summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
            automatic = json.loads((output / "auto-memory.json").read_text(encoding="utf-8"))
        self.assertGreaterEqual(retrieval["recall_at_3"], BENCHMARK_THRESHOLDS["retrieval.recall_at_3"])
        self.assertGreaterEqual(retrieval["mrr"], BENCHMARK_THRESHOLDS["retrieval.mrr"])
        self.assertEqual(retrieval["forbidden_recall_count"], 0)
        self.assertEqual(summary["fact_preservation"], 1.0)
        self.assertEqual(automatic["automatic_confirmed_count"], 0)

    def test_uninitialized_and_newer_schema_matrix_is_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing = root / "missing.db"
            self.assertEqual(inspect_database_path(missing).state, SchemaState.UNINITIALIZED)
            self.assertFalse(missing.exists())
            newer = root / "newer.db"
            connection = sqlite3.connect(newer)
            connection.execute("PRAGMA user_version=99")
            connection.execute("CREATE TABLE sentinel(value TEXT)")
            connection.execute("INSERT INTO sentinel VALUES('unchanged')")
            connection.commit()
            connection.close()
            before = newer.read_bytes()
            self.assertEqual(inspect_database_path(newer).state, SchemaState.NEWER)
            self.assertEqual(before, newer.read_bytes())


if __name__ == "__main__":
    unittest.main()
