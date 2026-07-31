from __future__ import annotations


DATASET_DIGEST = "87e3812c18f8cd9b9ba37da6db34e8703a5713543f7b121329fdf53035d9ac3f"
BENCHMARK_THRESHOLDS = {
    "retrieval.recall_at_3": 0.90,
    "retrieval.mrr": 0.80,
    "retrieval.forbidden_recall_count": 0,
    "summary.fact_preservation": 1.0,
    "summary.provenance_completeness": 1.0,
    "auto_memory.classification_accuracy": 1.0,
    "auto_memory.automatic_confirmed_count": 0,
}


INVARIANT_EVIDENCE = {
    "M7-INV-01": ("tests/memory/test_crypto_store.py", "encrypted authority and plaintext scan"),
    "M7-INV-02": ("tests/memory/test_thread_run_lifecycle.py", "authenticated ancestry"),
    "M7-INV-03": ("tests/memory/test_thread_transcript.py", "thread SQL filter before decrypt"),
    "M7-INV-04": ("tests/memory/test_thread_resume.py", "run is sequencing, not scope"),
    "M7-INV-05": ("tests/memory/test_structured_notes.py", "transcript/note types remain separate"),
    "M7-INV-06": ("tests/memory/test_structured_notes.py", "authenticated provenance"),
    "M7-INV-07": ("tests/memory/test_rolling_summary.py", "classification monotonicity"),
    "M7-INV-08": ("tests/memory/test_auto_memory_candidates.py", "automatic candidate only"),
    "M7-INV-09": ("tests/memory/test_rolling_summary.py", "model inference is not verified fact"),
    "M7-INV-10": ("tests/memory/test_explicit_notes.py", "immutable note revision"),
    "M7-INV-11": ("tests/memory/test_summary_concurrency.py", "summary CAS activation"),
    "M7-INV-12": ("tests/memory/test_cascade_deletion.py", "reverse derived closure"),
    "M7-INV-13": ("tests/memory/test_note_promotion.py", "copy-on-promote"),
    "M7-INV-14": ("tests/memory/test_note_promotion.py", "workspace-only index"),
    "M7-INV-15": ("tests/memory/test_search_authority.py", "SQLite authority recheck"),
    "M7-INV-16": ("tests/memory/test_memory_prompt_injection.py", "untrusted memory envelope"),
    "M7-INV-17": ("tests/memory/test_context_assembler.py", "complete tool groups and budgets"),
    "M7-INV-18": ("tests/memory/test_m7_security_adversarial.py", "tamper failures are closed"),
    "M7-INV-19": ("tests/memory/test_deletion_leakage.py", "metadata-only audit/log"),
    "M7-INV-20": ("tests/memory/test_m7_resource_bounds.py", "bounded knobs cannot bypass filters"),
    "M7-INV-21": ("tests/memory/test_cascade_deletion.py", "deleted parent makes child unavailable"),
    "M7-INV-22": ("tests/memory/test_retention_policy.py", "immediate expiry"),
    "M7-INV-23": ("tests/memory/test_thread_run_concurrency.py", "one running run"),
    "M7-INV-24": ("tests/memory/test_auto_memory_candidates.py", "persisted completed sources only"),
}
