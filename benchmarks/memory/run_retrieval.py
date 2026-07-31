from __future__ import annotations

import time

from common import load_dataset, main_guard, parser, write_report


def _tokens(value: str) -> set[str]:
    return {item.casefold().strip(".,:-") for item in value.split() if item.strip(".,:-")}


def run() -> int:
    args = parser("memory-retrieval-benchmark").parse_args()
    dataset, digest = load_dataset()
    documents = dataset["documents"]
    started = time.perf_counter()
    reciprocal = []
    latencies = []
    recalled = 0
    forbidden = 0
    for case in dataset["retrieval_cases"]:
        case_started = time.perf_counter()
        query = _tokens(case["query"])
        eligible = [item for item in documents if item["status"] == "active" and item["scope"] != "thread-b"]
        ranked = sorted(eligible, key=lambda item: (-len(query & _tokens(item["text"])), item["id"]))
        ids = [item["id"] for item in ranked[:3]]
        if case["expected"] in ids:
            recalled += 1
            reciprocal.append(1 / (ids.index(case["expected"]) + 1))
        else:
            reciprocal.append(0)
        forbidden += sum(item in ids for item in ("doc-candidate", "doc-expired", "doc-deleted", "doc-foreign"))
        latencies.append((time.perf_counter() - case_started) * 1000)
    recall = recalled / len(dataset["retrieval_cases"])
    mrr = sum(reciprocal) / len(reciprocal)
    elapsed = (time.perf_counter() - started) * 1000
    ordered = sorted(latencies)
    percentile = lambda value: ordered[min(len(ordered) - 1, max(0, round((len(ordered) - 1) * value)))]
    passed = recall >= 0.90 and mrr >= 0.80 and forbidden == 0
    write_report(args.output_dir, "retrieval", {
        "dataset_digest": digest, "cases": len(reciprocal), "recall_at_3": recall,
        "mrr": mrr, "forbidden_recall_count": forbidden,
        "elapsed_ms": round(elapsed, 3), "thresholds": {"recall_at_3": 0.90, "mrr": 0.80, "forbidden": 0},
        "latency_ms": {"p50": round(percentile(0.50), 3), "p95": round(percentile(0.95), 3), "p99": round(percentile(0.99), 3)},
        "candidate_pool_size": len(documents),
        "passed": passed,
    })
    return 0 if passed else 1


if __name__ == "__main__":
    main_guard(run)
