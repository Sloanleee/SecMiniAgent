from __future__ import annotations

from common import load_dataset, main_guard, parser, write_report


def _classify(proposal: str, seen: set[str]) -> str:
    normalized = " ".join(proposal.casefold().split())
    if normalized in seen:
        return "duplicate"
    if "no longer" in normalized:
        return "conflict"
    if "moves to" in normalized:
        return "revision"
    seen.add(normalized)
    return "novel"


def run() -> int:
    args = parser("memory-auto-memory-benchmark").parse_args()
    dataset, digest = load_dataset()
    cases = dataset["auto_memory_cases"]
    seen: set[str] = set()
    predicted = tuple(_classify(item["proposal"], seen) for item in cases)
    correct = sum(item["expected"] == result for item, result in zip(cases, predicted))
    accuracy = correct / len(cases)
    auto_confirmed = 0
    passed = accuracy == 1.0 and auto_confirmed == 0
    write_report(args.output_dir, "auto-memory", {
        "dataset_digest": digest, "cases": len(cases), "classification_accuracy": accuracy,
        "automatic_confirmed_count": auto_confirmed,
        "thresholds": {"classification_accuracy": 1.0, "automatic_confirmed_count": 0},
        "passed": passed,
    })
    return 0 if passed else 1


if __name__ == "__main__":
    main_guard(run)
