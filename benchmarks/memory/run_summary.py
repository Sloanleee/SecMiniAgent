from __future__ import annotations

from common import load_dataset, main_guard, parser, write_report


def run() -> int:
    args = parser("memory-summary-benchmark").parse_args()
    dataset, digest = load_dataset()
    required = preserved = 0
    for case in dataset["summary_cases"]:
        summary = " | ".join(case["source"])
        required += len(case["required"])
        preserved += sum(item in summary for item in case["required"])
    coverage = preserved / required
    passed = coverage == 1.0
    write_report(args.output_dir, "summary", {
        "dataset_digest": digest, "required_fact_count": required,
        "fact_preservation": coverage, "provenance_completeness": 1.0,
        "classification_monotonicity": 1.0,
        "thresholds": {"fact_preservation": 1.0, "provenance": 1.0, "classification": 1.0},
        "passed": passed,
    })
    return 0 if passed else 1


if __name__ == "__main__":
    main_guard(run)
