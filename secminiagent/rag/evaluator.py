from __future__ import annotations


def recall_at_k(results: list[list[str]], expected: list[set[str]], *, k: int) -> float:
    if not expected:
        return 0.0
    total = 0.0
    for result_ids, expected_ids in zip(results, expected):
        if expected_ids:
            total += len(expected_ids.intersection(result_ids[:k])) / len(expected_ids)
    return total / len(expected)


def hit_rate(results: list[list[str]], expected: list[set[str]], *, k: int) -> float:
    if not expected:
        return 0.0
    hits = 0
    for result_ids, expected_ids in zip(results, expected):
        if expected_ids.intersection(result_ids[:k]):
            hits += 1
    return hits / len(expected)


def mrr(results: list[list[str]], expected: list[set[str]]) -> float:
    if not expected:
        return 0.0
    total = 0.0
    for result_ids, expected_ids in zip(results, expected):
        for index, doc_id in enumerate(result_ids, start=1):
            if doc_id in expected_ids:
                total += 1.0 / index
                break
    return total / len(expected)
