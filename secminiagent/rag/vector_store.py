from __future__ import annotations

from secminiagent.rag.documents import KnowledgeChunk, RetrievedChunk


class InMemoryVectorStore:
    def __init__(self) -> None:
        self._items: list[tuple[KnowledgeChunk, list[float]]] = []

    def add(self, chunks: list[KnowledgeChunk], vectors: list[list[float]]) -> None:
        if len(chunks) != len(vectors):
            raise ValueError("chunks and vectors length mismatch")
        self._items.extend(zip(chunks, vectors))

    def search(
        self,
        vector: list[float],
        *,
        top_k: int,
        filters: dict[str, object] | None = None,
    ) -> list[RetrievedChunk]:
        filters = filters or {}
        scored: list[RetrievedChunk] = []
        for chunk, candidate in self._items:
            if not _matches_filters(chunk, filters):
                continue
            scored.append(RetrievedChunk(chunk=chunk, score=_dot(vector, candidate)))
        scored.sort(key=lambda item: item.score, reverse=True)
        return scored[:top_k]


def _dot(left: list[float], right: list[float]) -> float:
    return sum(a * b for a, b in zip(left, right))


def _matches_filters(chunk: KnowledgeChunk, filters: dict[str, object]) -> bool:
    for key, expected in filters.items():
        if chunk.metadata.get(key) != expected:
            return False
    return True
