from __future__ import annotations

from pathlib import Path

from secminiagent.rag.chunker import chunk_path
from secminiagent.rag.documents import RetrievedChunk
from secminiagent.rag.embeddings import HashEmbeddingClient
from secminiagent.rag.vector_store import InMemoryVectorStore


class KnowledgeRetriever:
    def __init__(
        self,
        *,
        embeddings: HashEmbeddingClient | None = None,
        store: InMemoryVectorStore | None = None,
    ) -> None:
        self.embeddings = embeddings or HashEmbeddingClient()
        self.store = store or InMemoryVectorStore()

    def ingest_path(self, path: Path) -> int:
        chunks = chunk_path(path)
        vectors = [self.embeddings.embed(f"{chunk.title}\n{chunk.text}") for chunk in chunks]
        self.store.add(chunks, vectors)
        return len(chunks)

    def search(
        self,
        query: str,
        *,
        top_k: int = 5,
        filters: dict[str, object] | None = None,
    ) -> list[RetrievedChunk]:
        bounded_top_k = max(1, min(int(top_k), 12))
        vector = self.embeddings.embed(query)
        return self.store.search(vector, top_k=bounded_top_k, filters=filters)
