from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from secminiagent.rag.chunker import chunk_document, load_markdown_documents
from secminiagent.rag.embeddings import HashEmbeddingClient
from secminiagent.rag.retriever import KnowledgeRetriever


@dataclass(frozen=True, slots=True)
class BackendSearchResult:
    doc_id: str
    score: float
    text: str
    metadata: dict[str, object]


class BaseRagBackend(Protocol):
    def ingest_path(self, path: Path) -> int:
        ...

    def search(
        self,
        query: str,
        top_k: int = 5,
        filters: dict[str, str] | None = None,
    ) -> list[BackendSearchResult]:
        ...


class LocalRagBackend:
    def __init__(self) -> None:
        self.retriever = KnowledgeRetriever()

    def ingest_path(self, path: Path) -> int:
        return self.retriever.ingest_path(path)

    def search(
        self,
        query: str,
        top_k: int = 5,
        filters: dict[str, str] | None = None,
    ) -> list[BackendSearchResult]:
        results = self.retriever.search(query, top_k=top_k, filters=filters)
        return [
            BackendSearchResult(
                doc_id=_relative_doc_id(result.chunk.source_path),
                score=result.score,
                text=result.chunk.text,
                metadata=dict(result.chunk.metadata),
            )
            for result in results
        ]


class ChromaRagBackend:
    def __init__(
        self,
        persist_path: Path | None = None,
        collection_name: str = "secminiagent_knowledge",
    ) -> None:
        try:
            import chromadb
        except ImportError as exc:
            raise RuntimeError(
                "Chroma backend requires chromadb. Install with: python -m pip install -e \".[chroma]\""
            ) from exc
        self.persist_path = persist_path or Path(".secminiagent") / "rag" / "chroma"
        self.client = chromadb.PersistentClient(path=str(self.persist_path))
        try:
            self.client.delete_collection(collection_name)
        except Exception:
            pass
        self.collection = self.client.get_or_create_collection(collection_name)

    def ingest_path(self, path: Path) -> int:
        ids: list[str] = []
        embeddings: list[list[float]] = []
        metadatas: list[dict[str, str]] = []
        documents: list[str] = []

        for document in load_markdown_documents(path):
            for index, chunk in enumerate(chunk_document(document), start=1):
                doc_id = _relative_doc_id(chunk.source_path)
                ids.append(f"{doc_id}#{index}")
                embeddings.append(embed_text(chunk.text))
                metadata = {
                    "doc_id": doc_id,
                    "source_path": chunk.source_path,
                    "title": chunk.title,
                }
                metadata.update({key: str(value) for key, value in chunk.metadata.items()})
                metadatas.append(metadata)
                documents.append(chunk.text)

        if ids:
            self.collection.upsert(
                ids=ids,
                embeddings=embeddings,
                metadatas=metadatas,
                documents=documents,
            )
        return len(ids)

    def search(
        self,
        query: str,
        top_k: int = 5,
        filters: dict[str, str] | None = None,
    ) -> list[BackendSearchResult]:
        n_results = max(1, min(int(top_k), 12))
        result = self.collection.query(
            query_embeddings=[embed_text(query)],
            n_results=n_results,
            where=filters,
        )
        ids = result.get("ids", [[]])[0]
        documents = result.get("documents", [[]])[0]
        metadatas = result.get("metadatas", [[]])[0]
        distances = result.get("distances", [[]])[0]

        rows: list[BackendSearchResult] = []
        for item_id, text, metadata, distance in zip(ids, documents, metadatas, distances):
            item_metadata = dict(metadata or {})
            doc_id = str(item_metadata.get("doc_id") or str(item_id).split("#", 1)[0])
            rows.append(
                BackendSearchResult(
                    doc_id=doc_id,
                    score=1.0 / (1.0 + float(distance or 0.0)),
                    text=str(text or ""),
                    metadata=item_metadata,
                )
            )
        return rows


def create_backend(name: str, *, persist_path: Path | None = None) -> BaseRagBackend:
    normalized = name.lower()
    if normalized == "local":
        return LocalRagBackend()
    if normalized == "chroma":
        return _create_chroma_backend(persist_path)
    raise ValueError(f"Unknown RAG backend: {name}")


def _create_chroma_backend(persist_path: Path | None) -> BaseRagBackend:
    return ChromaRagBackend(persist_path=persist_path)


def embed_text(text: str) -> list[float]:
    return HashEmbeddingClient().embed(text)


def _relative_doc_id(path: Path | str) -> str:
    text = path.as_posix() if isinstance(path, Path) else path
    marker = "/knowledge/"
    if marker in text:
        return "knowledge/" + text.split(marker, 1)[1]
    return text
