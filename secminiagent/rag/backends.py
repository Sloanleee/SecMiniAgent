from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

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


def create_backend(name: str, *, persist_path: Path | None = None) -> BaseRagBackend:
    normalized = name.lower()
    if normalized == "local":
        return LocalRagBackend()
    if normalized == "chroma":
        return _create_chroma_backend(persist_path)
    raise ValueError(f"Unknown RAG backend: {name}")


def _create_chroma_backend(persist_path: Path | None) -> BaseRagBackend:
    raise RuntimeError(
        "Chroma backend requires chromadb. Install with: python -m pip install -e \".[chroma]\""
    )


def _relative_doc_id(path: Path | str) -> str:
    text = path.as_posix() if isinstance(path, Path) else path
    marker = "/knowledge/"
    if marker in text:
        return "knowledge/" + text.split(marker, 1)[1]
    return text
