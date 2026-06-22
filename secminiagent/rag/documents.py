from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class KnowledgeDocument:
    doc_id: str
    source_path: str
    title: str
    text: str
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class KnowledgeChunk:
    chunk_id: str
    doc_id: str
    source_path: str
    title: str
    text: str
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class RetrievedChunk:
    chunk: KnowledgeChunk
    score: float

    def to_dict(self) -> dict[str, object]:
        return {
            "chunk_id": self.chunk.chunk_id,
            "doc_id": self.chunk.doc_id,
            "source_path": self.chunk.source_path,
            "title": self.chunk.title,
            "score": self.score,
            "text": self.chunk.text,
            "metadata": self.chunk.metadata,
        }
