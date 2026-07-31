from __future__ import annotations

import gc
from pathlib import Path
from typing import Sequence

from secminiagent.rag.backends import embed_text

from .errors import MemoryDependencyUnavailable
from .models import MemoryAccessContext, MemoryMetadata, MemoryQuery, MemoryScope


class ChromaMemoryIndex:
    """Workspace-filtered, rebuildable index of non-secret memory text."""

    def __init__(
        self,
        persist_path: Path,
        collection_name: str = "secminiagent_memory_v1",
    ) -> None:
        try:
            import chromadb
        except ImportError as exc:
            raise MemoryDependencyUnavailable("Chroma memory index requires the optional chromadb dependency") from exc
        self.client = chromadb.PersistentClient(path=str(persist_path))
        self.collection_name = collection_name
        self.collection = self.client.get_or_create_collection(collection_name)

    def index(self, metadata: MemoryMetadata, redacted_text: str) -> None:
        if metadata.scope is not MemoryScope.WORKSPACE:
            return
        self.collection.upsert(
            ids=[metadata.id],
            embeddings=[embed_text(redacted_text)],
            documents=[redacted_text],
            metadatas=[
                {
                    "workspace_id": metadata.workspace_id,
                    "memory_type": metadata.memory_type.value,
                    "classification": metadata.classification.value,
                }
            ],
        )

    def candidate_ids(self, query: MemoryQuery, context: MemoryAccessContext) -> Sequence[str]:
        if not query.text or self.collection.count() == 0:
            return ()
        result = self.collection.query(
            query_embeddings=[embed_text(query.text)],
            n_results=min(query.limit, self.collection.count()),
            where={"workspace_id": context.workspace_id},
        )
        return tuple(str(item) for item in result.get("ids", [[]])[0])

    def delete(self, memory_id: str, context: MemoryAccessContext) -> None:
        existing = self.collection.get(ids=[memory_id], where={"workspace_id": context.workspace_id})
        if existing.get("ids"):
            self.collection.delete(ids=[memory_id], where={"workspace_id": context.workspace_id})

    def reset(self) -> None:
        try:
            self.client.delete_collection(self.collection_name)
        except Exception:
            pass
        self.collection = self.client.get_or_create_collection(self.collection_name)

    def count(self, workspace_id: str | None = None) -> int:
        if workspace_id is None:
            return int(self.collection.count())
        return len(self.collection.get(where={"workspace_id": workspace_id}).get("ids", []))

    def close(self) -> None:
        client = self.client
        self.collection = None
        close = getattr(client, "close", None)
        if close is not None:
            close()
        self.client = None
        gc.collect()

    def __enter__(self) -> "ChromaMemoryIndex":
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()
