from __future__ import annotations

import re
from pathlib import Path

from .documents import KnowledgeChunk, KnowledgeDocument


HEADING_RE = re.compile(r"^(#{1,6})\s+(.+)$")


def load_markdown_documents(root: Path) -> list[KnowledgeDocument]:
    paths = [root] if root.is_file() else sorted(root.rglob("*.md"))
    documents: list[KnowledgeDocument] = []
    for path in paths:
        if not path.is_file() or path.suffix.lower() != ".md":
            continue
        text = path.read_text(encoding="utf-8")
        title = _extract_title(text, path.stem)
        source_path = path.as_posix()
        doc_id = _doc_id(root, path)
        documents.append(
            KnowledgeDocument(
                doc_id=doc_id,
                source_path=source_path,
                title=title,
                text=text,
                metadata=_metadata_for_path(path, title),
            )
        )
    return documents


def chunk_path(path: Path) -> list[KnowledgeChunk]:
    chunks: list[KnowledgeChunk] = []
    for document in load_markdown_documents(path):
        chunks.extend(chunk_document(document))
    return chunks


def chunk_document(
    document: KnowledgeDocument,
    *,
    max_chars: int = 1800,
    overlap_chars: int = 240,
) -> list[KnowledgeChunk]:
    sections = _split_sections(document.text)
    chunks: list[KnowledgeChunk] = []
    buffer = ""
    index = 1
    for section in sections:
        candidate = f"{buffer}\n\n{section}".strip() if buffer else section
        if len(candidate) <= max_chars:
            buffer = candidate
            continue
        if buffer:
            chunks.append(_make_chunk(document, buffer, index))
            index += 1
            buffer = buffer[-overlap_chars:] if overlap_chars > 0 else ""
        buffer = f"{buffer}\n\n{section}".strip() if buffer else section
    if buffer:
        chunks.append(_make_chunk(document, buffer, index))
    return chunks


def _split_sections(text: str) -> list[str]:
    sections: list[str] = []
    current: list[str] = []
    for line in text.splitlines():
        if HEADING_RE.match(line) and current:
            sections.append("\n".join(current).strip())
            current = [line]
        else:
            current.append(line)
    if current:
        sections.append("\n".join(current).strip())
    return [section for section in sections if section]


def _make_chunk(document: KnowledgeDocument, text: str, index: int) -> KnowledgeChunk:
    return KnowledgeChunk(
        chunk_id=f"{document.doc_id}#chunk-{index}",
        doc_id=document.doc_id,
        source_path=document.source_path,
        title=document.title,
        text=text,
        metadata=dict(document.metadata),
    )


def _extract_title(text: str, fallback: str) -> str:
    for line in text.splitlines():
        match = HEADING_RE.match(line.strip())
        if match:
            return match.group(2).strip()
    return fallback.replace("_", " ").replace("-", " ").title()


def _doc_id(root: Path, path: Path) -> str:
    try:
        rel = path.relative_to(root if root.is_dir() else root.parent)
    except ValueError:
        rel = path.name
    rel_path = rel if isinstance(rel, Path) else Path(str(rel))
    return rel_path.with_suffix("").as_posix()


def _metadata_for_path(path: Path, title: str) -> dict[str, object]:
    parts = set(path.parts)
    metadata: dict[str, object] = {"title": title, "source_path": path.as_posix()}
    if "protocols" in parts:
        metadata["source_type"] = "protocol"
        metadata["protocol"] = title
        port = {"Modbus": 502, "S7comm": 102, "OPC UA": 4840}.get(title)
        if port:
            metadata["port"] = port
    elif "rules" in parts:
        metadata["source_type"] = "rule"
    elif "playbooks" in parts:
        metadata["source_type"] = "playbook"
    elif "wind_power" in parts:
        metadata["source_type"] = "wind_power"
        metadata["domain"] = "wind_power"
    else:
        metadata["source_type"] = "knowledge"
    return metadata
