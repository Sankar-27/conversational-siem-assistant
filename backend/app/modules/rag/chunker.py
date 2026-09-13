"""Text chunking for RAG ingestion."""
from __future__ import annotations

from app.modules.rag.document_loader import KnowledgeDocument


def chunk_document(doc: KnowledgeDocument, chunk_size: int = 500, overlap: int = 50) -> list[dict]:
    text = doc.content.strip()
    if len(text) <= chunk_size:
        return [{
            "chunk_id": f"{doc.doc_id}_0",
            "doc_id": doc.doc_id,
            "title": doc.title,
            "text": text,
            "source": doc.source,
            "doc_type": doc.doc_type,
            "metadata": doc.metadata,
        }]

    chunks = []
    start = 0
    idx = 0
    while start < len(text):
        end = min(start + chunk_size, len(text))
        chunk_text = text[start:end]
        chunks.append({
            "chunk_id": f"{doc.doc_id}_{idx}",
            "doc_id": doc.doc_id,
            "title": doc.title,
            "text": chunk_text,
            "source": doc.source,
            "doc_type": doc.doc_type,
            "metadata": doc.metadata,
        })
        if end >= len(text):
            break
        start = end - overlap
        idx += 1
    return chunks
