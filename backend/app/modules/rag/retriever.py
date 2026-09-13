"""Semantic retrieval service with metadata filtering and source references."""
from __future__ import annotations

from typing import Optional

from app.modules.rag.vector_store import get_knowledge_store


class KnowledgeHit:
    def __init__(self, chunk_id: str, title: str, text: str, source: str,
                 doc_type: str, doc_id: str, score: float):
        self.chunk_id = chunk_id
        self.title = title
        self.text = text
        self.source = source
        self.doc_type = doc_type
        self.doc_id = doc_id
        self.score = score

    def to_dict(self) -> dict:
        return {
            "chunk_id": self.chunk_id,
            "title": self.title,
            "text": self.text,
            "source": self.source,
            "doc_type": self.doc_type,
            "doc_id": self.doc_id,
            "score": round(self.score, 3),
            "evidence_type": "knowledge_base",
        }


async def search_security_knowledge(
    query: str,
    top_k: int = 5,
    doc_type: Optional[str] = None,
    technique_id: Optional[str] = None,
) -> list[KnowledgeHit]:
    """Retrieve relevant security knowledge with optional metadata filter."""
    store = get_knowledge_store()
    search_query = query
    if technique_id:
        search_query = f"{technique_id} {query}"

    raw_hits = store.search(search_query, top_k=top_k, doc_type=doc_type)

    hits = []
    for h in raw_hits:
        if technique_id and technique_id.lower() not in h.get("text", "").lower() and technique_id.lower() not in h.get("doc_id", "").lower():
            continue
        hits.append(KnowledgeHit(
            chunk_id=h["chunk_id"],
            title=h.get("title", ""),
            text=h["text"],
            source=h.get("source", "unknown"),
            doc_type=h.get("doc_type", "unknown"),
            doc_id=h.get("doc_id", ""),
            score=float(h.get("score", 0)),
        ))
    return hits[:top_k]


async def get_mitre_technique(technique_id: str) -> Optional[KnowledgeHit]:
    hits = await search_security_knowledge(
        query=technique_id,
        top_k=3,
        doc_type="mitre",
        technique_id=technique_id,
    )
    for hit in hits:
        if technique_id.upper() in hit.doc_id.upper() or technique_id.upper() in hit.text.upper():
            return hit
    return hits[0] if hits else None
