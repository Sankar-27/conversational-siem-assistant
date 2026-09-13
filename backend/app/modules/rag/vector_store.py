"""Vector store — ChromaDB with keyword-search fallback."""
from __future__ import annotations

import re
from typing import Optional

from app.core.config import settings
from app.core.logging import logger
from app.modules.rag.chunker import chunk_document
from app.modules.rag.document_loader import KnowledgeDocument, load_all_knowledge_documents

_store: Optional["KnowledgeVectorStore"] = None


class KnowledgeVectorStore:
    def __init__(self):
        self._chunks: list[dict] = []
        self._chroma = None
        self._collection = None
        self._use_chroma = False
        self._init_store()

    def _init_store(self) -> None:
        try:
            import chromadb
            client = chromadb.PersistentClient(path=settings.CHROMA_PERSIST_DIR)
            self._collection = client.get_or_create_collection(settings.MITRE_COLLECTION)
            self._chroma = client
            self._use_chroma = True
            if self._collection.count() == 0:
                self.ingest_all()
            else:
                self._load_chunks_memory()
            logger.info("rag_chroma_initialized", count=self._collection.count())
        except Exception as e:
            logger.warning("rag_chroma_fallback", error=str(e))
            self._use_chroma = False
            self.ingest_all()

    def _load_chunks_memory(self) -> None:
        docs = load_all_knowledge_documents()
        all_chunks: list[dict] = []
        for doc in docs:
            all_chunks.extend(chunk_document(doc))
        self._chunks = all_chunks

    def ingest_all(self) -> int:
        docs = load_all_knowledge_documents()
        all_chunks: list[dict] = []
        for doc in docs:
            all_chunks.extend(chunk_document(doc))

        self._chunks = all_chunks

        if self._use_chroma and self._collection is not None:
            try:
                # Delete existing documents in collection and re-add all updated chunks
                existing = self._collection.get()
                if existing and existing.get("ids"):
                    self._collection.delete(ids=existing["ids"])
            except Exception:
                pass
            
            ids = [c["chunk_id"] for c in all_chunks]
            texts = [c["text"] for c in all_chunks]
            metadatas = [{
                "doc_id": c["doc_id"],
                "title": c["title"],
                "source": c["source"],
                "doc_type": c["doc_type"],
            } for c in all_chunks]
            self._collection.add(ids=ids, documents=texts, metadatas=metadatas)

        return len(all_chunks)

    def search(
        self,
        query: str,
        top_k: int = 5,
        doc_type: Optional[str] = None,
    ) -> list[dict]:
        keyword_hits = self._keyword_search(query, top_k=top_k * 2, doc_type=doc_type)
        chroma_hits = []
        if self._use_chroma and self._collection is not None:
            where = {"doc_type": doc_type} if doc_type else None
            try:
                results = self._collection.query(
                    query_texts=[query],
                    n_results=top_k,
                    where=where,
                )
                for i, doc_id in enumerate(results["ids"][0]):
                    chroma_hits.append({
                        "chunk_id": doc_id,
                        "text": results["documents"][0][i],
                        "score": 1.0 - (results["distances"][0][i] if results.get("distances") else 0),
                        "source": results["metadatas"][0][i].get("source"),
                        "doc_type": results["metadatas"][0][i].get("doc_type"),
                        "title": results["metadatas"][0][i].get("title"),
                        "doc_id": results["metadatas"][0][i].get("doc_id"),
                    })
            except Exception as e:
                logger.warning("rag_chroma_query_failed", error=str(e))

        seen = set()
        merged = []
        for hit in keyword_hits + chroma_hits:
            cid = hit["chunk_id"]
            if cid not in seen:
                seen.add(cid)
                merged.append(hit)
        return merged[:top_k]

    def _keyword_search(self, query: str, top_k: int, doc_type: Optional[str]) -> list[dict]:
        if not self._chunks:
            self._load_chunks_memory()
        tokens = set(re.findall(r"[a-z0-9]+", query.lower()))
        scored = []
        for chunk in self._chunks:
            if doc_type and chunk.get("doc_type") != doc_type:
                continue
            searchable = f"{chunk.get('doc_id', '')} {chunk.get('title', '')} {chunk['text']}"
            text_tokens = set(re.findall(r"[a-z0-9]+", searchable.lower()))
            overlap = len(tokens & text_tokens)
            if overlap == 0:
                continue
            scored.append((overlap / max(len(tokens), 1), chunk))
        scored.sort(key=lambda x: -x[0])
        return [{
            "chunk_id": c["chunk_id"],
            "text": c["text"],
            "score": score,
            "source": c["source"],
            "doc_type": c["doc_type"],
            "title": c["title"],
            "doc_id": c["doc_id"],
        } for score, c in scored[:top_k]]


def get_knowledge_store() -> KnowledgeVectorStore:
    global _store
    if _store is None:
        _store = KnowledgeVectorStore()
    return _store
