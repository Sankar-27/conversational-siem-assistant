"""Tests for RAG layer (Phase 2.2)."""
import pytest

from app.modules.rag.document_loader import load_all_knowledge_documents
from app.modules.rag.retriever import search_security_knowledge, get_mitre_technique


def test_load_knowledge_documents():
    docs = load_all_knowledge_documents()
    assert len(docs) >= 8
    assert any(d.doc_type == "mitre" for d in docs)


@pytest.mark.asyncio
async def test_search_security_knowledge():
    hits = await search_security_knowledge("brute force credential access", top_k=3)
    assert len(hits) >= 1
    assert hits[0].to_dict()["evidence_type"] == "knowledge_base"


@pytest.mark.asyncio
async def test_get_mitre_technique():
    hit = await get_mitre_technique("T1110")
    assert hit is not None
    assert "T1110" in hit.doc_id or "T1110" in hit.text
