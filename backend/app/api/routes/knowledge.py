"""Knowledge base / RAG API routes (Phase 2.2)."""
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from app.core.auth import get_current_user
from app.modules.rag.retriever import search_security_knowledge, get_mitre_technique
from app.modules.rag.vector_store import get_knowledge_store

router = APIRouter(prefix="/knowledge", tags=["knowledge"])


class KnowledgeSearchRequest(BaseModel):
    query: str
    top_k: int = 5
    doc_type: str | None = None


@router.post("/search")
async def search_knowledge(
    req: KnowledgeSearchRequest,
    current_user=Depends(get_current_user),
):
    hits = await search_security_knowledge(req.query, top_k=req.top_k, doc_type=req.doc_type)
    return {
        "query": req.query,
        "count": len(hits),
        "results": [h.to_dict() for h in hits],
        "evidence_type": "knowledge_base",
    }


@router.get("/mitre/{technique_id}")
async def get_technique(
    technique_id: str,
    current_user=Depends(get_current_user),
):
    hit = await get_mitre_technique(technique_id)
    if not hit:
        return {"ok": False, "error": f"Technique {technique_id} not found"}
    return {"ok": True, "technique": hit.to_dict()}


@router.post("/reindex")
async def reindex_knowledge(current_user=Depends(get_current_user)):
    store = get_knowledge_store()
    count = store.ingest_all()
    return {"ok": True, "documents_indexed": count}
