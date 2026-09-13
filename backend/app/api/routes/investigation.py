"""
Conversational SIEM Core API Routes.

Exposes:
- POST /api/investigate: Main 3-stage AI Agent investigation workflow
- POST /api/query: NLP entity and intent extraction
- GET /api/logs: Search & filter the 10K+ security logs dataset
- GET /api/threats: List & search the 20+ threat patterns knowledge base
- GET /api/investigations: Retrieve investigation history
"""
from fastapi import APIRouter, Depends, HTTPException, Query as FastQuery
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from uuid import UUID
from typing import Optional, List, Dict, Any

from app.db.session import get_db
from app.core.auth import get_current_user, require_analyst
from app.models.investigation import Conversation, Investigation, InvestigationStatus
from app.modules.agent.investigation_agent import run_three_stage_investigation
from app.modules.conversational.context_manager import get_context
from app.modules.conversational.intent_extractor import extract_intent
from app.modules.conversational.ambiguity_resolver import resolve_ambiguity
from app.modules.query_engine.query_generator import build_query
from app.modules.query_engine.elasticsearch_client import get_siem
from app.modules.rag.retriever import search_security_knowledge

router = APIRouter(tags=["investigation"])


class InvestigateRequest(BaseModel):
    conversation_id: str | None = None
    query: str


class QueryNLPRequest(BaseModel):
    query: str
    conversation_id: str | None = None


# ── 1. Main 3-Stage Conversational Agent Investigation ───────────────────────
@router.post("/investigate")
@router.post("/investigate/chat")
async def investigate(
    req: InvestigateRequest,
    current_user=Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """
    Core 3-Stage Conversational SIEM Investigation:
    Stage 1: Detection / Retrieval Agent (Query NLP + 10K logs + RAG)
    Stage 2: Investigation / Correlation Agent (20+ Threat Patterns + IOCs + MITRE)
    Stage 3: Investigation Summary Agent (Evidence Grounding + Remediation)
    """
    if not req.query.strip():
        raise HTTPException(status_code=400, detail="Query cannot be empty")

    conversation_id = req.conversation_id
    if conversation_id:
        result = await db.execute(
            select(Conversation).where(Conversation.id == UUID(conversation_id))
        )
        conv = result.scalar_one_or_none()
        if not conv:
            conv = Conversation(
                id=UUID(conversation_id),
                user_id=UUID(current_user.user_id),
                title=req.query[:100],
            )
            db.add(conv)
            await db.flush()
    else:
        conv = Conversation(
            user_id=UUID(current_user.user_id),
            title=req.query[:100],
        )
        db.add(conv)
        await db.flush()
        conversation_id = str(conv.id)

    # Run 3-stage agent pipeline
    result = await run_three_stage_investigation(
        nl_query=req.query,
        conversation_id=conversation_id,
    )

    # Persist investigation
    try:
        inv = Investigation(
            id=UUID(result.investigation_id),
            conversation_id=UUID(conversation_id),
            user_id=UUID(current_user.user_id),
            nl_query=req.query,
            generated_query=result.generated_dsl,
            elasticsearch_query=result.generated_dsl,
            result_count=result.retrieved_logs_count,
            status=InvestigationStatus.completed if result.status == "completed" else InvestigationStatus.failed,
            explanation=result.conversational_response,
        )
        db.add(inv)
        await db.flush()
    except Exception:
        pass

    return result.model_dump()


# ── 2. Dedicated NLP Query Parsing Endpoint ──────────────────────────────────
@router.post("/query")
async def parse_query_nlp(
    req: QueryNLPRequest,
    current_user=Depends(get_current_user),
):
    """
    Dedicated NLP endpoint: Extract security intent, indicators, and generated IR/DSL.
    """
    context = get_context(req.conversation_id or "default")
    intent_res = await extract_intent(req.query, context.get_history())
    intent_res = resolve_ambiguity(intent_res, req.query)
    
    merged = context.merge_entities(intent_res.entities, intent_res.is_followup, req.query)
    ir, dsl = await build_query(merged)

    return {
        "query": req.query,
        "intent": intent_res.intent,
        "is_followup": intent_res.is_followup,
        "entities": merged.model_dump(exclude_none=True),
        "intermediate_representation": ir,
        "elasticsearch_dsl": dsl,
        "confidence": intent_res.confidence,
    }


# ── 3. Security Logs Explorer & Filtering Endpoint ───────────────────────────
@router.get("/logs")
async def get_logs(
    source_ip: Optional[str] = None,
    event_action: Optional[str] = None,
    username: Optional[str] = None,
    threat_tag: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = FastQuery(50, le=500),
    offset: int = 0,
    current_user=Depends(get_current_user),
):
    """
    Explore, search, and filter the 10,000+ security logs dataset.
    """
    siem = get_siem()
    dsl: Dict[str, Any] = {"query": {"bool": {"must": []}}, "size": limit}
    
    if source_ip:
        dsl["query"]["bool"]["must"].append({"term": {"source.ip": source_ip}})
    if event_action:
        dsl["query"]["bool"]["must"].append({"term": {"event.action": event_action}})
    if username:
        dsl["query"]["bool"]["must"].append({"term": {"user.name": username}})
    if threat_tag:
        dsl["query"]["bool"]["must"].append({"term": {"threat.indicator": threat_tag}})
    if search:
        dsl["query"]["bool"]["must"].append({"wildcard": {"url.original": f"*{search}*"}})

    raw_response = await siem.search(dsl)
    hits = raw_response.get("hits", {}).get("hits", [])
    total = raw_response.get("hits", {}).get("total", {}).get("value", len(hits))

    logs_slice = [h.get("_source", h) for h in hits[offset:offset + limit]]
    return {
        "total_records": total,
        "offset": offset,
        "limit": limit,
        "count": len(logs_slice),
        "logs": logs_slice,
    }


# ── 4. 20+ Threat Patterns Knowledge Base Endpoint ───────────────────────────
@router.get("/threats")
async def get_threat_patterns(
    query: Optional[str] = None,
    limit: int = 30,
    current_user=Depends(get_current_user),
):
    """
    List and retrieve the 20+ threat patterns and detection signatures from knowledge base.
    """
    search_q = query or "threat attack pattern security detection"
    hits = await search_security_knowledge(search_q, top_k=limit)
    
    return {
        "count": len(hits),
        "threat_patterns": [h.to_dict() for h in hits],
    }


# ── 5. List Past Investigations ──────────────────────────────────────────────
@router.get("/investigations")
async def list_investigations(
    skip: int = 0,
    limit: int = 20,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List recent investigations."""
    result = await db.execute(
        select(Investigation)
        .order_by(Investigation.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    investigations = result.scalars().all()
    return [
        {
            "id": str(inv.id),
            "conversation_id": str(inv.conversation_id),
            "nl_query": inv.nl_query,
            "result_count": inv.result_count,
            "status": inv.status.value,
            "created_at": inv.created_at.isoformat(),
        }
        for inv in investigations
    ]
