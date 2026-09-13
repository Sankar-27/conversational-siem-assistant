"""
Investigation Service — orchestrates the full investigation pipeline.

Pipeline:
  NL Query
      ↓ Context Manager (load history)
      ↓ Intent Extractor (LLM)
      ↓ Entity Merging (follow-up resolution)
      ↓ Query Generator (LLM → IR → DSL compiler)
      ↓ Query Validator (whitelist + safety)
      ↓ SIEM Client (mock or ES)
      ↓ IOC Extractor (regex + LLM)
      ↓ Event Correlator (rule-based)
      ↓ MITRE Mapper (static table)
      ↓ Timeline Builder
      ↓ Explainability Engine (LLM — evidence grounded)
      ↓ Persist to PostgreSQL
      ↓ Response
"""
from __future__ import annotations
import uuid
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.investigation import (
    Conversation, Investigation, InvestigationStatus,
    IOC, IOCType, MITREMapping, Evidence, Report,
)
from app.models.user import User
from app.modules.conversational.context_manager import get_context, save_context_to_db
from app.modules.conversational.intent_extractor import extract_intent
from app.modules.conversational.schemas import IntentResult
from app.modules.query_engine.query_generator import build_query
from app.modules.query_engine.query_validator import validate_dsl
from app.modules.query_engine.elasticsearch_client import get_siem
from app.modules.threat_analysis.ioc_extractor import extract_iocs
from app.modules.threat_analysis.event_correlator import correlate_events
from app.modules.mitre.attack_mapper import map_to_mitre
from app.modules.mitre.timeline_builder import build_timeline, summarize_timeline
from app.modules.explainability.evidence_linker import generate_explanation
from app.modules.rag.retriever import search_security_knowledge
from app.modules.threat_analysis.attack_chain import (
    reconstruct_attack_chain,
    score_incident_severity,
    build_entity_relationships,
)
from app.core.config import settings
from app.core.logging import logger


class InvestigationResponse:
    def __init__(
        self,
        investigation_id: str,
        conversation_id: str,
        nl_query: str,
        intent: str,
        generated_query_ir: dict,
        elasticsearch_query: dict,
        result_count: int,
        hits_preview: list[dict],
        iocs: list[dict],
        patterns: list[dict],
        mitre: list[dict],
        timeline: list[dict],
        timeline_summary: dict,
        explanation: str,
        status: str,
        ambiguous: bool = False,
        clarification_needed: str | None = None,
        validation_errors: list[str] | None = None,
        knowledge_evidence: list[dict] | None = None,
        siem_evidence: list[dict] | None = None,
        attack_chain: dict | None = None,
        severity: dict | None = None,
        entity_graph: dict | None = None,
    ):
        self.investigation_id = investigation_id
        self.conversation_id = conversation_id
        self.nl_query = nl_query
        self.intent = intent
        self.generated_query_ir = generated_query_ir
        self.elasticsearch_query = elasticsearch_query
        self.result_count = result_count
        self.hits_preview = hits_preview
        self.iocs = iocs
        self.patterns = patterns
        self.mitre = mitre
        self.timeline = timeline
        self.timeline_summary = timeline_summary
        self.explanation = explanation
        self.status = status
        self.ambiguous = ambiguous
        self.clarification_needed = clarification_needed
        self.validation_errors = validation_errors or []
        self.knowledge_evidence = knowledge_evidence or []
        self.siem_evidence = siem_evidence or []
        self.attack_chain = attack_chain or {}
        self.severity = severity or {}
        self.entity_graph = entity_graph or {}

    def to_dict(self) -> dict:
        return self.__dict__


async def run_investigation(
    nl_query: str,
    conversation_id: str,
    user_id: str,
    db: AsyncSession,
) -> InvestigationResponse:
    """Run the full investigation pipeline."""
    logger.info("investigation_start", query=nl_query, conversation_id=conversation_id)

    # ── Step 1: Load context ───────────────────────────────────────────────────
    context = get_context(conversation_id)

    # ── Step 2: Intent & entity extraction ────────────────────────────────────
    intent_result: IntentResult = await extract_intent(nl_query, context.get_history())

    # ── Step 3: Handle ambiguity ───────────────────────────────────────────────
    if intent_result.ambiguous and intent_result.clarification_needed:
        context.add_turn("user", nl_query)
        context.add_turn("assistant", intent_result.clarification_needed)
        return InvestigationResponse(
            investigation_id=str(uuid.uuid4()),
            conversation_id=conversation_id,
            nl_query=nl_query,
            intent="ambiguous",
            generated_query_ir={},
            elasticsearch_query={},
            result_count=0,
            hits_preview=[],
            iocs=[],
            patterns=[],
            mitre=[],
            timeline=[],
            timeline_summary={},
            explanation=intent_result.clarification_needed,
            status="ambiguous",
            ambiguous=True,
            clarification_needed=intent_result.clarification_needed,
        )

    # ── Step 4: Merge entities (follow-up resolution) ─────────────────────────
    merged_entities = context.merge_entities(
        intent_result.entities, intent_result.is_followup, nl_query
    )

    # ── Step 5: Query generation ───────────────────────────────────────────────
    ir, dsl = await build_query(merged_entities)

    # ── Step 6: Query validation ───────────────────────────────────────────────
    validation = validate_dsl(dsl)
    if not validation.valid:
        logger.warning("query_validation_failed", errors=validation.errors)
        return InvestigationResponse(
            investigation_id=str(uuid.uuid4()),
            conversation_id=conversation_id,
            nl_query=nl_query,
            intent=intent_result.intent,
            generated_query_ir=ir,
            elasticsearch_query=dsl,
            result_count=0,
            hits_preview=[],
            iocs=[],
            patterns=[],
            mitre=[],
            timeline=[],
            timeline_summary={},
            explanation=f"Query validation failed: {'; '.join(validation.errors)}",
            status="failed",
            validation_errors=validation.errors,
        )

    # ── Step 7: SIEM execution ─────────────────────────────────────────────────
    siem = get_siem()
    raw_response = await siem.search(dsl, index=settings.ELASTICSEARCH_INDEX)
    hits = raw_response.get("hits", {}).get("hits", [])
    result_count = raw_response.get("hits", {}).get("total", {}).get("value", len(hits))

    # ── Step 8: IOC extraction ─────────────────────────────────────────────────
    ioc_result = await extract_iocs(hits)
    iocs_list = ioc_result.to_list()

    # ── Step 9: Event correlation ──────────────────────────────────────────────
    patterns = correlate_events(hits)

    # ── Step 10: MITRE mapping ─────────────────────────────────────────────────
    mitre_techniques = map_to_mitre(patterns)

    # ── Step 11: Timeline ──────────────────────────────────────────────────────
    timeline_events = build_timeline(hits)
    tl_summary = summarize_timeline(timeline_events)

    # ── Step 12: Security knowledge retrieval (RAG) ───────────────────────────
    knowledge_query = nl_query
    if patterns:
        knowledge_query = f"{patterns[0].pattern_type} {nl_query}"
    knowledge_hits = await search_security_knowledge(knowledge_query, top_k=5)
    knowledge_evidence = [h.to_dict() for h in knowledge_hits]

    # ── Phase 5: Attack chain, severity, entity graph ─────────────────────────
    primary_ip = merged_entities.source_ip
    attack_chain = reconstruct_attack_chain(patterns, source_ip=primary_ip)
    severity = score_incident_severity(patterns)
    entity_graph = build_entity_relationships(hits)

    # ── Step 13: Explanation ───────────────────────────────────────────────────
    explanation = await generate_explanation(
        nl_query, hits, patterns, mitre_techniques, result_count
    )

    # ── Step 14: Persist to DB ─────────────────────────────────────────────────
    investigation_id = str(uuid.uuid4())
    try:
        await _persist_investigation(
            db=db,
            investigation_id=investigation_id,
            conversation_id=conversation_id,
            user_id=user_id,
            nl_query=nl_query,
            ir=ir,
            dsl=dsl,
            result_count=result_count,
            hits=hits,
            iocs_list=iocs_list,
            patterns=patterns,
            mitre_techniques=mitre_techniques,
            explanation=explanation,
        )
        context.add_turn("user", nl_query)
        context.add_turn("assistant", explanation)
        context.last_result_count = result_count
        context.last_investigation_id = investigation_id
        await save_context_to_db(conversation_id, db)
    except Exception as e:
        logger.error("db_persist_failed", error=str(e))

    logger.info("investigation_complete", investigation_id=investigation_id, result_count=result_count)

    return InvestigationResponse(
        investigation_id=investigation_id,
        conversation_id=conversation_id,
        nl_query=nl_query,
        intent=intent_result.intent,
        generated_query_ir=ir,
        elasticsearch_query=dsl,
        result_count=result_count,
        hits_preview=[h.get("_source", h) for h in hits[:10]],
        iocs=iocs_list,
        patterns=[p.to_dict() for p in patterns],
        mitre=[m.to_dict() for m in mitre_techniques],
        timeline=[e.to_dict() for e in timeline_events[:100]],
        timeline_summary=tl_summary,
        explanation=explanation,
        status="completed",
        knowledge_evidence=knowledge_evidence,
        siem_evidence=[
            {"log_id": h.get("_id"), "evidence_type": "siem", "preview": h.get("_source", h)}
            for h in hits[:20]
        ],
        attack_chain=attack_chain,
        severity=severity,
        entity_graph=entity_graph,
    )


async def _persist_investigation(
    db: AsyncSession,
    investigation_id: str,
    conversation_id: str,
    user_id: str,
    nl_query: str,
    ir: dict,
    dsl: dict,
    result_count: int,
    hits: list[dict],
    iocs_list: list[dict],
    patterns,
    mitre_techniques,
    explanation: str,
) -> None:
    """Persist investigation results to PostgreSQL."""
    from uuid import UUID as PYUUID

    inv = Investigation(
        id=PYUUID(investigation_id),
        conversation_id=PYUUID(conversation_id),
        user_id=PYUUID(user_id),
        nl_query=nl_query,
        generated_query=ir,
        elasticsearch_query=dsl,
        result_count=result_count,
        status=InvestigationStatus.completed,
        explanation=explanation,
    )
    db.add(inv)
    await db.flush()

    # Persist IOCs
    for ioc in iocs_list[:100]:
        db.add(IOC(
            investigation_id=PYUUID(investigation_id),
            type=ioc.get("type", "ipv4"),
            value=str(ioc.get("value", ""))[:1000],
            confidence=1.0,
            occurrence_count=ioc.get("occurrence_count", 1),
        ))

    # Persist MITRE mappings
    for m in mitre_techniques:
        db.add(MITREMapping(
            investigation_id=PYUUID(investigation_id),
            technique_id=m.technique_id,
            technique_name=m.technique_name,
            tactic=m.tactic,
            confidence=m.confidence,
            evidence_count=m.evidence_count,
            description=m.description,
        ))

    # Persist evidence (up to 50 log entries)
    for hit in hits[:50]:
        src = hit.get("_source", hit)
        db.add(Evidence(
            investigation_id=PYUUID(investigation_id),
            log_id=hit.get("_id"),
            timestamp=src.get("@timestamp"),
            source_ip=(src.get("source") or {}).get("ip"),
            destination_ip=(src.get("destination") or {}).get("ip"),
            username=(src.get("user") or {}).get("name"),
            event_type=(src.get("event") or {}).get("category"),
            event_action=(src.get("event") or {}).get("action"),
            severity=(src.get("event") or {}).get("severity"),
            raw_log=src,
        ))

    await db.flush()
