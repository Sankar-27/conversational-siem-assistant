"""
Three-Stage AI Agent Investigation Engine.

Implements the formal 3-Stage Investigation Workflow:
  Stage 1: Detection / Retrieval Agent
           - Parse natural language query & security entities
           - Retrieve relevant logs from 10K+ SIEM dataset
           - Retrieve threat patterns & mitigation context via RAG
  Stage 2: Investigation / Correlation Agent
           - Analyze retrieved log stream & build chronological timeline
           - Correlate events across 20+ threat patterns & MITRE ATT&CK
           - Extract Indicators of Compromise (IOCs) & compute severity risk score
  Stage 3: Investigation Summary Agent
           - Produce evidence-grounded final conclusion
           - Demarcate confirmed facts vs. analytical hypotheses
           - Generate actionable remediation playbooks
"""
from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.core.config import settings
from app.core.logging import logger
from app.modules.conversational.context_manager import get_context
from app.modules.conversational.intent_extractor import extract_intent
from app.modules.conversational.ambiguity_resolver import resolve_ambiguity
from app.modules.query_engine.query_generator import build_query
from app.modules.query_engine.query_validator import validate_dsl
from app.modules.query_engine.elasticsearch_client import get_siem
from app.modules.threat_analysis.ioc_extractor import extract_iocs
from app.modules.threat_analysis.event_correlator import correlate_events, AttackPattern
from app.modules.mitre.attack_mapper import map_to_mitre, MITRETechniqueResult
from app.modules.mitre.timeline_builder import build_timeline, summarize_timeline
from app.modules.rag.retriever import search_security_knowledge, KnowledgeHit
from app.modules.explainability.evidence_linker import generate_explanation
from app.modules.threat_analysis.attack_chain import reconstruct_attack_chain, score_incident_severity


class AgentStageOutput(BaseModel):
    stage_number: int
    stage_name: str
    status: str = "completed"  # pending | running | completed | failed
    duration_ms: float = 0.0
    summary: str = ""
    details: Dict[str, Any] = Field(default_factory=dict)


class ThreeStageInvestigationResult(BaseModel):
    investigation_id: str
    conversation_id: str
    nl_query: str
    status: str = "completed"  # completed | ambiguous | failed | error
    total_duration_ms: float = 0.0
    
    # 3-Stage structured progress traces
    stages: List[AgentStageOutput] = Field(default_factory=list)
    
    # Stage 1 artifacts
    entities: Dict[str, Any] = Field(default_factory=dict)
    generated_dsl: Dict[str, Any] = Field(default_factory=dict)
    retrieved_logs_count: int = 0
    retrieved_logs: List[Dict[str, Any]] = Field(default_factory=list)
    rag_threat_context: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Stage 2 artifacts
    matched_patterns: List[Dict[str, Any]] = Field(default_factory=list)
    mitre_tactics: List[Dict[str, Any]] = Field(default_factory=list)
    iocs: List[Dict[str, Any]] = Field(default_factory=list)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    severity_assessment: Dict[str, Any] = Field(default_factory=dict)
    
    # Stage 3 artifacts
    conversational_response: str = ""
    confirmed_evidence: List[str] = Field(default_factory=list)
    assumptions_and_hypotheses: List[str] = Field(default_factory=list)
    remediation_recommendations: List[str] = Field(default_factory=list)
    confidence: str = "High"


# ═══════════════════════════════════════════════════════════════════════════════
# Stage 1: Detection / Retrieval Agent
# ═══════════════════════════════════════════════════════════════════════════════
class DetectionRetrievalAgent:
    """Understands query intent, extracts entities, retrieves logs, and performs RAG lookup."""

    async def execute(self, nl_query: str, conversation_id: str) -> Dict[str, Any]:
        start = time.perf_counter()
        context = get_context(conversation_id)
        
        # 1. Intent & entity extraction
        intent_res = await extract_intent(nl_query, context.get_history())
        intent_res = resolve_ambiguity(intent_res, nl_query)
        
        if intent_res.ambiguous:
            return {
                "ambiguous": True,
                "clarification": intent_res.clarification_needed or "Please clarify your query.",
                "duration_ms": round((time.perf_counter() - start) * 1000, 2),
            }

        merged = context.merge_entities(intent_res.entities, intent_res.is_followup, nl_query)
        entities_dict = merged.model_dump(exclude_none=True)

        # 2. Build and execute SIEM Query on 10K+ logs
        ir, dsl = await build_query(merged)
        val = validate_dsl(dsl)
        if not val.valid:
            logger.warning("dsl_validation_warning", errors=val.errors)

        siem = get_siem()
        search_res = await siem.search(dsl, index=settings.ELASTICSEARCH_INDEX)
        hits = search_res.get("hits", {}).get("hits", [])
        total_hits = search_res.get("hits", {}).get("total", {}).get("value", len(hits))

        # 3. RAG retrieval of threat pattern context
        rag_query = f"{intent_res.intent} {entities_dict.get('event_action', '')} {nl_query}"
        rag_hits: List[KnowledgeHit] = await search_security_knowledge(rag_query, top_k=5)
        rag_context = [h.to_dict() for h in rag_hits]

        duration = round((time.perf_counter() - start) * 1000, 2)
        summary = f"Parsed entities ({len(entities_dict)} fields), retrieved {total_hits} matching log events from SIEM dataset, and retrieved {len(rag_context)} threat knowledge docs via RAG."

        return {
            "ambiguous": False,
            "entities": entities_dict,
            "dsl": dsl,
            "ir": ir,
            "hits": hits,
            "total_count": total_hits,
            "rag_context": rag_context,
            "duration_ms": duration,
            "summary": summary,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Stage 2: Investigation / Correlation Agent
# ═══════════════════════════════════════════════════════════════════════════════
class InvestigationCorrelationAgent:
    """Correlates log stream, extracts IOCs, matches 20+ threat patterns & MITRE, and assesses risk."""

    async def execute(self, hits: List[Dict[str, Any]], entities: Dict[str, Any], rag_context: List[Dict[str, Any]]) -> Dict[str, Any]:
        start = time.perf_counter()

        # 1. IOC Extraction
        ioc_container = await extract_iocs(hits)
        iocs = ioc_container.to_list()

        # 2. Pattern Correlation across 20+ threat patterns
        patterns: List[AttackPattern] = correlate_events(hits)
        pattern_dicts = [p.to_dict() for p in patterns]

        # 3. MITRE ATT&CK Mapping
        mitre_results: List[MITRETechniqueResult] = map_to_mitre(patterns)
        mitre_dicts = [m.to_dict() for m in mitre_results]

        # 4. Timeline Construction
        timeline_events = build_timeline(hits)
        tl_dicts = [e.to_dict() for e in timeline_events[:100]]

        # 5. Attack Chain & Severity Assessment
        primary_ip = entities.get("source_ip") or (pattern_dicts[0].get("source_ip") if pattern_dicts else None)
        attack_chain = reconstruct_attack_chain(patterns, source_ip=primary_ip)
        severity = score_incident_severity(patterns)

        duration = round((time.perf_counter() - start) * 1000, 2)
        summary = (
            f"Correlated {len(hits)} logs into {len(patterns)} threat patterns "
            f"({', '.join(p['pattern_type'] for p in pattern_dicts[:3]) if pattern_dicts else 'No anomalies'}), "
            f"extracted {len(iocs)} IOCs, mapped to {len(mitre_dicts)} MITRE techniques. Severity: {severity.get('level', 'Medium')} ({severity.get('score', 0)}/100)."
        )

        return {
            "iocs": iocs,
            "patterns": pattern_dicts,
            "mitre": mitre_dicts,
            "timeline": tl_dicts,
            "attack_chain": attack_chain,
            "severity": severity,
            "duration_ms": duration,
            "summary": summary,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Stage 3: Investigation Summary Agent
# ═══════════════════════════════════════════════════════════════════════════════
class InvestigationSummaryAgent:
    """Produces the final structured report, separating evidence from assumptions and recommending remediation."""

    async def execute(
        self,
        nl_query: str,
        hits: List[Dict[str, Any]],
        patterns: List[Dict[str, Any]],
        mitre: List[Dict[str, Any]],
        iocs: List[Dict[str, Any]],
        severity: Dict[str, Any],
        rag_context: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        start = time.perf_counter()

        # Generate evidence-grounded explanation
        explanation = await generate_explanation(
            nl_query=nl_query,
            hits=hits,
            patterns=patterns,
            mitre=mitre,
            result_count=len(hits),
        )

        # Distinguish confirmed evidence from hypotheses
        confirmed_evidence = []
        if hits:
            sample_src = hits[0].get("_source", hits[0])
            confirmed_evidence.append(f"Retrieved {len(hits)} matching telemetry records from SIEM index.")
            if "source" in sample_src and "ip" in sample_src["source"]:
                confirmed_evidence.append(f"Identified source IP: {sample_src['source']['ip']}")
            if "event" in sample_src and "action" in sample_src["event"]:
                confirmed_evidence.append(f"Observed event action: {sample_src['event']['action']}")
        
        for p in patterns[:3]:
            confirmed_evidence.append(f"Verified {p.get('pattern_type')} pattern supported by {p.get('evidence_count')} events.")

        assumptions = []
        if patterns:
            top_p = patterns[0]
            assumptions.append(f"Hypothesized attacker intent aligns with {top_p.get('pattern_type')} objective.")
            assumptions.append(f"Confidence score {int(top_p.get('confidence', 0.8) * 100)}% based on event frequency and ECS indicators.")
        else:
            assumptions.append("No active malicious intrusion confirmed in retrieved sample; behavior consistent with baseline noise.")

        # Remediation recommendations from matched MITRE/RAG
        remediation = []
        for r in rag_context:
            text = r.get("text", "")
            if "remediation" in text.lower() or "mitigation" in text.lower():
                remediation.append(text[:200])
        
        if not remediation and patterns:
            p_type = patterns[0].get("pattern_type")
            if "brute_force" in p_type or "login" in p_type:
                remediation.extend([
                    "Temporarily block attacker source IP on perimeter firewall/WAF.",
                    "Enforce rate limiting on authentication endpoints (/login, /api/auth).",
                    "Require MFA / step-up authentication for targeted user accounts.",
                ])
            elif "sql" in p_type or "injection" in p_type:
                remediation.extend([
                    "Deploy WAF signatures to block SQL injection payloads.",
                    "Audit backend queries to use parameterized prepared statements.",
                ])
            elif "scan" in p_type:
                remediation.extend([
                    "Block scanning IP at border routers / security groups.",
                    "Disable unused exposed ports and management services.",
                ])
            else:
                remediation.extend([
                    "Isolate affected endpoint to prevent lateral movement.",
                    "Rotate compromised user credentials and review audit logs.",
                ])
        elif not remediation:
            remediation.append("Continue standard continuous monitoring; no immediate containment required.")

        duration = round((time.perf_counter() - start) * 1000, 2)
        summary = f"Synthesized investigation findings, demarcated {len(confirmed_evidence)} verified facts vs. {len(assumptions)} hypotheses, and formulated {len(remediation)} remediation steps."

        return {
            "explanation": explanation,
            "confirmed_evidence": confirmed_evidence,
            "assumptions": assumptions,
            "remediation": remediation,
            "confidence": "High" if hits and patterns else "Medium",
            "duration_ms": duration,
            "summary": summary,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# 3-Stage Agent Orchestrator
# ═══════════════════════════════════════════════════════════════════════════════
async def run_three_stage_investigation(
    nl_query: str,
    conversation_id: str | None = None,
) -> ThreeStageInvestigationResult:
    """
    Executes the unified 3-stage conversational SIEM investigation workflow.
    """
    overall_start = time.perf_counter()
    inv_id = str(uuid.uuid4())
    conv_id = conversation_id or str(uuid.uuid4())
    
    stages: List[AgentStageOutput] = []

    # ── STAGE 1: Detection & Retrieval Agent ─────────────────────────────────
    stage1_agent = DetectionRetrievalAgent()
    s1_res = await stage1_agent.execute(nl_query, conv_id)

    if s1_res.get("ambiguous"):
        stage1_out = AgentStageOutput(
            stage_number=1,
            stage_name="Detection / Retrieval Agent",
            status="completed",
            duration_ms=s1_res.get("duration_ms", 0.0),
            summary="Query is ambiguous; clarification requested.",
            details={"clarification": s1_res.get("clarification")},
        )
        return ThreeStageInvestigationResult(
            investigation_id=inv_id,
            conversation_id=conv_id,
            nl_query=nl_query,
            status="ambiguous",
            total_duration_ms=round((time.perf_counter() - overall_start) * 1000, 2),
            stages=[stage1_out],
            conversational_response=s1_res.get("clarification", ""),
        )

    stage1_out = AgentStageOutput(
        stage_number=1,
        stage_name="Detection / Retrieval Agent",
        status="completed",
        duration_ms=s1_res.get("duration_ms", 0.0),
        summary=s1_res.get("summary", ""),
        details={
            "entities": s1_res.get("entities", {}),
            "retrieved_count": s1_res.get("total_count", 0),
            "rag_docs_count": len(s1_res.get("rag_context", [])),
        },
    )
    stages.append(stage1_out)

    hits = s1_res.get("hits", [])
    entities = s1_res.get("entities", {})
    rag_context = s1_res.get("rag_context", [])

    # ── STAGE 2: Investigation & Correlation Agent ───────────────────────────
    stage2_agent = InvestigationCorrelationAgent()
    s2_res = await stage2_agent.execute(hits, entities, rag_context)

    stage2_out = AgentStageOutput(
        stage_number=2,
        stage_name="Investigation / Correlation Agent",
        status="completed",
        duration_ms=s2_res.get("duration_ms", 0.0),
        summary=s2_res.get("summary", ""),
        details={
            "patterns_count": len(s2_res.get("patterns", [])),
            "iocs_count": len(s2_res.get("iocs", [])),
            "mitre_count": len(s2_res.get("mitre", [])),
            "severity_level": s2_res.get("severity", {}).get("level", "Medium"),
        },
    )
    stages.append(stage2_out)

    patterns = s2_res.get("patterns", [])
    mitre = s2_res.get("mitre", [])
    iocs = s2_res.get("iocs", [])
    timeline = s2_res.get("timeline", [])
    severity = s2_res.get("severity", {})

    # ── STAGE 3: Investigation Summary Agent ─────────────────────────────────
    stage3_agent = InvestigationSummaryAgent()
    s3_res = await stage3_agent.execute(
        nl_query=nl_query,
        hits=hits,
        patterns=patterns,
        mitre=mitre,
        iocs=iocs,
        severity=severity,
        rag_context=rag_context,
    )

    stage3_out = AgentStageOutput(
        stage_number=3,
        stage_name="Investigation Summary Agent",
        status="completed",
        duration_ms=s3_res.get("duration_ms", 0.0),
        summary=s3_res.get("summary", ""),
        details={
            "evidence_count": len(s3_res.get("confirmed_evidence", [])),
            "recommendations_count": len(s3_res.get("remediation", [])),
            "confidence": s3_res.get("confidence", "High"),
        },
    )
    stages.append(stage3_out)

    total_time = round((time.perf_counter() - overall_start) * 1000, 2)

    # Save turn to conversation context
    context = get_context(conv_id)
    context.add_turn("user", nl_query)
    context.add_turn("assistant", s3_res.get("explanation", ""))
    context.last_result_count = len(hits)
    context.last_investigation_id = inv_id

    # Format retrieved log previews
    log_previews = [h.get("_source", h) for h in hits[:100]]

    return ThreeStageInvestigationResult(
        investigation_id=inv_id,
        conversation_id=conv_id,
        nl_query=nl_query,
        status="completed",
        total_duration_ms=total_time,
        stages=stages,
        entities=entities,
        generated_dsl=s1_res.get("dsl", {}),
        retrieved_logs_count=len(hits),
        retrieved_logs=log_previews,
        rag_threat_context=rag_context,
        matched_patterns=patterns,
        mitre_tactics=mitre,
        iocs=iocs,
        timeline=timeline,
        severity_assessment=severity,
        conversational_response=s3_res.get("explanation", ""),
        confirmed_evidence=s3_res.get("confirmed_evidence", []),
        assumptions_and_hypotheses=s3_res.get("assumptions", []),
        remediation_recommendations=s3_res.get("remediation", []),
        confidence=s3_res.get("confidence", "High"),
    )
