"""
LangGraph Workflow Engine for Threat Analysis — explicit state-graph workflow for agentic SIEM investigations.
Implements nodes, conditional edge transitions, evidence grounding, and MCP tool execution.
"""
from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple, Callable
from pydantic import BaseModel, Field

from app.core.config import settings
from app.core.logging import logger
from app.core.mcp_client import get_mcp_client
from app.core.observability import get_metrics_collector, ToolExecutionMetric, InvestigationMetric
from app.modules.conversational.context_manager import get_context
from app.modules.conversational.intent_extractor import extract_intent
from app.modules.conversational.ambiguity_resolver import resolve_ambiguity
from app.modules.threat_analysis.ioc_extractor import extract_iocs
from app.modules.threat_analysis.event_correlator import correlate_events
from app.modules.mitre.attack_mapper import map_to_mitre
from app.modules.mitre.timeline_builder import build_timeline, summarize_timeline
from app.modules.explainability.evidence_linker import generate_explanation
from app.modules.threat_analysis.attack_chain import (
    reconstruct_attack_chain,
    score_incident_severity,
    build_entity_relationships,
)


class AgentState(BaseModel):
    investigation_id: str
    conversation_id: str
    nl_query: str
    status: str = "initialized"  # initialized | planned | running | awaiting_approval | completed | failed | timeout
    current_node: str = "start"
    executed_nodes: List[str] = Field(default_factory=list)
    plan: List[str] = Field(default_factory=list)
    max_iterations: int = 8
    pending_approval: Optional[Dict[str, Any]] = None
    entities: Dict[str, Any] = Field(default_factory=dict)
    hits: List[Dict[str, Any]] = Field(default_factory=list)
    ir: Dict[str, Any] = Field(default_factory=dict)
    dsl: Dict[str, Any] = Field(default_factory=dict)
    iocs: List[Dict[str, Any]] = Field(default_factory=list)
    patterns: List[Dict[str, Any]] = Field(default_factory=list)
    mitre: List[Dict[str, Any]] = Field(default_factory=list)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    knowledge_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    siem_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    attack_chain: Dict[str, Any] = Field(default_factory=dict)
    severity: Dict[str, Any] = Field(default_factory=dict)
    threat_assessment: Dict[str, Any] = Field(default_factory=dict)
    tool_calls: List[Dict[str, Any]] = Field(default_factory=list)
    conclusion: str = ""
    errors: List[str] = Field(default_factory=list)


# Action tools requiring human-in-the-loop authorization
HIGH_RISK_ACTION_TOOLS = {"block_ip", "isolate_host", "revoke_user", "execute_containment"}


class GraphNode:
    def __init__(self, name: str, func: Callable[[AgentState], Any]):
        self.name = name
        self.func = func


class StateGraph:
    """StateGraph engine for agent execution workflow."""

    def __init__(self):
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: Dict[str, str] = {}

    def add_node(self, name: str, func: Callable[[AgentState], Any]):
        self.nodes[name] = GraphNode(name, func)

    def add_edge(self, source: str, target: str):
        self.edges[source] = target

    async def run(self, state: AgentState, start_node: str = "nlp_extract") -> AgentState:
        curr = start_node
        start_time = time.perf_counter()
        collector = get_metrics_collector()

        while curr and curr in self.nodes:
            if state.status in ("awaiting_approval", "failed", "timeout", "completed"):
                break

            state.current_node = curr
            state.executed_nodes.append(curr)
            logger.info("graph_node_exec", node=curr, investigation_id=state.investigation_id)

            node_func = self.nodes[curr].func
            if asyncio.iscoroutinefunction(node_func):
                state = await node_func(state)
            else:
                state = node_func(state)

            curr = self.edges.get(curr)

        total_ms = round((time.perf_counter() - start_time) * 1000, 2)
        collector.record_investigation(InvestigationMetric(
            investigation_id=state.investigation_id,
            conversation_id=state.conversation_id,
            nl_query=state.nl_query,
            status=state.status,
            total_duration_ms=total_ms,
            siem_hits_count=len(state.hits),
            iocs_count=len(state.iocs),
            mitre_count=len(state.mitre),
            rag_hits_count=len(state.knowledge_evidence),
        ))

        return state


# ── Graph Node Handlers ───────────────────────────────────────────────────────

async def nlp_extract_node(state: AgentState) -> AgentState:
    context = get_context(state.conversation_id)
    intent_res = await extract_intent(state.nl_query, context.get_history())
    intent_res = resolve_ambiguity(intent_res, state.nl_query)

    if intent_res.ambiguous:
        state.status = "ambiguous"
        state.conclusion = intent_res.clarification_needed or "Clarification needed."
        return state

    merged = context.merge_entities(intent_res.entities, intent_res.is_followup, state.nl_query)
    state.entities = merged.model_dump(exclude_none=True)
    return state


async def planner_node(state: AgentState) -> AgentState:
    plan = ["mcp_search_logs"]
    if state.entities.get("source_ip"):
        plan.extend(["mcp_related_events", "mcp_lookup_ip"])
    plan.extend(["mcp_knowledge_search", "correlate_evidence", "evidence_grounding"])
    state.plan = plan
    state.status = "running"
    return state


async def mcp_execution_node(state: AgentState) -> AgentState:
    mcp = get_mcp_client()
    collector = get_metrics_collector()

    # 1. Search SIEM logs via SIEM MCP Server
    search_res = await mcp.call_tool("search_logs", {"entities": state.entities})
    state.tool_calls.append({
        "tool_name": "search_logs",
        "arguments": {"entities": state.entities},
        "result_summary": f"{search_res.get('result_count', len(search_res.get('hits', [])))} SIEM hits",
        "status": "completed" if search_res.get("ok") else "failed",
    })
    collector.record_tool_execution("search_logs", 50.0, "completed" if search_res.get("ok") else "failed")

    if search_res.get("ok"):
        state.hits = search_res.get("hits", [])
        state.ir = search_res.get("ir", {})
        state.dsl = search_res.get("dsl", {})
        state.siem_evidence = [
            {"log_id": h.get("_id"), "evidence_type": "siem", "source": h.get("_source", h)}
            for h in state.hits[:20]
        ]

    # 2. Threat Intel Lookup via Threat Intel MCP Server
    src_ip = state.entities.get("source_ip")
    if src_ip:
        ti_res = await mcp.call_tool("lookup_ip", {"ip": src_ip})
        state.tool_calls.append({
            "tool_name": "lookup_ip",
            "arguments": {"ip": src_ip},
            "result_summary": f"Reputation: {ti_res.get('reputation', 'unknown')} (score: {ti_res.get('score', 0)})",
            "status": "completed",
        })
        collector.record_tool_execution("lookup_ip", 20.0, "completed")

    return state


async def correlate_node(state: AgentState) -> AgentState:
    # IOC Extraction
    ioc_res = await extract_iocs(state.hits)
    state.iocs = ioc_res.to_list()

    # Event Correlation & MITRE Mapping
    patterns = correlate_events(state.hits)
    state.patterns = [p.to_dict() for p in patterns]

    mitre_objs = map_to_mitre(patterns)
    state.mitre = [m.to_dict() for m in mitre_objs]

    # Timeline Construction
    tl_events = build_timeline(state.hits)
    state.timeline = [e.to_dict() for e in tl_events[:100]]

    # Attack chain & severity scoring
    state.attack_chain = reconstruct_attack_chain(patterns, source_ip=state.entities.get("source_ip"))
    state.severity = score_incident_severity(patterns)

    return state


async def knowledge_rag_node(state: AgentState) -> AgentState:
    mcp = get_mcp_client()
    collector = get_metrics_collector()

    query = state.nl_query
    if state.patterns:
        query = f"{state.patterns[0].get('pattern_type', '')} {state.nl_query}"

    rag_res = await mcp.call_tool("search_security_knowledge", {"query": query, "top_k": 5})
    if rag_res.get("ok"):
        state.knowledge_evidence = rag_res.get("results", [])

    state.tool_calls.append({
        "tool_name": "search_security_knowledge",
        "arguments": {"query": query},
        "result_summary": f"{len(state.knowledge_evidence)} knowledge hits",
        "status": "completed",
    })
    collector.record_tool_execution("search_security_knowledge", 30.0, "completed")

    return state


async def evidence_grounding_node(state: AgentState) -> AgentState:
    explanation = await generate_explanation(
        state.nl_query,
        state.hits,
        state.patterns,
        state.mitre,
        len(state.hits),
    )

    state.threat_assessment = {
        "observed_evidence": state.siem_evidence[:10],
        "retrieved_knowledge": state.knowledge_evidence[:5],
        "ai_assessment": explanation,
        "confidence": "High" if state.hits else "Medium",
    }
    state.conclusion = explanation
    state.status = "completed"
    return state


# Build execution graph
def build_investigation_graph() -> StateGraph:
    g = StateGraph()
    g.add_node("nlp_extract", nlp_extract_node)
    g.add_node("planner", planner_node)
    g.add_node("mcp_execution", mcp_execution_node)
    g.add_node("correlation", correlate_node)
    g.add_node("knowledge_rag", knowledge_rag_node)
    g.add_node("evidence_grounding", evidence_grounding_node)

    g.add_edge("nlp_extract", "planner")
    g.add_edge("planner", "mcp_execution")
    g.add_edge("mcp_execution", "correlation")
    g.add_edge("correlation", "knowledge_rag")
    g.add_edge("knowledge_rag", "evidence_grounding")
    return g
