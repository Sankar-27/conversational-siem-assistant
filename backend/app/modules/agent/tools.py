"""
Agent Tools — controlled capabilities for the investigation agent (Phase 3.2).

All SIEM search tools route through the IR compiler and query validator.
"""
from __future__ import annotations

import time
import uuid
from typing import Any, Optional

from app.core.config import settings
from app.core.logging import logger
from app.modules.conversational.entities import ExtractedEntities
from app.modules.query_engine.query_generator import build_query
from app.modules.query_engine.query_validator import validate_dsl
from app.modules.query_engine.elasticsearch_client import get_siem
from app.modules.threat_analysis.ioc_extractor import extract_iocs
from app.modules.threat_analysis.event_correlator import correlate_events
from app.modules.mitre.attack_mapper import map_to_mitre
from app.modules.mitre.timeline_builder import build_timeline, summarize_timeline
from app.modules.rag.retriever import search_security_knowledge, get_mitre_technique
from app.modules.reporting.report_builder import build_report
from app.modules.agent.state import ToolCallRecord, AgentStepStatus


# Mock threat intelligence — replace with external TI APIs in production
TI_REPUTATION: dict[str, dict] = {
    "185.220.101.45": {"reputation": "malicious", "category": "tor_exit_node", "score": 85},
    "45.142.212.100": {"reputation": "malicious", "category": "scanner", "score": 90},
    "203.0.113.99": {"reputation": "suspicious", "category": "web_attacker", "score": 70},
}


async def search_logs(entities: ExtractedEntities) -> dict:
    """Search SIEM via validated IR → DSL pipeline."""
    ir, dsl = await build_query(entities)
    validation = validate_dsl(dsl)
    if not validation.valid:
        return {"ok": False, "errors": validation.errors, "ir": ir, "dsl": dsl}

    siem = get_siem()
    raw = await siem.search(dsl, index=settings.ELASTICSEARCH_INDEX)
    hits = raw.get("hits", {}).get("hits", [])
    count = raw.get("hits", {}).get("total", {}).get("value", len(hits))
    return {
        "ok": True,
        "ir": ir,
        "dsl": dsl,
        "result_count": count,
        "hits": hits,
        "evidence_type": "siem",
    }


async def get_event(event_id: str, hits: list[dict]) -> Optional[dict]:
    for hit in hits:
        if hit.get("_id") == event_id:
            return hit
    return None


async def get_related_events(source_ip: str, hits: list[dict]) -> list[dict]:
    related = []
    for hit in hits:
        src = hit.get("_source", hit)
        ip = (src.get("source") or {}).get("ip")
        if ip == source_ip:
            related.append(hit)
    return related


async def search_threat_intelligence(ioc_type: str, value: str) -> dict:
    if ioc_type == "ip":
        return await lookup_ip(value)
    if ioc_type == "domain":
        return await lookup_domain(value)
    if ioc_type in ("hash", "md5", "sha256"):
        return await lookup_hash(value)
    return {"ok": False, "error": f"Unsupported IOC type: {ioc_type}"}


async def lookup_ip(ip: str) -> dict:
    rep = TI_REPUTATION.get(ip, {"reputation": "unknown", "category": "none", "score": 0})
    return {"ok": True, "ioc_type": "ip", "value": ip, **rep, "evidence_type": "threat_intel"}


async def lookup_domain(domain: str) -> dict:
    return {
        "ok": True,
        "ioc_type": "domain",
        "value": domain,
        "reputation": "unknown",
        "score": 0,
        "evidence_type": "threat_intel",
    }


async def lookup_hash(hash_value: str) -> dict:
    return {
        "ok": True,
        "ioc_type": "hash",
        "value": hash_value,
        "reputation": "unknown",
        "score": 0,
        "evidence_type": "threat_intel",
    }


async def search_security_knowledge_tool(query: str, doc_type: Optional[str] = None) -> dict:
    hits = await search_security_knowledge(query, top_k=5, doc_type=doc_type)
    return {
        "ok": True,
        "results": [h.to_dict() for h in hits],
        "evidence_type": "knowledge_base",
    }


async def get_mitre_technique_tool(technique_id: str) -> dict:
    hit = await get_mitre_technique(technique_id)
    if not hit:
        return {"ok": False, "error": f"Technique {technique_id} not found"}
    return {"ok": True, **hit.to_dict()}


async def build_timeline_tool(hits: list[dict]) -> dict:
    events = build_timeline(hits)
    summary = summarize_timeline(events)
    return {
        "ok": True,
        "timeline": [e.to_dict() for e in events[:100]],
        "summary": summary,
        "evidence_type": "siem",
    }


async def generate_report_tool(
    investigation_id: str,
    nl_query: str,
    hits: list[dict],
    patterns: list,
    mitre: list,
    iocs: list,
    explanation: str,
    ir: dict | None = None,
    dsl: dict | None = None,
    timeline: list | None = None,
    analyst_name: str = "Agent",
) -> dict:
    report = await build_report(
        investigation_id=investigation_id,
        nl_query=nl_query,
        generated_query=ir or {},
        elasticsearch_query=dsl or {},
        hits=hits,
        result_count=len(hits),
        iocs=iocs,
        patterns=patterns,
        mitre=mitre,
        timeline=timeline or [],
        explanation=explanation,
        analyst_name=analyst_name,
    )
    return {"ok": True, "report": report, "evidence_type": "report"}


ALLOWED_TOOLS = {
    "search_logs", "get_event", "get_related_events",
    "search_threat_intelligence", "lookup_ip", "lookup_domain", "lookup_hash",
    "search_security_knowledge", "get_mitre_technique",
    "build_timeline", "generate_report",
}


async def execute_tool(
    tool_name: str,
    arguments: dict,
    context: dict,
) -> tuple[dict, ToolCallRecord]:
    """Execute a whitelisted tool with audit logging."""
    if tool_name not in ALLOWED_TOOLS:
        record = ToolCallRecord(
            tool_name=tool_name,
            arguments=arguments,
            result_summary=f"Blocked: tool not in allowlist",
            status=AgentStepStatus.failed,
        )
        return {"ok": False, "error": "Tool not allowed"}, record

    start = time.perf_counter()
    try:
        result = await _dispatch_tool(tool_name, arguments, context)
        elapsed = (time.perf_counter() - start) * 1000
        record = ToolCallRecord(
            tool_name=tool_name,
            arguments=arguments,
            result_summary=_summarize_result(result),
            status=AgentStepStatus.completed,
            duration_ms=round(elapsed, 2),
        )
        logger.info("agent_tool_executed", tool=tool_name, duration_ms=record.duration_ms)
        return result, record
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        record = ToolCallRecord(
            tool_name=tool_name,
            arguments=arguments,
            result_summary=str(e),
            status=AgentStepStatus.failed,
            duration_ms=round(elapsed, 2),
        )
        logger.error("agent_tool_failed", tool=tool_name, error=str(e))
        return {"ok": False, "error": str(e)}, record


async def _dispatch_tool(tool_name: str, arguments: dict, context: dict) -> dict:
    hits = context.get("hits", [])

    if tool_name == "search_logs":
        entities = ExtractedEntities(**arguments.get("entities", {}))
        return await search_logs(entities)

    if tool_name == "get_event":
        event = await get_event(arguments["event_id"], hits)
        return {"ok": event is not None, "event": event}

    if tool_name == "get_related_events":
        related = await get_related_events(arguments["source_ip"], hits)
        return {"ok": True, "events": related, "count": len(related)}

    if tool_name == "search_threat_intelligence":
        return await search_threat_intelligence(arguments["ioc_type"], arguments["value"])

    if tool_name == "lookup_ip":
        return await lookup_ip(arguments["ip"])

    if tool_name == "lookup_domain":
        return await lookup_domain(arguments["domain"])

    if tool_name == "lookup_hash":
        return await lookup_hash(arguments["hash"])

    if tool_name == "search_security_knowledge":
        return await search_security_knowledge_tool(
            arguments["query"], arguments.get("doc_type")
        )

    if tool_name == "get_mitre_technique":
        return await get_mitre_technique_tool(arguments["technique_id"])

    if tool_name == "build_timeline":
        return await build_timeline_tool(hits)

    if tool_name == "generate_report":
        return await generate_report_tool(
            investigation_id=context.get("investigation_id", str(uuid.uuid4())),
            nl_query=context.get("nl_query", ""),
            hits=hits,
            patterns=context.get("patterns", []),
            mitre=context.get("mitre", []),
            iocs=context.get("iocs", []),
            explanation=context.get("explanation", ""),
            ir=context.get("ir"),
            dsl=context.get("dsl"),
            timeline=context.get("timeline_events"),
            analyst_name=arguments.get("analyst_name", "Agent"),
        )

    return {"ok": False, "error": "Unknown tool"}


def _summarize_result(result: dict) -> str:
    if not result.get("ok", True):
        return result.get("error", "failed")
    if "result_count" in result:
        return f"{result['result_count']} SIEM hits"
    if "results" in result:
        return f"{len(result['results'])} knowledge hits"
    if "count" in result:
        return f"{result['count']} related events"
    return "ok"
