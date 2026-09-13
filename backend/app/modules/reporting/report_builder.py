"""
Report Builder — assembles investigation artifacts into a structured incident report.
"""
from __future__ import annotations
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from app.modules.threat_analysis.event_correlator import AttackPattern
from app.modules.mitre.attack_mapper import MITRETechniqueResult
from app.modules.mitre.timeline_builder import TimelineEvent, summarize_timeline
from app.modules.explainability.evidence_linker import get_recommendations, generate_executive_summary


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def build_report(
    investigation_id: str,
    nl_query: str,
    generated_query: dict,
    elasticsearch_query: dict,
    hits: list[dict],
    result_count: int,
    iocs: list[dict],
    patterns: list[AttackPattern],
    mitre: list[MITRETechniqueResult],
    timeline: list[TimelineEvent],
    explanation: str,
    analyst_name: str = "SOC Analyst",
) -> dict:
    """Assemble a complete structured incident report."""

    timeline_summary = summarize_timeline(timeline)
    recommendations = get_recommendations(patterns)

    # Build evidence table (up to 50 log entries)
    evidence_table = []
    for hit in hits[:50]:
        src = hit.get("_source", hit)
        evidence_table.append({
            "log_id": hit.get("_id", ""),
            "timestamp": src.get("@timestamp", ""),
            "source_ip": (src.get("source") or {}).get("ip", ""),
            "username": (src.get("user") or {}).get("name", ""),
            "event_action": (src.get("event") or {}).get("action", ""),
            "http_status": ((src.get("http") or {}).get("response") or {}).get("status_code", ""),
            "url": (src.get("url") or {}).get("original", ""),
            "severity": (src.get("event") or {}).get("severity", ""),
        })

    # Executive summary data
    exec_summary_data = {
        "nl_query": nl_query,
        "result_count": result_count,
        "patterns": [p.to_dict() for p in patterns],
        "mitre": [m.to_dict() for m in mitre],
        "ioc_count": len(iocs),
        "timeline_summary": timeline_summary,
        "investigation_id": investigation_id,
    }
    executive_summary = await generate_executive_summary(exec_summary_data)

    report = {
        "report_id": str(uuid.uuid4()),
        "investigation_id": investigation_id,
        "generated_at": _now_iso(),
        "analyst": analyst_name,

        # ── Executive Summary ───────────────────────────────────────────────
        "executive_summary": executive_summary,

        # ── Investigation Details ───────────────────────────────────────────
        "investigation": {
            "title": _generate_title(patterns, nl_query),
            "analyst_query": nl_query,
            "generated_query_ir": generated_query,
            "elasticsearch_dsl": elasticsearch_query,
            "total_events_matched": result_count,
            "events_analyzed": len(hits),
            "time_range": {
                "from": timeline[0].timestamp if timeline else None,
                "to": timeline[-1].timestamp if timeline else None,
            },
        },

        # ── Evidence Table ──────────────────────────────────────────────────
        "evidence": evidence_table,

        # ── IOC Section ─────────────────────────────────────────────────────
        "iocs": iocs,

        # ── Attack Analysis ─────────────────────────────────────────────────
        "attack_analysis": {
            "patterns": [p.to_dict() for p in patterns],
            "mitre_techniques": [m.to_dict() for m in mitre],
        },

        # ── Attack Timeline ─────────────────────────────────────────────────
        "timeline": {
            "summary": timeline_summary,
            "events": [e.to_dict() for e in timeline],
        },

        # ── AI Explanation ──────────────────────────────────────────────────
        "explanation": explanation,

        # ── Recommendations ─────────────────────────────────────────────────
        "recommendations": recommendations,
    }

    return report


def _generate_title(patterns: list[AttackPattern], nl_query: str) -> str:
    if not patterns:
        return f"Security Investigation: {nl_query[:80]}"
    primary = patterns[0].pattern_type.replace("_", " ").title()
    if patterns[0].source_ip:
        return f"{primary} Attack Investigation — Source: {patterns[0].source_ip}"
    return f"{primary} Activity — Security Incident Report"
