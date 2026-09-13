"""
Advanced Threat Analysis — attack chain reconstruction & severity scoring (Phase 5).
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Optional

from app.modules.threat_analysis.event_correlator import AttackPattern


PHASE_ORDER = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Exfiltration",
    "Impact",
]

PATTERN_TO_PHASE = {
    "scanner_activity": "Reconnaissance",
    "port_scan": "Discovery",
    "brute_force": "Credential Access",
    "credential_stuffing": "Credential Access",
    "sql_injection": "Initial Access",
    "path_traversal": "Discovery",
    "dos_attack": "Impact",
    "unauthorized_access": "Initial Access",
    "data_exfiltration": "Exfiltration",
}

SEVERITY_WEIGHTS = {
    "dos_attack": 9,
    "data_exfiltration": 9,
    "sql_injection": 8,
    "unauthorized_access": 8,
    "brute_force": 7,
    "credential_stuffing": 7,
    "port_scan": 5,
    "scanner_activity": 4,
    "path_traversal": 6,
}


def reconstruct_attack_chain(
    patterns: list[AttackPattern],
    source_ip: Optional[str] = None,
) -> dict:
    """Build evidence-backed attack chain for a source IP."""
    filtered = patterns
    if source_ip:
        filtered = [p for p in patterns if p.source_ip == source_ip or p.source_ip is None]

    chain_steps = []
    seen_phases: set[str] = set()

    for pattern in sorted(filtered, key=lambda p: p.first_seen or ""):
        phase = PATTERN_TO_PHASE.get(pattern.pattern_type, "Unknown")
        if phase in seen_phases and pattern.pattern_type in [s["pattern"] for s in chain_steps]:
            continue
        seen_phases.add(phase)
        chain_steps.append({
            "phase": phase,
            "pattern": pattern.pattern_type,
            "source_ip": pattern.source_ip,
            "evidence_count": pattern.evidence_count,
            "confidence": pattern.confidence,
            "first_seen": pattern.first_seen,
            "last_seen": pattern.last_seen,
            "details": pattern.details,
        })

    chain_steps.sort(key=lambda s: PHASE_ORDER.index(s["phase"]) if s["phase"] in PHASE_ORDER else 99)

    return {
        "source_ip": source_ip,
        "chain": chain_steps,
        "phase_sequence": [s["phase"] for s in chain_steps],
        "evidence_backed": len(chain_steps) > 0,
    }


def score_incident_severity(patterns: list[AttackPattern]) -> dict:
    """Compute incident severity score 0-100 from detected patterns."""
    if not patterns:
        return {"score": 0, "level": "info", "factors": []}

    factors = []
    max_score = 0
    for p in patterns:
        weight = SEVERITY_WEIGHTS.get(p.pattern_type, 3)
        factor_score = min(100, weight * 10 + min(p.evidence_count, 50))
        max_score = max(max_score, factor_score)
        factors.append({
            "pattern": p.pattern_type,
            "weight": weight,
            "evidence_count": p.evidence_count,
            "contribution": factor_score,
        })

    level = "critical" if max_score >= 80 else "high" if max_score >= 60 else "medium" if max_score >= 40 else "low"
    return {"score": max_score, "level": level, "factors": factors}


def build_entity_relationships(hits: list[dict]) -> dict:
    """Build IP/user/entity relationship graph from SIEM evidence."""
    ip_users: dict[str, set] = defaultdict(set)
    user_ips: dict[str, set] = defaultdict(set)
    ip_events: dict[str, int] = defaultdict(int)

    for hit in hits:
        src = hit.get("_source", hit)
        ip = (src.get("source") or {}).get("ip")
        user = (src.get("user") or {}).get("name")
        if ip:
            ip_events[ip] += 1
        if ip and user:
            ip_users[ip].add(user)
            user_ips[user].add(ip)

    nodes = []
    edges = []
    for ip, users in ip_users.items():
        nodes.append({"id": ip, "type": "ip", "event_count": ip_events[ip]})
        for user in users:
            edges.append({"source": ip, "target": user, "relation": "authenticated_as"})

    return {
        "nodes": nodes,
        "edges": edges,
        "stats": {"unique_ips": len(ip_events), "unique_users": len(user_ips)},
    }
