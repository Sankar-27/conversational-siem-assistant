"""
Ambiguity Resolver — detects under-specified analyst queries and generates clarifications.
"""
from __future__ import annotations

import re
from typing import Optional

from app.modules.conversational.entities import ExtractedEntities, IntentResult

VAGUE_PATTERNS = [
    r"\bsuspicious activity\b",
    r"\bshow me everything\b",
    r"\bwhat happened\b",
    r"\bany attacks\b",
    r"\bfind anomalies\b",
    r"\blook into\b(?!\s+\d)",
    r"\binvestigate\b(?!\s+(?:failed|login|sql|scan|port|path|from|user|ip))",
]

SPECIFIC_SIGNALS = [
    r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
    r"\bfailed login\b",
    r"\bbrute force\b",
    r"\bsql injection\b",
    r"\bport scan\b",
    r"\bpath traversal\b",
    r"\busername\b",
    r"\blast \d+ (?:hour|day|week)s?\b",
    r"\byesterday\b",
    r"\btoday\b",
]


def is_under_specified(query: str, entities: ExtractedEntities) -> bool:
    """Heuristic: query lacks concrete filters for SIEM search."""
    q = query.strip().lower()
    if not q:
        return True

    has_entity = any(
        getattr(entities, f) is not None
        for f in entities.model_fields
        if f != "time_range"
    )
    has_time_only = entities.time_range and not has_entity

    if has_entity and not has_time_only:
        return False

    for pat in SPECIFIC_SIGNALS:
        if re.search(pat, q, re.I):
            return False

    for pat in VAGUE_PATTERNS:
        if re.search(pat, q, re.I):
            return True

    # Very short queries without entities are ambiguous
    if len(q.split()) <= 4 and not has_entity:
        return True

    return False


def build_clarification(query: str, entities: ExtractedEntities) -> str:
    """Generate a targeted clarification question."""
    q = query.lower()
    if "suspicious" in q or "anomal" in q:
        return (
            "Your request is broad. Which scope should I investigate? "
            "For example: a specific source IP, failed logins, web attacks (SQLi/path traversal), "
            "or network scanning — and what time range?"
        )
    if "report" in q:
        return "Which investigation should I generate a report for? Please run a search first or specify an investigation ID."
    if "timeline" in q:
        return "Which events should I build a timeline for? Provide a source IP, username, or attack type and time range."
    if entities.time_range and not any(
        getattr(entities, f) for f in ("source_ip", "username", "event_action", "attack_type")
    ):
        return (
            "I have a time range but need a filter. Which source IP, username, or event type "
            "(e.g. failed_login, web_attack, network_scan) should I search?"
        )
    return (
        "I need more detail to search the SIEM safely. Please specify at least one of: "
        "source IP, username, event type, or attack category, plus a time range."
    )


def resolve_ambiguity(intent: IntentResult, query: str) -> IntentResult:
    """
    Augment LLM intent result with rule-based ambiguity detection.
    LLM ambiguity takes precedence; rules catch cases the model misses.
    """
    if intent.ambiguous and intent.clarification_needed:
        return intent

    if intent.confidence < 0.5:
        return intent.model_copy(
            update={
                "ambiguous": True,
                "clarification_needed": intent.clarification_needed
                or build_clarification(query, intent.entities),
            }
        )

    if is_under_specified(query, intent.entities):
        return intent.model_copy(
            update={
                "ambiguous": True,
                "clarification_needed": build_clarification(query, intent.entities),
                "confidence": min(intent.confidence, 0.4),
            }
        )

    return intent
