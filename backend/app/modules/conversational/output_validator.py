"""
Structured Output Validator — validates LLM JSON with retry and rule-based fallback.
"""
from __future__ import annotations

import json
import re
from typing import Optional

from pydantic import ValidationError

from app.core.llm import get_llm
from app.core.logging import logger
from app.modules.conversational.schemas import ExtractedEntities, IntentResult
from app.modules.conversational.prompts import INTENT_SYSTEM_PROMPT
from app.modules.conversational.entity_normalizer import normalize_entities

VALID_INTENTS = {
    "investigate", "filter", "explain", "timeline", "report", "dashboard", "ambiguous"
}

MAX_LLM_RETRIES = 2


def _rule_based_extract(query: str) -> IntentResult:
    """Deterministic fallback when LLM output is invalid."""
    q = query.lower()
    ip_match = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", query)
    entities = ExtractedEntities(
        source_ip=ip_match.group(0) if ip_match else None,
        time_range={"from": "now-7d", "to": "now"},
    )

    if any(w in q for w in ("filter", "only", "narrow", "refine")):
        intent = "filter"
        is_followup = True
    elif "timeline" in q:
        intent = "timeline"
        is_followup = False
    elif "report" in q:
        intent = "report"
        is_followup = False
    elif "explain" in q:
        intent = "explain"
        is_followup = False
    else:
        intent = "investigate"
        is_followup = False

    if "failed" in q or "login" in q or "brute" in q:
        entities.event_action = "failed_login"
    elif "sql" in q or "injection" in q:
        entities.event_action = "web_attack"
        entities.attack_type = "sql_injection"
    elif "scan" in q or "port" in q:
        entities.event_action = "network_scan"
    elif "traversal" in q:
        entities.event_action = "web_attack"
        entities.attack_type = "path_traversal"

    user_match = re.search(r"(?:user(?:name)?|account)\s+([a-zA-Z0-9_\-\.]+)", query, re.I)
    if user_match:
        entities.username = user_match.group(1)

    entities = normalize_entities(entities, query)
    return IntentResult(
        intent=intent,
        entities=entities,
        is_followup=is_followup,
        ambiguous=False,
        confidence=0.55,
    )


def _parse_intent_payload(raw: dict, query: str) -> IntentResult:
    """Validate raw dict into IntentResult with normalization."""
    intent = raw.get("intent", "investigate")
    if intent not in VALID_INTENTS:
        intent = "investigate"

    entities_raw = raw.get("entities") or {}
    entities = ExtractedEntities(**entities_raw)
    entities = normalize_entities(entities, query)

    return IntentResult(
        intent=intent,
        entities=entities,
        is_followup=bool(raw.get("is_followup", False)),
        ambiguous=bool(raw.get("ambiguous", False)),
        clarification_needed=raw.get("clarification_needed"),
        confidence=float(raw.get("confidence", 1.0)),
    )


async def extract_intent_validated(
    query: str,
    conversation_history: list[dict] | None = None,
) -> IntentResult:
    """
    Extract intent with structured validation, retries, and rule-based fallback.
    """
    llm = get_llm()
    history_context = ""
    if conversation_history:
        history_context = "\n\nConversation history (for context resolution):\n"
        for turn in conversation_history[-5:]:
            history_context += f"  [{turn.get('role', 'user')}]: {turn.get('content', '')}\n"

    user_message = f"Analyst query: {query}{history_context}"
    last_error: Optional[str] = None

    for attempt in range(MAX_LLM_RETRIES + 1):
        try:
            raw = await llm.complete_json(INTENT_SYSTEM_PROMPT, user_message)
            result = _parse_intent_payload(raw, query)
            IntentResult.model_validate(result.model_dump())
            logger.info("intent_extraction_ok", attempt=attempt, intent=result.intent)
            return result
        except (json.JSONDecodeError, ValidationError, TypeError, ValueError) as e:
            last_error = str(e)
            logger.warning("intent_validation_failed", attempt=attempt, error=last_error)
            user_message = (
                f"{user_message}\n\nPrevious response was invalid ({last_error}). "
                "Respond ONLY with valid JSON matching the required schema."
            )

    logger.warning("intent_fallback_rule_based", error=last_error)
    fallback = _rule_based_extract(query)
    fallback.ambiguous = True
    fallback.clarification_needed = (
        fallback.clarification_needed
        or "I had trouble parsing your request. I applied basic filters — please confirm or refine your query."
    )
    fallback.confidence = 0.3
    return fallback
