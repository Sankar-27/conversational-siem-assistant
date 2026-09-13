"""
Intent & Entity Extractor.

Uses LLM to convert natural-language security queries into structured
intent + entity objects, then validates entities against the schema map.
Log data is NEVER passed into this module — only the user's query text.
"""
from __future__ import annotations

from app.modules.conversational.schemas import ExtractedEntities, IntentResult, TimeRange
from app.modules.conversational.entity_normalizer import normalize_entities
from app.modules.conversational.ambiguity_resolver import resolve_ambiguity
from app.modules.conversational.output_validator import extract_intent_validated
from app.modules.conversational.prompts import INTENT_SYSTEM_PROMPT


async def extract_intent(
    query: str,
    conversation_history: list[dict] | None = None,
) -> IntentResult:
    """Extract intent and entities from a natural language security query."""
    result = await extract_intent_validated(query, conversation_history)
    result = resolve_ambiguity(result, query)
    result.entities = normalize_entities(result.entities, query)
    return result
