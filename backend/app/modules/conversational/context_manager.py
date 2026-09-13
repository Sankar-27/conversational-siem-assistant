"""
Context Manager — maintains per-conversation investigation state.

Responsibilities:
- Store and retrieve conversation turns
- Merge new entities with previous investigation context (for follow-up queries)
- Resolve pronouns and references to previous findings
"""
from __future__ import annotations
import re
from typing import Optional
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.investigation import Conversation
from app.modules.conversational.entities import ExtractedEntities
from app.modules.conversational.entity_normalizer import is_external_ip, normalize_entities


class ConversationContext:
    """Holds the current state of a multi-turn investigation session."""

    def __init__(self, conversation_id: str):
        self.conversation_id = conversation_id
        self.turns: list[dict] = []
        self.active_entities: ExtractedEntities = ExtractedEntities()  # Accumulated from all turns
        self.last_result_count: Optional[int] = None
        self.last_investigation_id: Optional[str] = None

    def add_turn(self, role: str, content: str) -> None:
        self.turns.append({"role": role, "content": content})
        # Keep last 20 turns in memory
        if len(self.turns) > 20:
            self.turns = self.turns[-20:]

    def get_history(self, last_n: int = 5) -> list[dict]:
        return self.turns[-last_n:]

    def resolve_references(self, query: str, entities: ExtractedEntities) -> ExtractedEntities:
        """Resolve pronouns and contextual phrases using accumulated state."""
        q = query.lower()
        resolved = entities.model_copy()

        if re.search(r"\b(that ip|same ip|this ip|the ip)\b", q) and not resolved.source_ip:
            resolved.source_ip = self.active_entities.source_ip
        if re.search(r"\b(that user|same user|this user|the user)\b", q) and not resolved.username:
            resolved.username = self.active_entities.username
        if re.search(r"\b(same time|same period|that timeframe)\b", q) and not resolved.time_range:
            resolved.time_range = self.active_entities.time_range
        if re.search(r"\bexternal ip(s)? only\b", q):
            if resolved.source_ip and not is_external_ip(resolved.source_ip):
                resolved.source_ip = self.active_entities.source_ip
            if resolved.source_ip and is_external_ip(resolved.source_ip):
                pass
            elif self.active_entities.source_ip and is_external_ip(self.active_entities.source_ip):
                resolved.source_ip = self.active_entities.source_ip
        if re.search(r"\b(vpn|remote access)\b", q) and not resolved.url_path:
            resolved.url_path = "/vpn"

        return normalize_entities(resolved, query)

    def merge_entities(
        self,
        new_entities: ExtractedEntities,
        is_followup: bool,
        query: str = "",
    ) -> ExtractedEntities:
        """
        Merge new entities with the accumulated context.
        For follow-up queries, preserve previous entities unless overridden.
        """
        new_entities = self.resolve_references(query, new_entities)

        if not is_followup and not self._looks_like_followup(query):
            self.active_entities = new_entities
            return new_entities

        merged = ExtractedEntities(
            source_ip=new_entities.source_ip or self.active_entities.source_ip,
            destination_ip=new_entities.destination_ip or self.active_entities.destination_ip,
            destination_port=new_entities.destination_port or self.active_entities.destination_port,
            username=new_entities.username or self.active_entities.username,
            event_type=new_entities.event_type or self.active_entities.event_type,
            event_action=new_entities.event_action or self.active_entities.event_action,
            http_status=new_entities.http_status or self.active_entities.http_status,
            url_path=new_entities.url_path or self.active_entities.url_path,
            time_range=new_entities.time_range or self.active_entities.time_range,
            protocol=new_entities.protocol or self.active_entities.protocol,
            hostname=new_entities.hostname or self.active_entities.hostname,
            hash_value=new_entities.hash_value or self.active_entities.hash_value,
            attack_type=new_entities.attack_type or self.active_entities.attack_type,
        )
        merged = normalize_entities(merged, query)
        self.active_entities = merged
        return merged

    @staticmethod
    def _looks_like_followup(query: str) -> bool:
        q = query.lower()
        followup_markers = (
            "only", "filter", "narrow", "refine", "also", "same", "that",
            "exclude", "just", "limit", "external", "vpn",
        )
        return any(m in q for m in followup_markers)


# In-memory store of active conversation contexts (keyed by conversation_id string)
# In production this could be backed by Redis
_contexts: dict[str, ConversationContext] = {}


def get_context(conversation_id: str) -> ConversationContext:
    """Get or create a ConversationContext for the given conversation ID."""
    if conversation_id not in _contexts:
        _contexts[conversation_id] = ConversationContext(conversation_id)
    return _contexts[conversation_id]


def clear_context(conversation_id: str) -> None:
    """Clear context for a conversation (e.g., when starting fresh)."""
    if conversation_id in _contexts:
        del _contexts[conversation_id]


async def load_context_from_db(conversation_id: str, db: AsyncSession) -> ConversationContext:
    """Load conversation history from PostgreSQL into the in-memory context."""
    context = get_context(conversation_id)
    result = await db.execute(
        select(Conversation).where(Conversation.id == UUID(conversation_id))
    )
    conv = result.scalar_one_or_none()
    if conv and conv.context_window:
        context.turns = conv.context_window
    return context


async def save_context_to_db(conversation_id: str, db: AsyncSession) -> None:
    """Persist the current in-memory context turns to PostgreSQL."""
    context = get_context(conversation_id)
    result = await db.execute(
        select(Conversation).where(Conversation.id == UUID(conversation_id))
    )
    conv = result.scalar_one_or_none()
    if conv:
        conv.context_window = context.turns[-20:]  # Persist last 20 turns
        await db.flush()
