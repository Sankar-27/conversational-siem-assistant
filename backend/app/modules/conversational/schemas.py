"""Shared conversational Pydantic models."""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class TimeRange(BaseModel):
    from_: str = Field(alias="from", default="now-24h")
    to: str = "now"


class ExtractedEntities(BaseModel):
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    username: Optional[str] = None
    event_type: Optional[str] = None
    event_action: Optional[str] = None
    http_status: Optional[str] = None
    url_path: Optional[str] = None
    time_range: Optional[dict] = None
    protocol: Optional[str] = None
    hostname: Optional[str] = None
    hash_value: Optional[str] = None
    attack_type: Optional[str] = None


class IntentResult(BaseModel):
    intent: str
    entities: ExtractedEntities
    is_followup: bool = False
    ambiguous: bool = False
    clarification_needed: Optional[str] = None
    confidence: float = 1.0
