"""Investigation agent state schema (Phase 3)."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class AgentStepStatus(str, Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    skipped = "skipped"
    awaiting_approval = "awaiting_approval"


class ToolCallRecord(BaseModel):
    tool_name: str
    arguments: dict = Field(default_factory=dict)
    result_summary: str = ""
    status: AgentStepStatus = AgentStepStatus.completed
    duration_ms: float = 0.0
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class InvestigationAgentState(BaseModel):
    investigation_id: str
    conversation_id: str
    nl_query: str
    goal: str = ""
    plan: list[str] = Field(default_factory=list)
    current_step: int = 0
    max_iterations: int = 8
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    siem_evidence: list[dict] = Field(default_factory=list)
    knowledge_evidence: list[dict] = Field(default_factory=list)
    iocs: list[dict] = Field(default_factory=list)
    patterns: list[dict] = Field(default_factory=list)
    mitre: list[dict] = Field(default_factory=list)
    timeline: list[dict] = Field(default_factory=list)
    conclusion: str = ""
    status: str = "running"
    pending_approval: Optional[dict] = None
    metadata: dict = Field(default_factory=dict)
