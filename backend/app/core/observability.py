"""
Observability Module — metrics tracking for LLM calls, MCP tool invocations, RAG performance, and audit logging.
Provides optional integration hook for LangSmith / OpenTelemetry tracing platforms.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.core.logging import logger


@dataclass
class ToolExecutionMetric:
    tool_name: str
    duration_ms: float
    status: str
    error: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class InvestigationMetric:
    investigation_id: str
    conversation_id: str
    nl_query: str
    status: str
    total_duration_ms: float
    mcp_tool_calls: List[ToolExecutionMetric] = field(default_factory=list)
    siem_hits_count: int = 0
    iocs_count: int = 0
    mitre_count: int = 0
    rag_hits_count: int = 0
    estimated_tokens: int = 0
    error: Optional[str] = None


class MetricsCollector:
    """In-memory metrics collector for SOC operational monitoring."""

    def __init__(self):
        self._investigations: List[InvestigationMetric] = []
        self._tool_call_totals: Dict[str, int] = {}
        self._tool_latency_sum: Dict[str, float] = {}

    def record_tool_execution(self, tool_name: str, duration_ms: float, status: str, error: Optional[str] = None):
        self._tool_call_totals[tool_name] = self._tool_call_totals.get(tool_name, 0) + 1
        self._tool_latency_sum[tool_name] = self._tool_latency_sum.get(tool_name, 0) + duration_ms
        logger.info("metric_mcp_tool", tool=tool_name, duration_ms=duration_ms, status=status, error=error)

        # Optional LangSmith tracing hook
        if os.getenv("LANGSMITH_TRACING", "").lower() == "true" and os.getenv("LANGSMITH_API_KEY"):
            self._send_to_langsmith("tool_call", {"tool": tool_name, "duration_ms": duration_ms, "status": status})

    def record_investigation(self, metric: InvestigationMetric):
        self._investigations.append(metric)
        logger.info(
            "metric_investigation_summary",
            id=metric.investigation_id,
            duration_ms=metric.total_duration_ms,
            status=metric.status,
            siem_hits=metric.siem_hits_count,
            tool_calls_count=len(metric.mcp_tool_calls),
        )

    def get_summary(self) -> Dict[str, Any]:
        total_inv = len(self._investigations)
        completed = sum(1 for i in self._investigations if i.status == "completed")
        failed = sum(1 for i in self._investigations if i.status in ("failed", "timeout", "errored"))

        tool_averages = {
            t: round(self._tool_latency_sum[t] / max(self._tool_call_totals[t], 1), 2)
            for t in self._tool_call_totals
        }

        return {
            "total_investigations": total_inv,
            "completed_investigations": completed,
            "failed_investigations": failed,
            "success_rate": round((completed / max(total_inv, 1)) * 100, 1),
            "tool_call_counts": self._tool_call_totals,
            "tool_average_latency_ms": tool_averages,
        }

    def _send_to_langsmith(self, name: str, payload: dict):
        # Placeholder for optional non-blocking LangSmith webhook dispatch
        pass


# Global singleton instance
_collector: Optional[MetricsCollector] = None


def get_metrics_collector() -> MetricsCollector:
    global _collector
    if _collector is None:
        _collector = MetricsCollector()
    return _collector
