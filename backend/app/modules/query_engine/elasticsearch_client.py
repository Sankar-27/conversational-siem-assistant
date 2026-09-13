"""
Elasticsearch Client — abstract interface supporting Mock, ES, and Wazuh modes.

Mode selection: SIEM_MODE env var (mock | elasticsearch | wazuh)
"""
from __future__ import annotations
import json
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Optional
from app.core.config import settings
from app.core.logging import logger


class SIEMClient(ABC):
    @abstractmethod
    async def search(self, dsl: dict, index: str = "siem-logs") -> dict:
        """Execute a search query and return the raw response."""
        ...

    @abstractmethod
    async def health(self) -> dict:
        ...


class MockSIEMClient(SIEMClient):
    """
    Queries the local JSON mock dataset.
    Supports basic filters: source.ip, event.action, user.name, http.response.status_code,
    url.original, @timestamp range.
    """

    def __init__(self):
        # Look in data/mock_logs/ relative to project root or current working dir
        candidates = [
            Path(__file__).resolve().parent.parent.parent.parent.parent / "data" / "mock_logs" / "mock_logs.json",
            Path.cwd() / "data" / "mock_logs" / "mock_logs.json",
            Path.cwd().parent / "data" / "mock_logs" / "mock_logs.json",
            Path("data/mock_logs/mock_logs.json"),
        ]
        self._logs: list[dict] = []
        for p in candidates:
            if p.exists():
                try:
                    with open(p, encoding="utf-8") as f:
                        self._logs = json.load(f)
                    break
                except Exception:
                    pass
        if not self._logs:
            logger.warning("mock_logs_not_found")


    async def search(self, dsl: dict, index: str = "siem-logs") -> dict:
        logs = list(self._logs)

        # Apply filters from the bool query
        bool_q = dsl.get("query", {}).get("bool", {})
        all_clauses = []
        for clause_type in ("must", "filter", "should"):
            clauses = bool_q.get(clause_type, [])
            if isinstance(clauses, dict):
                clauses = [clauses]
            all_clauses.extend(clauses)

        for clause in all_clauses:
            logs = self._apply_clause(logs, clause)

        # Sort by @timestamp descending
        logs.sort(key=lambda x: x.get("@timestamp", ""), reverse=True)

        # Apply size limit
        size = dsl.get("size", 100)
        limited = logs[:size]

        # Wrap in ES-style response
        hits = [
            {"_id": log.get("_id", str(uuid.uuid4())), "_source": log, "_index": index}
            for log in limited
        ]
        return {
            "hits": {"total": {"value": len(logs)}, "hits": hits},
            "took": 5,
            "_shards": {"total": 1, "successful": 1, "failed": 0},
        }

    def _apply_clause(self, logs: list[dict], clause: dict) -> list[dict]:
        """Apply a single ES clause as a Python filter."""
        if "term" in clause:
            for field, value in clause["term"].items():
                logs = [l for l in logs if self._get_nested(l, field) == value]
        elif "terms" in clause:
            for field, values in clause["terms"].items():
                logs = [l for l in logs if self._get_nested(l, field) in values]
        elif "wildcard" in clause:
            for field, pattern in clause["wildcard"].items():
                pattern_clean = pattern.replace("*", "").lower()
                logs = [l for l in logs if pattern_clean in str(self._get_nested(l, field) or "").lower()]
        elif "range" in clause:
            for field, bounds in clause["range"].items():
                logs = self._apply_range(logs, field, bounds)
        return logs

    def _apply_range(self, logs: list[dict], field: str, bounds: dict) -> list[dict]:
        """Apply time range filter."""
        if field != "@timestamp" or not logs:
            return logs

        # In mock dataset mode, reference time is max timestamp in logs if available
        log_timestamps = []
        for l in logs:
            try:
                log_timestamps.append(datetime.fromisoformat(l["@timestamp"].replace("Z", "+00:00")))
            except (ValueError, KeyError):
                pass
        
        ref_time = max(log_timestamps) if log_timestamps else datetime.now(timezone.utc)

        def parse_time(expr: str) -> datetime:
            if expr == "now":
                return ref_time + timedelta(hours=1)
            if expr.startswith("now-"):
                delta_str = expr[4:].rstrip("/d")
                if delta_str.endswith("h"):
                    return ref_time - timedelta(hours=int(delta_str[:-1]))
                elif delta_str.endswith("d"):
                    return ref_time - timedelta(days=int(delta_str[:-1]))
                elif delta_str.endswith("w"):
                    return ref_time - timedelta(weeks=int(delta_str[:-1]))
            # Parse as ISO
            try:
                return datetime.fromisoformat(expr.replace("Z", "+00:00"))
            except ValueError:
                return ref_time - timedelta(days=7)

        gte = parse_time(bounds.get("gte", "now-7d"))
        lte = parse_time(bounds.get("lte", "now"))

        result = []
        for log in logs:
            ts_str = log.get("@timestamp", "")
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                if gte <= ts <= lte:
                    result.append(log)
            except (ValueError, AttributeError):
                pass
        return result if result else logs


    def _get_nested(self, doc: dict, dotted_field: str) -> Any:
        """Get a nested field value using dot notation."""
        parts = dotted_field.split(".")
        current = doc
        for part in parts:
            if not isinstance(current, dict):
                return None
            current = current.get(part)
        return current

    async def health(self) -> dict:
        return {"status": "green", "mode": "mock", "total_logs": len(self._logs)}


class ElasticsearchSIEMClient(SIEMClient):
    """Real Elasticsearch client."""

    def __init__(self):
        from elasticsearch import AsyncElasticsearch
        kwargs: dict = {"hosts": [settings.ELASTICSEARCH_URL]}
        if settings.ELASTICSEARCH_USERNAME and settings.ELASTICSEARCH_PASSWORD:
            kwargs["http_auth"] = (settings.ELASTICSEARCH_USERNAME, settings.ELASTICSEARCH_PASSWORD)
        self._es = AsyncElasticsearch(**kwargs)

    async def search(self, dsl: dict, index: str = "siem-logs") -> dict:
        response = await self._es.search(index=index, body=dsl)
        return response.body

    async def health(self) -> dict:
        response = await self._es.cluster.health()
        return response.body


def get_siem_client() -> SIEMClient:
    """Factory: returns the configured SIEM client."""
    mode = settings.SIEM_MODE.lower()
    if mode == "elasticsearch":
        return ElasticsearchSIEMClient()
    else:
        return MockSIEMClient()


# Singleton
_siem_client: SIEMClient | None = None


def get_siem() -> SIEMClient:
    global _siem_client
    if _siem_client is None:
        _siem_client = get_siem_client()
    return _siem_client
