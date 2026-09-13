"""
Security middleware — rate limiting, input validation, audit logging (Phase 7).
"""
from __future__ import annotations

import re
import time
from collections import defaultdict
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings
from app.core.logging import logger

# Simple in-memory rate limiter (replace with Redis in Phase 9)
_rate_buckets: dict[str, list[float]] = defaultdict(list)

PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"disregard\s+(the\s+)?system\s+prompt",
    r"you\s+are\s+now\s+a",
    r"execute\s+tool\s*:",
    r"<\s*script",
]


def check_prompt_injection(text: str) -> list[str]:
    """Detect potential prompt injection in user-supplied text."""
    warnings = []
    for pat in PROMPT_INJECTION_PATTERNS:
        if re.search(pat, text, re.I):
            warnings.append(f"Matched injection pattern: {pat}")
    return warnings


def validate_tool_arguments(tool_name: str, arguments: dict) -> tuple[bool, list[str]]:
    """Independent validation of agent tool arguments."""
    errors = []
    if tool_name == "search_logs":
        entities = arguments.get("entities", {})
        if not isinstance(entities, dict):
            errors.append("entities must be a dict")
    if tool_name in ("lookup_ip", "get_related_events"):
        if not arguments.get("ip") and not arguments.get("source_ip"):
            errors.append("IP address required")
    return len(errors) == 0, errors


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, limit: int = 60, window_seconds: int = 60):
        super().__init__(app)
        self.limit = limit
        self.window = window_seconds

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.url.path.endswith(("/investigate", "/agent/investigate", "/investigate/chat")):
            client = request.client.host if request.client else "unknown"
            key = f"{client}:{request.url.path}"
            now = time.time()
            bucket = _rate_buckets[key]
            bucket[:] = [t for t in bucket if now - t < self.window]
            if len(bucket) >= self.limit:
                logger.warning("rate_limit_exceeded", client=client, path=request.url.path)
                return Response(content='{"detail":"Rate limit exceeded"}', status_code=429,
                                media_type="application/json")
            bucket.append(now)

        response = await call_next(request)
        return response


class AuditLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start = time.perf_counter()
        response = await call_next(request)
        elapsed = (time.perf_counter() - start) * 1000
        if "/api/" in request.url.path:
            logger.info(
                "audit",
                method=request.method,
                path=request.url.path,
                status=response.status_code,
                duration_ms=round(elapsed, 2),
            )
        return response
