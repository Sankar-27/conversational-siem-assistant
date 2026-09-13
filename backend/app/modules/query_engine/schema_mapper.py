"""
Schema Mapper — canonical field dictionary.

This module is the SINGLE source of truth for Elasticsearch field names.
The LLM NEVER invents field names — it references this mapping.
Any field not in this mapping cannot be queried.
"""
from __future__ import annotations
from typing import Optional

# ── Canonical field map ────────────────────────────────────────────────────────
# Natural language alias → Elasticsearch ECS field
FIELD_MAP: dict[str, str] = {
    # Network / Source
    "source ip": "source.ip",
    "source_ip": "source.ip",
    "src ip": "source.ip",
    "src_ip": "source.ip",
    "attacker ip": "source.ip",
    "client ip": "source.ip",

    # Network / Destination
    "destination ip": "destination.ip",
    "dest ip": "destination.ip",
    "dst ip": "destination.ip",
    "server ip": "destination.ip",
    "destination port": "destination.port",
    "dest port": "destination.port",
    "port": "destination.port",

    # User
    "username": "user.name",
    "user": "user.name",
    "account": "user.name",

    # Event
    "event type": "event.category",
    "event action": "event.action",
    "event": "event.action",
    "action": "event.action",
    "failed login": "event.action",
    "successful login": "event.action",
    "failed authentication": "event.action",
    "authentication": "event.category",
    "severity": "event.severity",

    # HTTP
    "http method": "http.request.method",
    "method": "http.request.method",
    "status code": "http.response.status_code",
    "http status": "http.response.status_code",
    "response code": "http.response.status_code",
    "url": "url.original",
    "path": "url.original",
    "endpoint": "url.original",
    "user agent": "user_agent.original",

    # Timing
    "timestamp": "@timestamp",
    "time": "@timestamp",
    "date": "@timestamp",

    # File / Process
    "filename": "file.name",
    "hash": "file.hash.md5",
    "md5": "file.hash.md5",
    "sha256": "file.hash.sha256",

    # Network protocol
    "protocol": "network.protocol",
    "transport": "network.transport",

    # Source type
    "log source": "log.logger",
    "host": "host.name",
    "hostname": "host.name",
}

# ── Event action values ────────────────────────────────────────────────────────
EVENT_ACTION_MAP: dict[str, str] = {
    "failed login": "failed_login",
    "login failure": "failed_login",
    "failed authentication": "failed_login",
    "auth failure": "failed_login",
    "successful login": "successful_login",
    "login success": "successful_login",
    "authenticated": "successful_login",
    "brute force": "failed_login",
    "port scan": "network_scan",
    "sql injection": "web_attack",
    "path traversal": "web_attack",
    "xss": "web_attack",
    "web attack": "web_attack",
    "dos": "dos_attack",
    "ddos": "ddos_attack",
    "unauthorized access": "unauthorized_access",
    "file access": "file_access",
    "data exfiltration": "data_exfiltration",
}

# ── HTTP status code groups ────────────────────────────────────────────────────
HTTP_STATUS_GROUPS: dict[str, list[int]] = {
    "unauthorized": [401],
    "forbidden": [403],
    "not found": [404],
    "server error": [500, 502, 503, 504],
    "redirect": [301, 302, 303, 307, 308],
    "success": [200, 201, 202, 204],
    "client error": [400, 401, 402, 403, 404, 405, 408, 429],
}

# ── Supported index names ──────────────────────────────────────────────────────
SUPPORTED_INDICES: list[str] = [
    "siem-logs",
    "siem-logs-*",
    "wazuh-alerts-*",
    "filebeat-*",
]

# ── Allowed query fields (whitelist) ──────────────────────────────────────────
ALLOWED_QUERY_FIELDS: set[str] = {v for v in FIELD_MAP.values()} | {
    "@timestamp",
    "source.ip",
    "destination.ip",
    "destination.port",
    "user.name",
    "event.action",
    "event.category",
    "event.severity",
    "http.request.method",
    "http.response.status_code",
    "url.original",
    "user_agent.original",
    "file.name",
    "file.hash.md5",
    "file.hash.sha256",
    "network.protocol",
    "network.transport",
    "host.name",
    "log.logger",
}


def resolve_field(natural_term: str) -> Optional[str]:
    """Resolve a natural-language field name to its ES field path."""
    return FIELD_MAP.get(natural_term.lower().strip())


def resolve_event_action(natural_term: str) -> Optional[str]:
    """Resolve a natural-language event description to its canonical event.action value."""
    return EVENT_ACTION_MAP.get(natural_term.lower().strip())


def is_allowed_field(field_name: str) -> bool:
    """Return True if the field is in the whitelist."""
    return field_name in ALLOWED_QUERY_FIELDS


def get_http_status_codes(group_name: str) -> list[int]:
    """Return HTTP status codes for a named group (e.g. 'unauthorized')."""
    return HTTP_STATUS_GROUPS.get(group_name.lower(), [])
