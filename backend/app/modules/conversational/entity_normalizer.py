"""
Entity Normalizer — canonicalizes security entities extracted from NL queries.

Handles IP, domain, hash, username, and time-range normalization before query generation.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

import validators
from dateutil import parser as date_parser

from app.modules.conversational.entities import ExtractedEntities

# Private/reserved ranges — used for "external IP" follow-up filters
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]

IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?$")
MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")

RELATIVE_TIME_MAP = {
    "last hour": {"from": "now-1h", "to": "now"},
    "past hour": {"from": "now-1h", "to": "now"},
    "last 24 hours": {"from": "now-24h", "to": "now"},
    "past 24 hours": {"from": "now-24h", "to": "now"},
    "last day": {"from": "now-1d", "to": "now"},
    "today": {"from": "now/d", "to": "now"},
    "yesterday": {"from": "now-1d/d", "to": "now/d"},
    "last week": {"from": "now-7d", "to": "now"},
    "last 7 days": {"from": "now-7d", "to": "now"},
    "last 30 days": {"from": "now-30d", "to": "now"},
    "last month": {"from": "now-30d", "to": "now"},
}


def normalize_ip(value: Optional[str]) -> Optional[str]:
    """Normalize IPv4/IPv6; strip CIDR to host address for SIEM term queries."""
    if not value:
        return None
    raw = value.strip().lower()
    try:
        if "/" in raw:
            network = ipaddress.ip_network(raw, strict=False)
            if network.num_addresses == 1 or (hasattr(network, "prefixlen") and network.prefixlen == 32):
                return str(network.network_address)
            return str(network.network_address)
        addr = ipaddress.ip_address(raw)
        return str(addr)
    except ValueError:
        return None


def is_external_ip(value: Optional[str]) -> bool:
    """Return True if IP is routable and not in private/reserved space."""
    normalized = normalize_ip(value)
    if not normalized:
        return False
    try:
        addr = ipaddress.ip_address(normalized)
        if not addr.is_global:
            return False
        for net in PRIVATE_NETWORKS:
            if addr in net:
                return False
        return True
    except ValueError:
        return False


def normalize_domain(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    domain = value.strip().lower().rstrip(".")
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = domain.split("://", 1)[1].split("/", 1)[0]
    if domain.startswith("www."):
        domain = domain[4:]
    if validators.domain(domain):
        return domain
    return None


def normalize_hash(value: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """Return (normalized_hash, hash_type) where hash_type is md5|sha1|sha256."""
    if not value:
        return None, None
    h = value.strip().lower()
    if MD5_RE.match(h):
        return h, "md5"
    if SHA1_RE.match(h):
        return h, "sha1"
    if SHA256_RE.match(h):
        return h, "sha256"
    return None, None


def normalize_username(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    username = value.strip()
    if username.startswith("@") or username.startswith("\\"):
        username = username[1:]
    if username.lower().startswith("domain\\"):
        username = username.split("\\", 1)[1]
    return username.lower() if username else None


def normalize_time_range(
    time_range: Optional[dict],
    query_text: Optional[str] = None,
) -> Optional[dict]:
    """
    Normalize time range to Elasticsearch date math expressions.
    Supports relative phrases and absolute ISO timestamps.
    """
    if time_range and isinstance(time_range, dict):
        tr = dict(time_range)
        if "from" in tr or "to" in tr:
            tr["from"] = _normalize_time_expr(tr.get("from"), is_start=True)
            tr["to"] = _normalize_time_expr(tr.get("to"), is_start=False)
            return tr

    if query_text:
        q = query_text.lower()
        for phrase, expr in RELATIVE_TIME_MAP.items():
            if phrase in q:
                return dict(expr)

    return time_range or {"from": "now-24h", "to": "now"}


def _normalize_time_expr(value: Optional[str], is_start: bool) -> str:
    if not value:
        return "now-24h" if is_start else "now"
    v = str(value).strip()
    if v.startswith("now"):
        return v
    try:
        dt = date_parser.parse(v)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except (ValueError, TypeError):
        return v


def normalize_entities(
    entities: ExtractedEntities,
    query_text: Optional[str] = None,
) -> ExtractedEntities:
    """Apply all normalizers to extracted entities."""
    hash_val, hash_type = normalize_hash(entities.hash_value)

    normalized = ExtractedEntities(
        source_ip=normalize_ip(entities.source_ip),
        destination_ip=normalize_ip(entities.destination_ip),
        destination_port=entities.destination_port,
        username=normalize_username(entities.username),
        event_type=(entities.event_type or "").strip().lower() or None,
        event_action=(entities.event_action or "").strip().lower() or None,
        http_status=entities.http_status,
        url_path=entities.url_path,
        time_range=normalize_time_range(entities.time_range, query_text),
        protocol=(entities.protocol or "").strip().lower() or None,
        hostname=normalize_domain(entities.hostname) or entities.hostname,
        hash_value=hash_val,
        attack_type=(entities.attack_type or "").strip().lower() or None,
    )

    # Map hash type to correct ECS field via attack_type hint for downstream IR builder
    if hash_type and not normalized.attack_type:
        normalized.attack_type = hash_type

    return normalized
