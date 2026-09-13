"""Tests for entity normalization (Phase 2.1)."""
import pytest

from app.modules.conversational.entity_normalizer import (
    normalize_ip,
    normalize_domain,
    normalize_hash,
    normalize_username,
    normalize_time_range,
    is_external_ip,
    normalize_entities,
)
from app.modules.conversational.ambiguity_resolver import is_under_specified, resolve_ambiguity
from app.modules.conversational.entities import ExtractedEntities, IntentResult


def test_normalize_ip_strips_cidr():
    assert normalize_ip("185.220.101.45/32") == "185.220.101.45"
    assert normalize_ip(" 185.220.101.45 ") == "185.220.101.45"


def test_normalize_ip_invalid():
    assert normalize_ip("999.999.999.999") is None


def test_is_external_ip():
    assert is_external_ip("185.220.101.45") is True
    assert is_external_ip("10.0.0.1") is False
    assert is_external_ip("127.0.0.1") is False


def test_normalize_domain():
    assert normalize_domain("HTTPS://Example.COM/path") == "example.com"
    assert normalize_domain("www.evil.com.") == "evil.com"


def test_normalize_hash():
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert normalize_hash(md5) == (md5, "md5")
    assert normalize_hash(sha256)[1] == "sha256"
    assert normalize_hash("not-a-hash") == (None, None)


def test_normalize_username():
    assert normalize_username("@Admin") == "admin"
    assert normalize_username("DOMAIN\\jsmith") == "jsmith"


def test_normalize_time_range_relative():
    tr = normalize_time_range(None, "show failed logins from last 24 hours")
    assert tr["from"] == "now-24h"
    assert tr["to"] == "now"


def test_normalize_entities_lowercase_actions():
    entities = ExtractedEntities(event_action="Failed_Login", username="Admin")
    normalized = normalize_entities(entities)
    assert normalized.event_action == "failed_login"
    assert normalized.username == "admin"


def test_ambiguity_under_specified():
    entities = ExtractedEntities()
    assert is_under_specified("show suspicious activity", entities) is True
    assert is_under_specified(
        "failed login from 185.220.101.45 yesterday",
        ExtractedEntities(source_ip="185.220.101.45"),
    ) is False


def test_resolve_ambiguity_marks_vague_query():
    intent = IntentResult(intent="investigate", entities=ExtractedEntities(), confidence=0.9)
    resolved = resolve_ambiguity(intent, "show suspicious activity")
    assert resolved.ambiguous is True
    assert resolved.clarification_needed
