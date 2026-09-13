import pytest
from app.modules.query_engine.schema_mapper import (
    resolve_field, resolve_event_action, is_allowed_field, FIELD_MAP
)

def test_resolve_field_aliases():
    assert resolve_field("source IP") == "source.ip"
    assert resolve_field("src_ip") == "source.ip"
    assert resolve_field("attacker ip") == "source.ip"
    assert resolve_field("username") == "user.name"
    assert resolve_field("destination port") == "destination.port"

def test_resolve_event_actions():
    assert resolve_event_action("failed login") == "failed_login"
    assert resolve_event_action("brute force") == "failed_login"
    assert resolve_event_action("port scan") == "network_scan"
    assert resolve_event_action("sql injection") == "web_attack"

def test_is_allowed_field_whitelist():
    assert is_allowed_field("source.ip") is True
    assert is_allowed_field("event.action") is True
    assert is_allowed_field("random_untrusted_field") is False
    assert is_allowed_field("password") is False
