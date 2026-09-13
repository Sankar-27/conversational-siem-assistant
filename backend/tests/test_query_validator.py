import pytest
from app.modules.query_engine.query_validator import validate_dsl

def test_validate_valid_dsl():
    valid_query = {
        "query": {
            "bool": {
                "filter": [
                    {"term": {"source.ip": "192.168.1.5"}},
                    {"term": {"event.action": "failed_login"}},
                ]
            }
        },
        "size": 50,
    }
    result = validate_dsl(valid_query)
    assert result.valid is True
    assert len(result.errors) == 0

def test_validate_blocks_forbidden_operations():
    destructive_query = {
        "query": {"match_all": {}},
        "script": "ctx._source.remove('secret')",
    }
    result = validate_dsl(destructive_query)
    assert result.valid is False
    assert any("forbidden" in err.lower() for err in result.errors)

def test_validate_blocks_unauthorized_fields():
    bad_field_query = {
        "query": {
            "bool": {
                "filter": [
                    {"term": {"sensitive_passwords": "admin"}},
                ]
            }
        }
    }
    result = validate_dsl(bad_field_query)
    assert result.valid is False
    assert any("whitelist" in err.lower() for err in result.errors)

def test_validate_size_limits():
    oversized = {
        "query": {"match_all": {}},
        "size": 50000,
    }
    result = validate_dsl(oversized)
    assert result.valid is False
    assert any("size" in err.lower() for err in result.errors)
