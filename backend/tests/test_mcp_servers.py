"""Unit and integration tests for Model Context Protocol (MCP) servers and MCPClientManager."""
import pytest
from pathlib import Path

from app.core.mcp_client import get_mcp_client, MCPClientManager


@pytest.mark.asyncio
async def test_mcp_client_tool_allowlist():
    client = get_mcp_client()
    valid, err = client.validate_tool_call("forbidden_tool_xyz", {})
    assert not valid
    assert "not in the allowed MCP tool allowlist" in err


@pytest.mark.asyncio
async def test_mcp_client_call_search_logs():
    client = get_mcp_client()
    res = await client.call_tool("search_logs", {"entities": {"source_ip": "185.220.101.45"}})
    assert res.get("ok") is True
    assert "hits" in res
    assert "evidence_type" in res


@pytest.mark.asyncio
async def test_mcp_client_call_threat_intel():
    client = get_mcp_client()
    res = await client.call_tool("lookup_ip", {"ip": "185.220.101.45"})
    assert res.get("ok") is True
    assert res.get("reputation") == "malicious"
    assert res.get("evidence_type") == "threat_intel"


@pytest.mark.asyncio
async def test_mcp_client_call_knowledge():
    client = get_mcp_client()
    res = await client.call_tool("get_mitre_technique", {"technique_id": "T1110"})
    assert res.get("ok") is True
    assert "doc_id" in res or "text" in res
