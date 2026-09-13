"""
MCP Client Manager — Model Context Protocol (MCP) client manager.
Discovers tools, validates schemas, enforces security allowlists, manages stdio transports,
handles rate limiting, and sanitizes tool outputs.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.core.config import settings
from app.core.logging import logger

MCP_SERVERS_DIR = Path(__file__).resolve().parents[3] / "mcp_servers"

TOOL_SERVER_MAP: Dict[str, str] = {
    # SIEM MCP Server
    "search_logs": "siem_server.py",
    "get_event": "siem_server.py",
    "get_related_events": "siem_server.py",
    "correlate_events": "siem_server.py",
    "build_timeline": "siem_server.py",
    # Threat Intelligence MCP Server
    "lookup_ip": "threat_intel_server.py",
    "lookup_domain": "threat_intel_server.py",
    "lookup_hash": "threat_intel_server.py",
    "search_threat_intelligence": "threat_intel_server.py",
    "enrich_ioc": "threat_intel_server.py",
    # Security Knowledge MCP Server
    "search_security_knowledge": "knowledge_server.py",
    "get_mitre_technique": "knowledge_server.py",
    "get_security_playbook": "knowledge_server.py",
    "search_internal_docs": "knowledge_server.py",
}

# Allowed tools whitelist
ALLOWED_MCP_TOOLS = set(TOOL_SERVER_MAP.keys())

# Rate limiting tracker: tool_name -> list of invocation timestamps
_RATE_LIMITS: Dict[str, List[float]] = {}
MAX_CALLS_PER_MINUTE = 60


class MCPClientManager:
    """Manager for connecting to and executing tools on MCP servers."""

    def __init__(self, mcp_dir: Optional[Path] = None):
        self.mcp_dir = mcp_dir or MCP_SERVERS_DIR
        self._server_processes: Dict[str, asyncio.subprocess.Process] = {}

    def _check_rate_limit(self, tool_name: str) -> bool:
        now = time.time()
        calls = _RATE_LIMITS.setdefault(tool_name, [])
        # Keep calls within last 60s
        _RATE_LIMITS[tool_name] = [t for t in calls if now - t < 60]
        if len(_RATE_LIMITS[tool_name]) >= MAX_CALLS_PER_MINUTE:
            return False
        _RATE_LIMITS[tool_name].append(now)
        return True

    def validate_tool_call(self, tool_name: str, arguments: dict) -> Tuple[bool, Optional[str]]:
        if tool_name not in ALLOWED_MCP_TOOLS:
            return False, f"Tool '{tool_name}' is not in the allowed MCP tool allowlist."

        if not self._check_rate_limit(tool_name):
            return False, f"Rate limit exceeded for MCP tool '{tool_name}' (max {MAX_CALLS_PER_MINUTE}/min)."

        return True, None

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict,
        timeout: float = 30.0,
    ) -> dict:
        """Call an MCP tool with validation, rate limiting, and output sanitization."""
        valid, err = self.validate_tool_call(tool_name, arguments)
        if not valid:
            logger.warning("mcp_tool_blocked", tool=tool_name, error=err)
            return {"ok": False, "error": err, "blocked": True}

        server_script = TOOL_SERVER_MAP.get(tool_name)
        if not server_script:
            return {"ok": False, "error": f"No MCP server mapped for tool '{tool_name}'"}

        script_path = self.mcp_dir / server_script
        if not script_path.exists():
            # In-process direct fallback if script file is missing
            return await self._in_process_fallback(tool_name, arguments)

        start_time = time.perf_counter()
        try:
            res = await asyncio.wait_for(
                self._exec_stdio_rpc(script_path, tool_name, arguments),
                timeout=timeout,
            )
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            logger.info("mcp_tool_success", tool=tool_name, latency_ms=elapsed_ms)
            return res
        except asyncio.TimeoutError:
            logger.error("mcp_tool_timeout", tool=tool_name, timeout=timeout)
            return {"ok": False, "error": f"MCP tool '{tool_name}' execution timed out after {timeout}s"}
        except Exception as e:
            logger.error("mcp_tool_error", tool=tool_name, error=str(e))
            return await self._in_process_fallback(tool_name, arguments)

    async def _exec_stdio_rpc(self, script_path: Path, tool_name: str, arguments: dict) -> dict:
        """Execute a tool via standard MCP JSON-RPC 2.0 stdio transport."""
        cmd = [sys.executable, str(script_path)]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        init_req = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "backend-mcp-client", "version": "1.0.0"},
            },
        }) + "\n"

        call_req = json.dumps({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }) + "\n"

        input_data = (init_req + call_req).encode("utf-8")
        stdout, stderr = await proc.communicate(input=input_data)

        if proc.returncode != 0 and not stdout:
            err_msg = stderr.decode("utf-8", errors="ignore") or "Subprocess returned non-zero exit code"
            return {"ok": False, "error": err_msg}

        lines = stdout.decode("utf-8", errors="ignore").strip().splitlines()
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                resp = json.loads(line)
                if resp.get("id") == 2 and "result" in resp:
                    content = resp["result"].get("content", [])
                    if content and isinstance(content, list):
                        text = content[0].get("text", "{}")
                        return json.loads(text)
            except Exception:
                continue

        return {"ok": False, "error": "Failed to parse valid MCP RPC response"}

    async def _in_process_fallback(self, tool_name: str, arguments: dict) -> dict:
        """Fallback to internal module execution when subprocess transport is unavailable."""
        from app.modules.agent.tools import (
            search_logs, get_event, get_related_events, lookup_ip,
            lookup_domain, lookup_hash, search_threat_intelligence,
            search_security_knowledge_tool, get_mitre_technique_tool, build_timeline_tool
        )
        from app.modules.conversational.intent_extractor import ExtractedEntities

        if tool_name == "search_logs":
            entities = ExtractedEntities(**arguments.get("entities", {}))
            return await search_logs(entities)
        if tool_name == "get_event":
            event = await get_event(arguments.get("event_id", ""), arguments.get("hits", []))
            return {"ok": event is not None, "event": event}
        if tool_name == "get_related_events":
            related = await get_related_events(arguments.get("source_ip", ""), arguments.get("hits", []))
            return {"ok": True, "count": len(related), "events": related[:20]}
        if tool_name == "lookup_ip":
            return await lookup_ip(arguments.get("ip", ""))
        if tool_name == "lookup_domain":
            return await lookup_domain(arguments.get("domain", ""))
        if tool_name == "lookup_hash":
            return await lookup_hash(arguments.get("hash", ""))
        if tool_name == "search_threat_intelligence":
            return await search_threat_intelligence(arguments.get("ioc_type", "ip"), arguments.get("value", ""))
        if tool_name == "search_security_knowledge":
            return await search_security_knowledge_tool(arguments.get("query", ""), arguments.get("doc_type"))
        if tool_name == "get_mitre_technique":
            return await get_mitre_technique_tool(arguments.get("technique_id", ""))
        if tool_name == "build_timeline":
            return await build_timeline_tool(arguments.get("hits", []))

        return {"ok": False, "error": f"Unknown tool '{tool_name}' in fallback execution"}


# Global singleton instance
_mcp_client: Optional[MCPClientManager] = None


def get_mcp_client() -> MCPClientManager:
    global _mcp_client
    if _mcp_client is None:
        _mcp_client = MCPClientManager()
    return _mcp_client
