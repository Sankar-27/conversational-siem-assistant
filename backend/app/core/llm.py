"""
LLM Provider Abstraction Layer.

Supports: Gemini, OpenAI, Anthropic, Mock (for testing without API keys).
The provider is selected via LLM_PROVIDER env var.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any
import json
from app.core.config import settings
from app.core.logging import logger


class LLMProvider(ABC):
    @abstractmethod
    async def complete(self, system_prompt: str, user_message: str, temperature: float = 0.1) -> str:
        """Send a completion request and return the response text."""
        ...

    async def complete_json(self, system_prompt: str, user_message: str) -> dict:
        """Complete a request and parse the response as JSON."""
        raw = await self.complete(system_prompt, user_message, temperature=0.0)
        # Strip markdown code fences if present
        raw = raw.strip()
        if raw.startswith("```"):
            lines = raw.split("\n")
            raw = "\n".join(lines[1:-1]) if lines[-1].strip() == "```" else "\n".join(lines[1:])
        return json.loads(raw)


class GeminiProvider(LLMProvider):
    def __init__(self):
        import google.generativeai as genai
        genai.configure(api_key=settings.GEMINI_API_KEY)
        self._model = genai.GenerativeModel(settings.LLM_MODEL)

    async def complete(self, system_prompt: str, user_message: str, temperature: float = 0.1) -> str:
        import asyncio, functools
        combined = f"{system_prompt}\n\n{user_message}"
        response = await asyncio.get_event_loop().run_in_executor(
            None,
            functools.partial(
                self._model.generate_content,
                combined,
                generation_config={"temperature": temperature, "max_output_tokens": 4096},
            ),
        )
        return response.text


class OpenAIProvider(LLMProvider):
    def __init__(self):
        from openai import AsyncOpenAI
        self._client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)

    async def complete(self, system_prompt: str, user_message: str, temperature: float = 0.1) -> str:
        response = await self._client.chat.completions.create(
            model=settings.LLM_MODEL or "gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            temperature=temperature,
            max_tokens=4096,
        )
        return response.choices[0].message.content


class AnthropicProvider(LLMProvider):
    def __init__(self):
        import anthropic
        self._client = anthropic.AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)

    async def complete(self, system_prompt: str, user_message: str, temperature: float = 0.1) -> str:
        message = await self._client.messages.create(
            model=settings.LLM_MODEL or "claude-3-haiku-20240307",
            max_tokens=4096,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
            temperature=temperature,
        )
        return message.content[0].text


class MockLLMProvider(LLMProvider):
    """Returns deterministic mock responses for development/testing without API keys."""

    async def complete(self, system_prompt: str, user_message: str, temperature: float = 0.1) -> str:
        import re
        combined = f"{system_prompt}\n{user_message}".lower()
        msg_lower = user_message.lower()

        # Check for intent/entity extraction prompt
        if "intent" in combined or "entity" in combined or "extract" in combined:
            # Extract IP if present in query
            ip_match = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", user_message)
            source_ip = ip_match.group(0) if ip_match else None
            
            # Action & Threat category detection
            action = None
            if "failed" in msg_lower or "login" in msg_lower or "auth" in msg_lower or "brute" in msg_lower:
                action = "failed_login"
            elif "sql" in msg_lower or "injection" in msg_lower or "traversal" in msg_lower or "web" in msg_lower or "xss" in msg_lower or "command" in msg_lower:
                action = "web_attack"
            elif "scan" in msg_lower or "port" in msg_lower or "probe" in msg_lower:
                action = "network_scan"
            elif "powershell" in msg_lower or "privilege" in msg_lower or "task" in msg_lower:
                action = "process_created"
            elif "exfiltrat" in msg_lower or "download" in msg_lower:
                action = "data_transfer"
            elif "ddos" in msg_lower or "flood" in msg_lower:
                action = "high_volume_request"

            user_match = re.search(r"username\s+([a-zA-Z0-9_\-\.]+)", user_message, re.I)
            username = user_match.group(1) if user_match else ("admin" if "admin" in msg_lower and "user" in msg_lower else None)

            return json.dumps({
                "intent": "investigate",
                "entities": {
                    "source_ip": source_ip,
                    "username": username,
                    "event_action": action,
                    "time_range": {"from": "now-7d", "to": "now"},
                },
                "is_followup": False,
                "ambiguous": False,
                "clarification_needed": None,
                "confidence": 0.95,
            })

        # Query builder prompt
        if "elasticsearch" in combined or "query" in combined or "dsl" in combined:
            filters = []
            try:
                if "{" in user_message:
                    ent = json.loads(user_message[user_message.find("{"):user_message.rfind("}")+1])
                    if ent.get("source_ip"):
                        filters.append({"field": "source.ip", "operator": "eq", "value": ent["source_ip"]})
                    if ent.get("event_action"):
                        filters.append({"field": "event.action", "operator": "eq", "value": ent["event_action"]})
                    if ent.get("username"):
                        filters.append({"field": "user.name", "operator": "eq", "value": ent["username"]})
            except Exception:
                pass

            return json.dumps({
                "query_type": "security_event_search",
                "filters": filters,
                "time_range": {"from": "now-7d", "to": "now"},
                "sort": [{"field": "@timestamp", "order": "desc"}],
                "size": 100,
            })

        # Explanation / synthesis prompt
        if "explain" in combined or "evidence" in combined or "analyst" in combined or "summary" in combined:
            # Extract IP if present in evidence
            ip_match = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", user_message)
            identified_ip = ip_match.group(0) if ip_match else "the flagged endpoint"
            
            return (
                f"Investigation Analysis:\n\n"
                f"Multiple security events were observed matching the query criteria targeting {identified_ip}. "
                f"The 3-stage correlation engine detected recurring activity aligning with known threat signatures and MITRE ATT&CK techniques. "
                f"High-frequency requests and anomalous access patterns were captured in the telemetry stream. "
                f"All supporting event logs and IOC indicators have been preserved as verified evidence."
            )

        return (
            "Investigation complete. Security logs were correlated against threat pattern definitions and verified with supporting telemetry evidence."
        )



def get_llm_provider() -> LLMProvider:
    """Factory: returns the configured LLM provider."""
    provider = settings.LLM_PROVIDER.lower()
    logger.info("llm_provider_init", provider=provider)
    if provider == "gemini":
        if not settings.GEMINI_API_KEY:
            logger.warning("No GEMINI_API_KEY set — falling back to MockLLMProvider")
            return MockLLMProvider()
        return GeminiProvider()
    elif provider == "openai":
        return OpenAIProvider()
    elif provider == "anthropic":
        return AnthropicProvider()
    else:
        return MockLLMProvider()


# Singleton
_llm_provider: LLMProvider | None = None


def get_llm() -> LLMProvider:
    global _llm_provider
    if _llm_provider is None:
        _llm_provider = get_llm_provider()
    return _llm_provider
