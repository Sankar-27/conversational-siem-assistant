"""
Query Generator.

Pipeline:
  Natural Language
      ↓
  ExtractedEntities (from intent_extractor)
      ↓
  JSON Intermediate Representation (via LLM + schema_mapper whitelist)
      ↓
  Elasticsearch DSL (deterministic compiler — no LLM involvement)

The LLM generates ONLY the structured JSON IR.
The compiler translates IR → DSL using validated field names from schema_mapper.
This prevents the LLM from injecting malicious or invalid query fragments.
"""
from __future__ import annotations
import json
from typing import Any, Optional
from app.core.llm import get_llm
from app.modules.conversational.entities import ExtractedEntities
from app.modules.query_engine.schema_mapper import (
    ALLOWED_QUERY_FIELDS, is_allowed_field, resolve_event_action, get_http_status_codes
)

QUERY_SYSTEM_PROMPT = """You are an Elasticsearch query builder for a SIEM system.
Given extracted security entities, produce a JSON intermediate representation (IR) for an Elasticsearch query.

The IR must follow this exact schema — no other fields are allowed:
{
  "query_type": "security_event_search",
  "filters": [
    {"field": "<ES_FIELD>", "operator": "<eq|gt|lt|gte|lte|contains|in>", "value": <value>}
  ],
  "time_range": {"from": "<ES_time_expression>", "to": "<ES_time_expression>"},
  "sort": [{"field": "@timestamp", "order": "desc"}],
  "size": <integer 10-1000>,
  "aggs": {}
}

ALLOWED field names (use ONLY these):
source.ip, destination.ip, destination.port, user.name, event.action, event.category,
event.severity, http.request.method, http.response.status_code, url.original,
user_agent.original, file.name, file.hash.md5, file.hash.sha256, network.protocol,
network.transport, host.name, log.logger

IMPORTANT: Return ONLY the JSON object. No explanation. No markdown fences."""


def _build_filter_clause(field: str, operator: str, value: Any) -> dict:
    """Convert an IR filter into an ES query clause."""
    if not is_allowed_field(field):
        raise ValueError(f"Field '{field}' is not in the allowed whitelist")

    if operator == "eq":
        return {"term": {field: value}}
    elif operator == "contains":
        return {"wildcard": {field: f"*{value}*"}}
    elif operator == "in":
        return {"terms": {field: value if isinstance(value, list) else [value]}}
    elif operator in ("gt", "lt", "gte", "lte"):
        return {"range": {field: {operator: value}}}
    else:
        return {"term": {field: value}}


def compile_ir_to_dsl(ir: dict) -> dict:
    """
    Deterministic compiler: JSON IR → Elasticsearch DSL.
    All field names are validated against the whitelist before inclusion.
    """
    must_clauses = []
    filter_clauses = []

    # Time range filter
    time_range = ir.get("time_range", {})
    if time_range:
        filter_clauses.append({
            "range": {
                "@timestamp": {
                    "gte": time_range.get("from", "now-24h"),
                    "lte": time_range.get("to", "now"),
                }
            }
        })

    # Field filters
    for f in ir.get("filters", []):
        field = f.get("field", "")
        operator = f.get("operator", "eq")
        value = f.get("value")
        if value is None:
            continue
        try:
            clause = _build_filter_clause(field, operator, value)
            filter_clauses.append(clause)
        except ValueError:
            # Skip invalid fields silently (already validated upstream)
            continue

    # Build bool query
    bool_query: dict = {}
    if must_clauses:
        bool_query["must"] = must_clauses
    if filter_clauses:
        bool_query["filter"] = filter_clauses

    dsl: dict = {
        "query": {"bool": bool_query} if bool_query else {"match_all": {}},
        "sort": ir.get("sort", [{"@timestamp": {"order": "desc"}}]),
        "size": min(max(ir.get("size", 100), 1), 1000),
    }

    # Aggregations
    aggs = ir.get("aggs", {})
    if aggs:
        dsl["aggs"] = aggs

    return dsl


async def generate_query_ir(entities: ExtractedEntities) -> dict:
    """
    Use the LLM to produce a structured JSON IR from extracted entities.
    Returns a validated IR dict.
    """
    llm = get_llm()

    # Serialize entities for the LLM (only non-None fields)
    entity_dict = {k: v for k, v in entities.model_dump().items() if v is not None}
    user_message = f"Extracted security entities:\n{json.dumps(entity_dict, indent=2)}"

    try:
        ir = await llm.complete_json(QUERY_SYSTEM_PROMPT, user_message)

        # Validate and sanitize IR fields
        validated_filters = []
        for f in ir.get("filters", []):
            if is_allowed_field(f.get("field", "")):
                validated_filters.append(f)
        ir["filters"] = validated_filters

        # Ensure size is within bounds
        ir["size"] = min(max(ir.get("size", 100), 1), 1000)

        return ir
    except Exception:
        # Fallback: build IR directly from entities without LLM
        return _build_fallback_ir(entities)


def _build_fallback_ir(entities: ExtractedEntities) -> dict:
    """Build a basic IR directly from entities — no LLM involved."""
    filters = []

    if entities.source_ip:
        filters.append({"field": "source.ip", "operator": "eq", "value": entities.source_ip})
    if entities.username:
        filters.append({"field": "user.name", "operator": "eq", "value": entities.username})
    if entities.event_action:
        action = resolve_event_action(entities.event_action) or entities.event_action
        filters.append({"field": "event.action", "operator": "eq", "value": action})
    if entities.url_path:
        filters.append({"field": "url.original", "operator": "contains", "value": entities.url_path})
    if entities.destination_port:
        filters.append({"field": "destination.port", "operator": "eq", "value": entities.destination_port})
    if entities.http_status:
        status_codes = get_http_status_codes(entities.http_status)
        if status_codes:
            filters.append({"field": "http.response.status_code", "operator": "in", "value": status_codes})
        else:
            try:
                filters.append({"field": "http.response.status_code", "operator": "eq", "value": int(entities.http_status)})
            except (ValueError, TypeError):
                pass

    return {
        "query_type": "security_event_search",
        "filters": filters,
        "time_range": entities.time_range or {"from": "now-24h", "to": "now"},
        "sort": [{"field": "@timestamp", "order": "desc"}],
        "size": 100,
        "aggs": {},
    }


async def build_query(entities: ExtractedEntities) -> tuple[dict, dict]:
    """
    Full query build pipeline.
    Returns (ir, dsl) — the intermediate representation and the compiled ES DSL.
    """
    ir = await generate_query_ir(entities)
    dsl = compile_ir_to_dsl(ir)
    return ir, dsl
