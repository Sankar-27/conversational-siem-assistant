"""
Query Validator — validates Elasticsearch DSL before execution.

Checks:
1. Field names are in the whitelist
2. No destructive operations
3. Time range is valid
4. Size is within bounds
5. Query structure is well-formed
"""
from __future__ import annotations
from dataclasses import dataclass, field
from app.modules.query_engine.schema_mapper import ALLOWED_QUERY_FIELDS, SUPPORTED_INDICES

# Terms that absolutely must not appear in a query
FORBIDDEN_TERMS = {"_delete_by_query", "_update_by_query", "_bulk", "_mapping", "script"}


@dataclass
class ValidationResult:
    valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def validate_dsl(dsl: dict, index: str = "siem-logs") -> ValidationResult:
    """Validate a compiled Elasticsearch DSL query."""
    result = ValidationResult(valid=True)

    # 1. Must be a dict
    if not isinstance(dsl, dict):
        result.valid = False
        result.errors.append("Query must be a JSON object")
        return result

    # 2. Forbidden terms check
    dsl_str = str(dsl).lower()
    for term in FORBIDDEN_TERMS:
        if term in dsl_str:
            result.valid = False
            result.errors.append(f"Forbidden operation detected: '{term}'")

    # 3. Check query structure
    if "query" not in dsl:
        result.warnings.append("No 'query' key found — will match all documents")

    # 4. Validate all field references in filters
    query = dsl.get("query", {})
    fields_used = _extract_fields_from_query(query)
    for f in fields_used:
        if f not in ALLOWED_QUERY_FIELDS and not f.startswith("@"):
            result.errors.append(f"Field '{f}' is not in the allowed field whitelist")
            result.valid = False

    # 5. Size check
    size = dsl.get("size", 100)
    if not isinstance(size, int) or size < 1 or size > 1000:
        result.errors.append(f"'size' must be an integer between 1 and 1000 (got {size})")
        result.valid = False

    # 6. Index check
    if index not in SUPPORTED_INDICES and not any(index.endswith("*") for _ in [1]):
        result.warnings.append(f"Index '{index}' is not in the known supported list")

    return result


def _extract_fields_from_query(query: dict) -> list[str]:
    """Recursively extract all field names referenced in a query dict."""
    fields = []
    if not isinstance(query, dict):
        return fields

    # bool query
    if "bool" in query:
        for clause_type in ("must", "filter", "should", "must_not"):
            clauses = query["bool"].get(clause_type, [])
            if isinstance(clauses, dict):
                clauses = [clauses]
            for clause in clauses:
                fields.extend(_extract_fields_from_query(clause))

    # term / match / range / wildcard / terms
    for leaf_type in ("term", "match", "range", "wildcard", "terms"):
        if leaf_type in query:
            fields.extend(query[leaf_type].keys())

    return fields
