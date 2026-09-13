# Conversational SIEM — Technical Architecture (Phase 10)

## System Overview

```text
SOC Analyst (React Console)
        ↓
FastAPI Backend (JWT + RBAC)
        ↓
┌───────────────────────────────────────────────────┐
│  Investigation Agent (optional)                   │
│  Plan → Tools → Correlate → Explain → Report      │
└───────────────────────────────────────────────────┘
        ↓
┌─────────────┬──────────────┬─────────────────────┐
│ NLP Layer   │ Query Engine │ Threat Analysis     │
│ Intent      │ IR → DSL     │ IOC + Correlation     │
│ Entities    │ Validator    │ Attack Chain          │
│ Normalizer  │ SIEM Client  │ MITRE Mapping         │
└─────────────┴──────────────┴─────────────────────┘
        ↓                    ↓
   SIEM Evidence      Knowledge Evidence (RAG)
   (Elasticsearch)    (MITRE, Playbooks, Rules)
        ↓                    ↓
              Explainability Engine
                        ↓
              JSON / PDF Reports
```

## Agent Workflow

```text
Analyst Question
      ↓
Intent + Entity Extraction (with normalization)
      ↓
[Optional] Human Approval of Plan
      ↓
Agent Loop (max 8 iterations, 60s timeout)
  1. search_logs (IR compiler — never raw DSL)
  2. get_related_events
  3. lookup_ip (threat intel)
  4. extract_iocs + correlate_patterns
  5. search_security_knowledge (RAG)
  6. build_timeline
  7. generate_explanation
      ↓
Evidence Correlation (SIEM + Knowledge separated)
      ↓
Attack Chain + Severity Score
      ↓
Explainable Response + Report
```

## MCP Architecture

```text
Investigation Agent
        ↓
┌──────────────┬─────────────────┬──────────────────┐
│ SIEM MCP     │ Threat Intel MCP│ Knowledge MCP    │
│ search_logs  │ lookup_ip       │ search_knowledge │
│ get_event    │ lookup_domain   │ get_mitre        │
│ get_related  │ lookup_hash     │                  │
└──────────────┴─────────────────┴──────────────────┘
        ↓              ↓                  ↓
   IR Compiler    TI Mock/API       ChromaDB / Keyword
```

## RAG Pipeline

```text
data/mitre/techniques.json
data/playbooks/*.json
data/detection_rules/rules.json
        ↓
Document Loader → Chunker (500 chars, 50 overlap)
        ↓
Vector Index (ChromaDB or keyword fallback)
        ↓
Semantic Search + Metadata Filter (doc_type)
        ↓
Source References (evidence_type: knowledge_base)
```

## Security Architecture

- **IR Compiler**: LLM never writes raw Elasticsearch DSL
- **Untrusted Log Isolation**: `[UNTRUSTED LOG DATA]` blocks in LLM prompts
- **Tool Allowlist**: Agent tools restricted to `ALLOWED_TOOLS`
- **RBAC**: admin / analyst / viewer on all investigation endpoints
- **Rate Limiting**: Per-IP limits on investigate endpoints
- **Prompt Injection Detection**: Pattern-based screening on user input
- **Audit Logging**: All API requests logged with duration

## API Endpoints (New in Phases 2–7)

| Endpoint | Description |
|---|---|
| `POST /api/knowledge/search` | RAG semantic search |
| `GET /api/knowledge/mitre/{id}` | MITRE technique lookup |
| `POST /api/agent/investigate` | Agentic investigation |
| `POST /api/agent/approve` | Human-in-the-loop approval |
| `GET /health` | Health + knowledge doc count |
| `GET /metrics` | Service metrics |

## Evaluation (Phase 8)

Run: `python backend/tests/evaluation_phase8.py`

Metrics: intent accuracy, entity normalization, IR/DSL validity, RAG retrieval, prompt injection detection, tool argument validation.

## Benchmark (Phase 1 + 8)

Run: `python backend/tests/evaluation_suite.py` (50-query benchmark)
