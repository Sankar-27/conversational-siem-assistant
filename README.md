# Conversational SIEM Assistant for Threat Investigation & Automated Reporting

[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688.svg?style=flat&logo=FastAPI&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB.svg?style=flat&logo=React&logoColor=black)](https://reactjs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.4-3178C6.svg?style=flat&logo=TypeScript&logoColor=white)](https://www.typescriptlang.org)
[![Elasticsearch](https://img.shields.io/badge/Elasticsearch-8.13-005571.svg?style=flat&logo=Elasticsearch&logoColor=white)](https://www.elastic.co)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-ED1C24.svg?style=flat)](https://attack.mitre.org)

An enterprise-grade AI assistant that enables SOC analysts to perform **natural-language SIEM investigations**, automatically extract **Indicators of Compromise (IOCs)**, map attack patterns to **MITRE ATT&CK**, and generate **evidence-grounded incident reports (JSON & PDF)**.

---

## Architecture Overview

```
Security Analyst
       ↓
Natural Language Question
       ↓
Conversational AI Layer (Intent + Entity Extraction)
       ↓
Query Intelligence Layer (Schema Mapper + JSON IR)
       ↓
Query Validation Layer (Whitelist + Safety Guardrails)
       ↓
SIEM Execution (Elasticsearch / Wazuh / Mock Store)
       ↓
Retrieved Security Logs (ECS Normalized)
       ↓
Threat Analysis Layer (IOC Extraction + Event Correlation)
       ↓
MITRE ATT&CK Mapping (Tactic & Technique Classification)
       ↓
Explainability Layer (Evidence Linker + Reasoning Engine)
       ↓
Visualization & Reporting (React Console + PDF Exporter)
```

---

## Key Features

- **Natural Language SIEM Search**: Converts analyst questions (e.g. *"Show failed logins from 185.220.101.45 yesterday"*) into validated Elasticsearch DSL queries without requiring KQL/DSL expertise.
- **Multi-Turn Investigation Context**: Retains previous filters for seamless follow-up questions (*"Only show VPN-related attempts"*).
- **Automated IOC Extraction**: Extracts IPv4/IPv6 addresses, domains, URLs, file hashes, usernames, and flags suspicious external IPs.
- **MITRE ATT&CK Mapping**: Maps detected attack patterns (Brute Force, Port Scanning, SQLi, Path Traversal, Credential Stuffing) to MITRE tactics and technique IDs (e.g. `T1110`, `T1046`, `T1190`).
- **Explainable AI Responses**: Displays generated DSL queries, hit counts, and guarantees that conclusions are backed by retrieved log evidence.
- **Automated Incident Reports**: Assembles formal executive summaries, evidence tables, IOC lists, and exports formatted PDF incident reports with one click.
- **Interactive Security Dashboard**: Real-time charts for top attacking source IPs, MITRE technique distribution, and telemetry metrics using Recharts.
- **Role-Based Access Control (RBAC)**: JWT authentication with `admin`, `analyst`, and `viewer` permissions.

---

## Project Structure

```
Project_work/
├── backend/
│   ├── app/
│   │   ├── api/routes/          # Auth, Investigation, Reports, Dashboard routes
│   │   ├── core/                # Config, JWT Auth, Logging, Pluggable LLM Layer
│   │   ├── db/                  # Async database session & table initialization
│   │   ├── models/              # SQLAlchemy models (User, Conversation, Investigation, IOC, MITRE, Evidence, Report)
│   │   ├── modules/
│   │   │   ├── conversational/  # Context manager & Intent/Entity extractor
│   │   │   ├── query_engine/    # Schema mapper, JSON IR builder, DSL compiler, SIEM client
│   │   │   ├── threat_analysis/ # Regex & LLM IOC extractor, Event correlator
│   │   │   ├── mitre/           # ATT&CK mapper & Chronological timeline builder
│   │   │   ├── explainability/  # Evidence linker & explanation engine
│   │   │   └── reporting/       # Incident report builder & ReportLab PDF exporter
│   │   └── main.py              # FastAPI application factory
│   ├── tests/                   # Pytest suite & Benchmark evaluation (50 queries)
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── api/                 # Typed Axios client with auth interceptors
│   │   ├── components/          # Evidence tables, IOC panels, MITRE cards, Timelines
│   │   ├── context/             # AuthContext (JWT session management)
│   │   ├── pages/               # ChatInvestigation, Dashboard, History, ReportViewer, Login, Register
│   │   └── types/               # TypeScript data contracts
│   ├── package.json
│   └── Dockerfile
├── data/
│   └── mock_logs/               # Synthetic 5000-log dataset with 5 embedded attack scenarios
├── docker-compose.yml           # Full-stack Docker orchestration
└── README.md
```

---

## Quick Start (Local Setup)

### 1. Prerequisites
- Python 3.10+
- Node.js 18+ (for frontend)
- (Optional) Docker & Docker Compose

### 2. Backend Setup
```bash
cd backend
python -m venv venv
.\venv\Scripts\activate
python -m pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
API Documentation will be accessible at: `http://localhost:8000/api/docs`

### 3. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```
Web console will be accessible at: `http://localhost:5173`

### 4. Running via Docker Compose
To run PostgreSQL, Elasticsearch, Backend, and Frontend all at once:
```bash
docker-compose up --build
```

---

## Testing & Research Benchmark Evaluation

Run the automated evaluation benchmark (Section 35 of PRD):
```bash
cd backend
python tests/evaluation_suite.py
```

---

## Security & Reliability Design

1. **Intermediate Representation (IR) Compiler**: The LLM never writes raw DSL directly. It outputs structured JSON that is compiled by a deterministic engine against an allowed whitelist.
2. **Untrusted Data Isolation**: All retrieved log content is passed in strictly delimited `[UNTRUSTED LOG DATA]` blocks to prevent prompt injection from malicious logs.
3. **Evidence Grounding**: Findings must be linked to specific retrieved log IDs before appearing in reports.
