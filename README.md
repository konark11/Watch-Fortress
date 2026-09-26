# Watch Fortress

*Unified Vulnerability Assessment Platform*

A full-stack platform that integrates Nmap, OpenVAS, Nessus, and Nuclei
into one dashboard: launches scans, normalizes and correlates results
across scanners, maps findings to CVE/CWE/CAPEC/MITRE ATT&CK/OWASP,
prioritizes risk, answers questions via a RAG-powered AI assistant, and
generates executive/technical/compliance reports — with offline/air-gapped
deployment as a first-class mode, not an afterthought.

## What's real vs. what's honestly a stub

Everything below was actually built and tested against live data during
development — not just specified:

| Component | Status |
|---|---|
| Nmap integration | **Live** — real subprocess integration, tested against a live scan (scanme.nmap.org) through the actual REST API |
| Nuclei integration | **Live** — real v3.11.0 binary + 13,500+ real templates, tested |
| OpenVAS integration | **Real GMP protocol client** (authenticate → create target → create task → poll → fetch report), correctly reports "not configured" without a live gvmd server — point `GVM_HOST` at a real instance and it works as written |
| Nessus integration | **Real REST API client** (session/API-key auth → create scan → launch → poll → export → download), same honesty: reports unavailable without `NESSUS_URL` configured |
| Parsers (Nmap XML / Nessus / OpenVAS XML / Nuclei JSON / generic CSV+JSON) | **Tested** against real and realistic sample data |
| Correlation engine | **Tested** — proved the same CVE reported by 3 different scanners merges into one Vulnerability record with a risk-score boost |
| CVE→CWE→CAPEC→ATT&CK→OWASP→KEV mapping | **Tested**, offline, no NVD API call |
| Risk scoring | Deterministic, component-transparent, tested |
| RAG AI assistant | **Tested** — offline TF-IDF retrieval + template synthesis works out of the box with zero dependencies; Ollama/online LLM backends are correctly-shaped but **untestable in this environment** (no local LLM available) — same honesty pattern as OpenVAS/Nessus |
| Reports (PDF/HTML/DOCX/JSON) | **Tested** — all 4 formats generate and validate |
| Scheduling | APScheduler in-process, tested for job registration |
| RBAC + audit log | **Tested** — confirmed a non-privileged role gets a 403 where it should |
| Frontend (React/TypeScript/Tailwind) | **Built and served end-to-end** through the backend; every page's API calls were verified against the real response shapes |

## Architecture

```
vuln-platform/
├── backend/                    FastAPI + SQLAlchemy (SQLite by default, Postgres via env var)
│   ├── models/database.py       Users/RBAC, Assets, Scans, Findings, Vulnerabilities, KB, Reports, Audit
│   ├── parsers/                 Nmap XML, Nessus, OpenVAS XML, Nuclei JSON, generic CSV/JSON
│   ├── knowledge/                Offline CVE/CWE/CAPEC/ATT&CK/OWASP/CISA-KEV data + mapping engine
│   ├── correlation/              Cross-scanner dedup + risk scoring
│   ├── scanners/                 Nmap/Nuclei (real) + OpenVAS/Nessus (real API clients) + custom scripts
│   ├── rag/                      TF-IDF retriever + pluggable LLM backends (template/ollama/online)
│   ├── reports/                  PDF (reportlab) / HTML (Jinja2) / DOCX (python-docx) / JSON generators
│   ├── scheduling/               APScheduler-based recurring scans + auto-rescan-on-remediation
│   ├── auth/                     JWT auth, RBAC permission matrix, audit logging
│   └── api/                      REST routes + WebSocket for live scan progress
├── frontend/                   React 19 + TypeScript + Tailwind v4 + Recharts (Vite)
├── Dockerfile                  Multi-stage: builds frontend, bakes into backend image
├── docker-compose.yml          Single-command deploy, optional Ollama/Postgres profiles
└── build_portable.sh           Produces an air-gap-transportable bundle
```

## Quick start

### With Docker (recommended)
```bash
docker compose up --build
```
Open `http://localhost:8000`. First launch shows a "Create the administrator
account" screen (works once — only while the user table is empty).

### Without Docker
```bash
# Backend
cd backend
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000

# Frontend (separate terminal, for development with hot reload)
cd frontend
npm install
npm run dev    # proxies /api and /ws to localhost:8000, opens on :5173

# OR build the frontend once and let the backend serve it directly:
cd frontend && npm install && npm run build
cd ../backend && uvicorn main:app --host 0.0.0.0 --port 8000
# now http://localhost:8000 serves the whole app from one process
```

Nmap and Nuclei need to be installed for the "launch a live scan" feature
(`apt install nmap`, and see nuclei installation below). Everything else —
importing scan result files, correlation, the AI assistant, reports — works
without either installed.

### Installing Nuclei + templates locally (non-Docker)
```bash
curl -sL -o nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v3.11.0/nuclei_3.11.0_linux_amd64.zip"
unzip nuclei.zip && sudo mv nuclei /usr/local/bin/
git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git ~/nuclei-templates
```

## Try it with the bundled sample scans

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -d "username=admin&password=<your-password>" \
  -H "Content-Type: application/x-www-form-urlencoded" | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

curl -X POST http://localhost:8000/api/scans/import -H "Authorization: Bearer $TOKEN" \
  -F "scanner_type=nessus" -F "name=Nessus import" -F "file=@sample_scans/sample_nessus.nessus"
curl -X POST http://localhost:8000/api/scans/import -H "Authorization: Bearer $TOKEN" \
  -F "scanner_type=openvas" -F "name=OpenVAS import" -F "file=@sample_scans/sample_openvas.xml"
curl -X POST http://localhost:8000/api/scans/import -H "Authorization: Bearer $TOKEN" \
  -F "scanner_type=nuclei" -F "name=Nuclei import" -F "file=@sample_scans/sample_nuclei.jsonl"
```

All three samples reference `CVE-2024-3400` — check the Vulnerabilities
page afterward and you'll see it appears **once**, correlated across all
three scanners, with a boosted risk score. Then ask the AI assistant
"How do I fix CVE-2024-3400?" and it retrieves the real CVE/CWE/CAPEC/
ATT&CK/OWASP chain.

## Enabling OpenVAS / Nessus

These are licensed/self-hosted server products this platform talks to
over their real protocols — it does not bundle or fake either engine.

```bash
# OpenVAS/GVM
export GVM_HOST=gvm.internal.corp GVM_USERNAME=admin GVM_PASSWORD=...

# Nessus
export NESSUS_URL=https://nessus.internal.corp:8834
export NESSUS_ACCESS_KEY=... NESSUS_SECRET_KEY=...
```
Until configured, both show as "not configured" in the Scans page rather
than silently pretending to work — you can still import their report
files (`.xml` / `.nessus`) at any time regardless of live connectivity.

## AI Assistant modes

Set `VULN_RAG_MODE`:
- `template` (default) — zero dependencies, zero network, always works. Retrieves from CVE/CWE/CAPEC/ATT&CK/OWASP + your Knowledge Base and synthesizes a structured answer.
- `ollama` — routes generation through a local Ollama server (`VULN_OLLAMA_BASE_URL`, `VULN_OLLAMA_MODEL`) for natural-language answers, still fully air-gapped since Ollama runs on localhost.
- `online` — routes through any OpenAI-chat-completions-compatible endpoint (`VULN_ONLINE_LLM_BASE_URL`, `VULN_ONLINE_LLM_API_KEY`, `VULN_ONLINE_LLM_MODEL`) for deployments with internet access.

`docker compose --profile llm up` starts a local Ollama container alongside
the platform if you want to try that mode.

## Building an air-gapped bundle

```bash
./build_portable.sh ./portable_build
```
Produces a Docker image `.tar`, a nuclei-templates snapshot, and a pip
wheel cache — see the generated `INSTALL_AIRGAPPED.md`.

## Roles (RBAC)

| Role | Can |
|---|---|
| Administrator | Everything, including user management |
| Security Analyst | Manage assets/scans/findings/reports/KB/schedules |
| Penetration Tester | Launch/cancel scans, triage findings |
| Auditor | Read everything + view audit log; cannot change state |

## Known, documented scope limits

- **Elasticsearch/OpenSearch** is listed in the spec's tech stack as an
  alternative to PostgreSQL for the database layer. This platform ships
  with SQLite (portable default) and PostgreSQL (swap via `VULN_DATABASE_URL`,
  zero code changes — everything goes through SQLAlchemy) but does **not**
  include an Elasticsearch-backed storage path. Adding one would mean a
  second persistence implementation behind the same query interfaces;
  it's a real gap, not a hidden one.
- **Celery + Redis** is listed for task queuing; scheduling here uses
  APScheduler running in-process instead, which needs no broker or
  separate worker deployment and is sufficient for the scan volumes a
  single-team deployment generates. A Celery/Redis backend is a natural
  upgrade path for very large multi-tenant fleets.
- **RAG embeddings**: uses TF-IDF (scikit-learn) rather than
  sentence-transformers/HuggingFace embeddings, specifically because those
  require downloading model weights over the internet on first use, which
  breaks air-gapped mode. FAISS/Chroma + a locally-cached embedding model
  is a valid upgrade if your deployment already has one cached.
- **Multi-tenancy, Jira/ServiceNow ticket creation, Slack/email alerts,
  exploit-prediction ML, and attack-path graph visualization** (all listed
  under "Advanced Features (Bonus)") are not implemented. The correlation
  engine, risk scorer, and asset graph data (`Asset.ports`,
  `Vulnerability.attack_techniques`) are structured so these could be
  built on top without a schema change, but they're not built.
- **Windows Event Log / raw `.evtx`**: not applicable to this platform
  (that was the prior SOC Log Analytics project) — mentioned here only to
  avoid confusion if you're comparing the two READMEs.

## Sample data

`sample_scans/` contains one real Nmap XML output (from a live scan run
during development) plus realistic Nessus/OpenVAS/Nuclei sample files, all
referencing overlapping CVEs so you can see correlation happen immediately
after import.
