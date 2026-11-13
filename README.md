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
| Authentication-failure analysis | **Implemented** — failed logins are recorded in the structured audit store and the assistant correlates daily volume, IP/user entities, temporal bursts, and retrieved attack-pattern context |
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
│   ├── rag/                      Persistent pgvector/FTS hybrid retrieval, incremental indexing, and pluggable LLM backends
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

Canonical hosted-generation settings are `RAG_GENERATION_PROVIDER`,
`RAG_GENERATION_BASE_URL`, `RAG_GENERATION_API_KEY`, and
`RAG_GENERATION_MODEL`. The OpenAI-compatible example uses
`openai/gpt-oss-120b`; credentials are supplied only through the environment.
The older `VULN_ONLINE_LLM_*` names remain fallback aliases.

For Groq's OpenAI-compatible endpoint, set `RAG_GENERATION_PROVIDER=groq`,
`GROQ_BASE_URL=https://api.groq.com/openai/v1`, and `GROQ_MODEL` to the
approved gpt-oss model. Provide either `GROQ_API_KEYS` as a comma-separated
pool or the backward-compatible `GROQ_API_KEY_1`, `GROQ_API_KEY_2`, and
`GROQ_API_KEY_3` variables. Retryable failures use bounded exponential
backoff, rotate keys, and open a short circuit after repeated failures; auth
and malformed-request failures are not retried. The status endpoint reports
only the configured key count and circuit state, never key values. If Groq is
unavailable or missing credentials, the API fails fast with a user-safe 503
instead of silently degrading to a different answer mode.

Set `VULN_RAG_MODE`:
- `template` (default) — zero dependencies, zero network, always works. Retrieves from CVE/CWE/CAPEC/ATT&CK/OWASP + your Knowledge Base and returns a concise answer in plain language.
- `ollama` — routes generation through a local Ollama server (`VULN_OLLAMA_BASE_URL`, `VULN_OLLAMA_MODEL`) for plain-language answers, still fully air-gapped since Ollama runs on localhost.
- `openrouter` — routes the retrieved evidence through OpenRouter's chat completions API. Set `OPENROUTER_API_KEY`, `OPENROUTER_MODEL`, and optionally `OPENROUTER_BASE_URL` in `.env`. The Docker Compose service forwards these variables to the backend, and local development loads them from the repository `.env`.

When local retrieval has no useful match, the assistant performs a bounded,
read-only NVD lookup (exact CVE IDs or a short keyword query) and cites that
result as an internet lookup. Set the optional `NVD_API_KEY` environment
variable for the NVD `apiKey` header. The lookup is limited to 3 seconds by default;
set `RAG_NVD_LOOKUP_TIMEOUT_SECONDS` to adjust it (1-10 seconds), and set
`VULN_NVD_URL` to use an approved mirror. Conversational follow-ups skip this
external lookup. Questions naming a CVE or specific vulnerability only use
matching evidence; otherwise the assistant reports that grounded evidence was
not found instead of generating from unrelated documents.
- `online` — routes through any OpenAI-chat-completions-compatible endpoint (`VULN_ONLINE_LLM_BASE_URL`, `VULN_ONLINE_LLM_API_KEY`, `VULN_ONLINE_LLM_MODEL`) for deployments with internet access.

`docker compose --profile llm up` starts a local Ollama container alongside
the platform if you want to try that mode.

For hosted generation, set `VULN_RAG_MODE=openrouter` and provide
`OPENROUTER_API_KEY`. The adapter defaults to
`poolside/laguna-s-2.1:free`; change `OPENROUTER_MODEL` only to another
OpenRouter model ending in `:free`. Optional embedding and reranking adapters are configured with
`OPENROUTER_EMBEDDING_MODEL` and `OPENROUTER_RERANK_MODEL` and use the same
key. The active retrieval path first uses local TF-IDF to build a broad
candidate set, then uses `OPENROUTER_RERANK_MODEL` when configured to score
the candidates and pass the best matches to the answer generator. This is an
optional query-document scoring stage, not a local `CrossEncoder` package;
the default remains fully offline and uses no key. `OPENROUTER_EMBEDDING_MODEL`
is available for future dense-retrieval deployments but is not needed by the
current local index. No paid model is selected or accepted by these adapters.
The local `BAAI/bge-base-en-v1.5` embedding model is preloaded during backend
startup by default (`RAG_PRELOAD_EMBEDDINGS=true`) so the first assistant
request does not pay model initialization cost. If the local model cannot be
loaded, startup continues with deterministic embeddings.

The assistant can answer questions such as "Show me why login failures
increased yesterday and whether this looks like an attack." It uses the
structured `auth.login_failed` audit events for exact aggregation and
correlation, then retrieves attack-pattern context from the local knowledge
base. The same evidence is available from `GET /api/assistant/login-failures`.
Analysis uses UTC calendar days and reports when fields needed for geographic
or impossible-travel analysis are not present.

### Embedding compatibility and re-embedding

Persisted knowledge chunks include model, revision, dimension, device, and
implementation metadata. Retrieval refuses vectors with missing provenance,
mixed dimensions, or a model mismatch; it never silently combines legacy
256-dimensional fallback vectors with 768-dimensional BGE vectors. From
`backend`, validate or rebuild persisted chunks with:

```bash
python -m rag.reembed --dry-run
python -m rag.reembed --apply
```

Generated corpus records are regenerated during the next index build. The
command reports the active encoder, dimensions, counts, and failures without
printing credentials.

### Durable scan jobs

Live scans are persisted as `background_jobs` and executed by a separate
worker. The API returns a scan ID and job ID immediately; progress and events
are read from the database, so an API restart does not lose queued work.
PostgreSQL is required for multi-worker durability and row locking. SQLite
remains a portable single-process development mode and does not provide the
same queue safety.

```bash
# Local development (single process/SQLite)
cd backend
python -m workers.run

# PostgreSQL production deployment
docker compose --profile production --profile postgres up --build
# Or run the processes directly with VULN_DATABASE_URL set:
python -m workers.run
python -m scheduling.dispatcher
```

### Database migrations and persistent RAG indexing

Migrations are ordered revisions. SQLite upgrades itself for portable
development; PostgreSQL production startup verifies the schema and does not
silently change it:

```bash
cd backend
python -m migrations upgrade
python -m migrations current
python -m rag.bootstrap                 # initial incremental snapshot
RAG_FULL_REINDEX_ENABLED=1 python -m rag.bootstrap --full
```

Revision 3 also adds ownership-scoped server-side assistant conversations,
explicit user memory, and retention audit records. Configure the finite
`ASSISTANT_*` retention and context settings in `.env.example`. The durable
scheduler enqueues `assistant.retention_purge` once per UTC day and the worker
tombstones expired records in bounded batches; this is logical deletion, not a
claim of cryptographic erasure.

The PostgreSQL image in Compose is `pgvector/pgvector:pg16`. The migration
enables the `vector` extension and creates an HNSW cosine index plus PostgreSQL
full-text indexes. A database role without extension permission fails clearly.
Rollback is forward-only for the retrieval migration: stop workers, restore a
database backup, or manually remove the retrieval tables after confirming no
jobs reference them; application data is not destructively downgraded.

The explicit bootstrap is a durable operation and must complete before
retrieval is ready. Scan imports and knowledge changes enqueue scoped
`rag.reindex` jobs; they reuse embeddings by content hash and provenance and
never rebuild the full corpus synchronously. SQLite uses a persistent,
portable fallback with bounded Python candidate scoring; it does not provide
pgvector HNSW performance or PostgreSQL multi-worker queue semantics.

### RAG evaluation and readiness evidence

#### Importing the CysekRAG corpus-derived benchmark

The CysekRAG question set can measure retrieval against a frozen CVE/CWE
corpus, but it is not a human-reviewed free-form answer benchmark. Convert it
without losing its source hashes or split assignments:

```powershell
cd backend
python -m rag.import_cysekrag_eval C:\path\to\eval_questions.jsonl `
  --split-manifest C:\path\to\eval_split.json `
  --output experiments\data\rag\cysekrag_corpus_derived.jsonl
```

The converter maps `CVE-…`, `CWE-…`, and `CAPEC-…` evidence IDs to the Watch
Fortress index form such as `cve:CVE-2021-44228`. It preserves the source
dataset and corpus hashes, labels each row `corpus_derived_not_human_reviewed`,
and leaves approved citation IDs empty. Use it to report retrieval metrics;
answer quality and citation correctness remain `NOT RUN` until a reviewer adds
those annotations. Verify that the imported evidence IDs exist in the active
Watch Fortress corpus before presenting a score.

Evaluation is retrieval-only by default and calls the same persistent
PostgreSQL/pgvector (or explicitly configured SQLite fallback) service,
metadata filters, reciprocal-rank fusion, and local reranker used by the
assistant. It never indexes the corpus or calls Groq unless answer mode is
explicitly selected:

```bash
cd backend
python -m rag.evaluation path/to/reviewed.jsonl --split development \
  --purpose development --output development-run.json
python -m rag.evaluation path/to/reviewed.jsonl --split held_out_test \
  --purpose final-held-out --output held-out-run.json
python -m rag.evaluation path/to/reviewed.jsonl --split development \
  --purpose development --answer-mode --output answer-run.json
```

Held-out runs accept one supplied configuration only; they do not search,
tune, or change configuration. Reports contain dataset provenance, the actual
index-run ID, active retrieval parameters, safe failure reasons, and
interpolated p50/p95 latency. Citation metrics remain NOT RUN unless generated
citations and reviewed annotations are both present. No reviewed dataset means
no quality claim.

Readiness `GET /api/observability/summary` performs a bounded database query,
checks the PostgreSQL vector extension and persisted index state, reads
persisted worker heartbeats with a stale threshold, inspects local model
cache/state without loading weights, reports Groq configuration/circuit state
without network access, and reports OTLP configuration. It never returns
credentials, prompts, evidence content, or connection strings.

PostgreSQL integration tests are opt-in and must use a disposable dedicated
database URL:

```bash
docker compose --profile postgres up -d postgres
$env:RAG_POSTGRES_TEST_URL="postgresql+psycopg://vuln:vuln@localhost:5432/vuln_platform_test"
cd backend
python -m pytest tests/test_postgres_integration.py -q
```

If `RAG_POSTGRES_TEST_URL` is unset, these tests are explicitly skipped and
SQLite unit-test results must not be interpreted as PostgreSQL verification.

Workers use leases, heartbeats, retry backoff, dead-letter transitions,
idempotency keys, safe cancellation checkpoints, and persisted progress
events. Scanner options are validated at the worker boundary and are not
logged.

### Reviewed RAG evaluation

The separate retrieval harness consumes operator-supplied reviewed JSONL rows
with `id`, `question`, and `gold_evidence_ids`; it never fabricates gold data.
Run it from `backend` with `python -m rag.evaluation path/to/reviewed.jsonl`.
The output includes dataset hash, configuration provenance, Recall@k, and MRR.
External generation, JEV, citation review, and answer correctness remain
`NOT RUN` unless their configured services and reviewed data are supplied.

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

## Observability and RAG evaluation

The application exposes Prometheus text at `/api/observability/metrics` and
authenticated readiness/evaluation APIs at `/api/observability/summary`,
`/api/observability/evaluations`, and
`/api/observability/evaluations/{run_id}`. These operational metrics do not
prove answer quality. Start the optional dashboard/trace profile with
`docker compose --profile observability up`; Prometheus is on `:9090` and
Jaeger is on `:16686`. OTLP export is disabled unless
`OTEL_EXPORTER_OTLP_ENDPOINT` is configured.

Reviewed retrieval datasets are JSONL. Each row requires `case_id`,
`question`, `rubric`, `gold_evidence_ids`, `approved_citation_ids`,
`category`, `safety_freshness`, `split` (`development` or `held_out_test`),
and provenance containing `reviewer` and `reviewed_at`. Run retrieval-only
evaluation with:

`python -m rag.evaluation path\\to\\reviewed.jsonl --split development --output run.json`

Runs are labelled honestly as `RUN` or `FAILED`; answer-generation metrics
remain `NOT RUN` unless a separately configured reviewed workflow records
them. Held-out rows must not be used to select thresholds or configurations.
