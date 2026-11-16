"""
Watch Fortress - backend entrypoint.

Run:
    uvicorn main:app --host 0.0.0.0 --port 8000

First-run setup: POST /api/auth/bootstrap-admin with a username/password
to create the initial administrator account (only works while the users
table is empty), then log in via /api/auth/login to get a bearer token.
"""
from __future__ import annotations
import os
import sys
import logging
from contextlib import asynccontextmanager

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


def _load_local_env() -> None:
    """Load the repository .env for non-Docker development.

    Production deployments should continue to provide environment variables
    through the process manager or container runtime.
    """
    env_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".env"))
    if not os.path.isfile(env_path):
        return
    with open(env_path, encoding="utf-8") as env_file:
        for raw_line in env_file:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip("\"'")
            if key and not os.environ.get(key):
                os.environ[key] = value


_load_local_env()

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from models.database import init_db
from scheduling.scheduler import start_scheduler, load_all_schedules
from observability import configure, set_correlation, span, http_requests, http_errors, http_duration, increment, observe

BASE_DIR = os.path.dirname(__file__)
FRONTEND_DIST = os.path.join(BASE_DIR, "..", "frontend", "dist")
logger = logging.getLogger(__name__)


def _preload_embeddings_enabled() -> bool:
    return os.environ.get("RAG_PRELOAD_EMBEDDINGS", "true").strip().lower() in {"1", "true", "yes"}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    from knowledge.updater import seed_reference_playbooks
    from workers.embedded import start as start_embedded_worker, stop as stop_embedded_worker

    seeded_count = seed_reference_playbooks()
    if seeded_count:
        logger.info("seeded %s reference knowledge-base documents", seeded_count)

    if _preload_embeddings_enabled():
        from rag.embeddings import warmup_embeddings
        try:
            result = warmup_embeddings()
            logger.info(
                "rag embeddings preloaded: duration_ms=%s metadata=%s",
                result["duration_ms"],
                result["embedding"],
            )
        except Exception:
            logger.exception("rag embedding preload failed; deterministic fallback remains available")
    embedded_worker = start_embedded_worker()
    try:
        yield
    finally:
        stop_embedded_worker(embedded_worker)

app = FastAPI(
    title="Watch Fortress",
    description="Integrates Nmap, OpenVAS, Nessus, and Nuclei into one dashboard with correlation, risk scoring, RAG-powered assistance, and reporting.",
    version="1.0.0",
    lifespan=lifespan,
)
configure()


@app.middleware("http")
async def observability_middleware(request: Request, call_next):
    route = request.url.path
    correlation = set_correlation(request.headers.get("x-correlation-id"))
    started = __import__("time").monotonic()
    status_code = 500
    with span("http.request", route=route, http_method=request.method):
        try:
            response = await call_next(request)
            status_code = response.status_code
            response.headers["X-Correlation-ID"] = correlation
            return response
        finally:
            elapsed = __import__("time").monotonic() - started
            status_class = f"{status_code // 100}xx"
            increment(http_requests, route, status_class)
            if status_code >= 400:
                increment(http_errors, route, status_class)
            observe(http_duration, elapsed, route)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

init_db()
start_scheduler()
load_all_schedules()

from api import (  # noqa: E402
    routes_auth, routes_users, routes_assets, routes_scans, routes_vulnerabilities,
    routes_dashboard, routes_rag, routes_reports, routes_knowledge, routes_schedules,
    routes_audit, routes_ws, routes_threat_intel, routes_exploitdb, routes_research,
    routes_observability,
)
from experiments.api import router as experiment_router  # noqa: E402

app.include_router(routes_auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(routes_users.router, prefix="/api/users", tags=["users"])
app.include_router(routes_assets.router, prefix="/api/assets", tags=["assets"])
app.include_router(routes_scans.router, prefix="/api/scans", tags=["scans"])
app.include_router(routes_vulnerabilities.router, prefix="/api/vulnerabilities", tags=["vulnerabilities"])
app.include_router(routes_dashboard.router, prefix="/api/dashboard", tags=["dashboard"])
app.include_router(routes_rag.router, prefix="/api/assistant", tags=["assistant"])
app.include_router(routes_reports.router, prefix="/api/reports", tags=["reports"])
app.include_router(routes_knowledge.router, prefix="/api/knowledge", tags=["knowledge"])
app.include_router(routes_schedules.router, prefix="/api/schedules", tags=["schedules"])
app.include_router(routes_audit.router, prefix="/api/audit", tags=["audit"])
app.include_router(routes_threat_intel.router, prefix="/api/threat-intel", tags=["threat-intel"])
app.include_router(routes_exploitdb.router, prefix="/api/exploit-db", tags=["exploit-db"])
app.include_router(routes_research.router, prefix="/api/research", tags=["research"])
app.include_router(experiment_router, prefix="/api/research-lab", tags=["research-lab"])
app.include_router(routes_observability.router, prefix="/api/observability", tags=["observability"])
app.include_router(routes_ws.router, tags=["websocket"])


@app.get("/api/health")
def health():
    from models.database import SessionLocal, User
    from scanners.orchestrator import scanner_availability
    db = SessionLocal()
    try:
        needs_bootstrap = db.query(User).count() == 0
    finally:
        db.close()
    return {
        "status": "ok",
        "needs_bootstrap_admin": needs_bootstrap,
        "scanner_availability": scanner_availability(),
    }


# --- Serve built frontend (React/Vite production build) ---
if os.path.isdir(FRONTEND_DIST):
    app.mount("/assets", StaticFiles(directory=os.path.join(FRONTEND_DIST, "assets")), name="assets")

    @app.get("/{full_path:path}")
    def spa_catch_all(full_path: str):
        # Client-side routed SPA: any non-API path serves index.html and
        # React Router takes over from there.
        return FileResponse(os.path.join(FRONTEND_DIST, "index.html"))
