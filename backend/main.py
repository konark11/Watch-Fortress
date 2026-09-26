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

sys.path.insert(0, os.path.dirname(__file__))

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from models.database import init_db
from scheduling.scheduler import start_scheduler, load_all_schedules

BASE_DIR = os.path.dirname(__file__)
FRONTEND_DIST = os.path.join(BASE_DIR, "..", "frontend", "dist")

app = FastAPI(
    title="Watch Fortress",
    description="Integrates Nmap, OpenVAS, Nessus, and Nuclei into one dashboard with correlation, risk scoring, RAG-powered assistance, and reporting.",
    version="1.0.0",
)

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
    routes_audit, routes_ws, routes_threat_intel, routes_exploitdb,
)

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
