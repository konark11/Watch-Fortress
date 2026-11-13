from __future__ import annotations

import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import func, text

from auth.security import get_current_user
from models.database import BackgroundJob, BackgroundJobState, WorkerHeartbeat, User, get_db
from observability import metrics_payload
from rag.embeddings import active_embedding_metadata
from rag.indexing.repository import latest_run
from rag.llm_providers import provider_status
from rag.retrieval.service import backend_name, capability
from rag.reranker import status as reranker_status
from rag.settings import EMBEDDING_MODEL, RERANKER_MODEL

router = APIRouter()


@router.get("/metrics", include_in_schema=False)
def metrics():
    body, content_type = metrics_payload()
    return Response(content=body, media_type=content_type)


@router.get("/summary")
def summary(db=Depends(get_db), _: User = Depends(get_current_user)):
    def probe_db():
        started = time.monotonic()
        try:
            db.execute(text("SELECT 1")).scalar_one()
            return {"status": "healthy" if time.monotonic() - started <= 2 else "degraded"}
        except Exception:
            return {"status": "unavailable"}

    database = probe_db()
    pg = {"status": "unconfigured"}
    if db.bind.dialect.name == "postgresql":
        try:
            present = bool(db.execute(text("SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname='vector')")).scalar())
            pg = {"status": "healthy" if present else "unavailable", "extension_present": present}
        except Exception:
            pg = {"status": "unavailable", "extension_present": False}
    run = latest_run(db)
    index = {
        "status": "not_yet_checked" if run is None else ("healthy" if run["state"] == "ready" else "degraded"),
        "backend": backend_name(db),
        "run_id": run["public_id"] if run else None,
        "state": run["state"] if run else None,
    }
    if db.bind.dialect.name == "postgresql":
        try:
            index["capability"] = capability(db)
        except Exception:
            index["status"] = "unavailable"
    stale_seconds = max(1, int(os.environ.get("WORKER_HEARTBEAT_STALE_SECONDS", "120")))
    heartbeat = db.query(WorkerHeartbeat).order_by(WorkerHeartbeat.last_seen_at.desc()).first()
    if heartbeat is None:
        worker = {"status": "not_yet_checked", "last_seen_at": None}
    else:
        age = (datetime.now(timezone.utc) - heartbeat.last_seen_at.replace(tzinfo=timezone.utc)).total_seconds()
        worker = {"status": "healthy" if age <= stale_seconds else "degraded", "last_seen_at": heartbeat.last_seen_at, "age_seconds": round(age), "stale_threshold_seconds": stale_seconds}
    embedding = active_embedding_metadata()
    embedding_status = "degraded" if embedding.get("implementation") == "deterministic-token-hash" else "healthy"
    reranker = reranker_status()
    reranker_status_value = "healthy" if reranker.get("configured") else "degraded"
    provider = provider_status()
    queued = db.query(BackgroundJob).filter(BackgroundJob.state.in_([BackgroundJobState.QUEUED, BackgroundJobState.RETRYING])).count()
    running = db.query(BackgroundJob).filter(BackgroundJob.state == BackgroundJobState.RUNNING).count()
    return {
        "status": "healthy" if database["status"] == "healthy" and index["status"] == "healthy" else "degraded",
        "database": database,
        "pgvector": pg,
        "retrieval_index": index,
        "worker": {**worker, "running_jobs": running, "queued_jobs": queued},
        "local_models": {
            "status": "healthy" if embedding_status == "healthy" and reranker_status_value == "healthy" else "degraded",
            "embedding": {"status": embedding_status, "model": embedding.get("model", EMBEDDING_MODEL), "loaded": embedding.get("implementation") != "deterministic-token-hash", "probe": "cache/state only; no model load"},
            "reranker": {"status": reranker_status_value, "model": reranker.get("model", RERANKER_MODEL), "configured": bool(reranker.get("configured")), "provider": reranker.get("provider"), "probe": "configuration only; no network request"},
        },
        "groq": {"status": "healthy" if provider.get("status") in {"configured", "selected"} and provider.get("circuit") != "open" else ("unconfigured" if provider.get("status") != "configured" else "degraded"), "provider": provider.get("provider"), "model": provider.get("model"), "circuit": provider.get("circuit")},
        "otlp": {"status": "healthy" if os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT") else "unconfigured"},
        "metrics_quality": "Operational metrics do not prove answer quality.",
    }


def _run_files():
    default_root = Path(__file__).resolve().parents[1] / "experiments" / "results"
    root = Path(os.environ.get("RAG_EVALUATION_RESULTS_DIR", str(default_root)))
    return sorted(root.glob("*.json")) if root.exists() else []


@router.get("/evaluations")
def evaluations(_: User = Depends(get_current_user)):
    runs = []
    for path in _run_files():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            runs.append({
                "run_id": path.stem, "status": data.get("status", "FAILED"),
                "purpose": data.get("run_purpose"), "split": data.get("dataset", {}).get("split"),
                "rows": data.get("dataset", {}).get("rows"), "dataset_sha256": data.get("dataset", {}).get("sha256"),
                "backend": data.get("provenance", {}).get("retrieval_backend"),
                "index_run_id": data.get("provenance", {}).get("index_run_id"),
                "models": {"embedding": data.get("provenance", {}).get("embedding_model"), "reranker": data.get("provenance", {}).get("reranker_model"), "generation": data.get("provenance", {}).get("generation")},
                "parameters": data.get("provenance", {}).get("retrieval_parameters"),
                "metrics": data.get("metrics"), "failures": len(data.get("failures", [])),
                "fallback_count": data.get("fallback_count"), "timestamp": data.get("provenance", {}).get("timestamp"),
            })
        except (OSError, ValueError):
            runs.append({"run_id": path.stem, "status": "FAILED"})
    return {"runs": runs}


@router.get("/evaluations/{run_id}")
def evaluation(run_id: str, _: User = Depends(get_current_user)):
    if Path(run_id).name != run_id or not run_id.endswith(".json"):
        run_id = f"{run_id}.json"
    default_root = Path(__file__).resolve().parents[1] / "experiments" / "results"
    path = Path(os.environ.get("RAG_EVALUATION_RESULTS_DIR", str(default_root))) / run_id
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Evaluation run not found")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=500, detail="Evaluation run is unreadable") from exc
    data.pop("cases", None)
    return data
