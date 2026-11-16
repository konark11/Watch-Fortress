from __future__ import annotations

import os
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from models.database import WorkerHeartbeat


def stale_threshold_seconds() -> int:
    try:
        configured = int(os.environ.get("WORKER_HEARTBEAT_STALE_SECONDS", "120"))
    except ValueError:
        configured = 120
    return max(1, configured)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def worker_readiness(db: Session) -> dict:
    threshold = stale_threshold_seconds()
    heartbeat = (
        db.query(WorkerHeartbeat)
        .order_by(WorkerHeartbeat.last_seen_at.desc())
        .first()
    )
    mode = "standalone" if db.bind.dialect.name == "postgresql" else "embedded"
    if heartbeat is None:
        return {
            "ready": False,
            "mode": mode,
            "reason": "worker_unavailable",
            "last_seen_at": None,
            "age_seconds": None,
            "stale_threshold_seconds": threshold,
        }

    age_seconds = max(0.0, (datetime.now(timezone.utc) - _as_utc(heartbeat.last_seen_at)).total_seconds())
    ready = age_seconds <= threshold
    return {
        "ready": ready,
        "mode": mode,
        "reason": "worker_ready" if ready else "worker_heartbeat_stale",
        "last_seen_at": heartbeat.last_seen_at,
        "age_seconds": round(age_seconds),
        "stale_threshold_seconds": threshold,
    }
