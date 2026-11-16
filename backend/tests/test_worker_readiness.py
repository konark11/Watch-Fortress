from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette.requests import Request

from api.routes_scans import launch_scan
from api.schemas import ScanLaunchRequest
from jobs.readiness import worker_readiness
from models.database import (
    BackgroundJob,
    Base,
    Scan,
    User,
    WorkerHeartbeat,
)


def session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def test_fresh_worker_heartbeat_is_ready(monkeypatch):
    db = session()
    monkeypatch.setenv("WORKER_HEARTBEAT_STALE_SECONDS", "120")
    db.add(WorkerHeartbeat(
        worker_id="worker-a",
        last_seen_at=datetime.now(timezone.utc),
        status="alive",
    ))
    db.commit()

    result = worker_readiness(db)

    assert result["ready"] is True
    assert result["reason"] == "worker_ready"
    assert result["mode"] == "embedded"


def test_missing_worker_heartbeat_is_not_ready():
    result = worker_readiness(session())

    assert result["ready"] is False
    assert result["reason"] == "worker_unavailable"
    assert result["last_seen_at"] is None


def test_stale_worker_heartbeat_is_not_ready(monkeypatch):
    db = session()
    monkeypatch.setenv("WORKER_HEARTBEAT_STALE_SECONDS", "30")
    db.add(WorkerHeartbeat(
        worker_id="worker-a",
        last_seen_at=datetime.now(timezone.utc) - timedelta(seconds=31),
        status="alive",
    ))
    db.commit()

    result = worker_readiness(db)

    assert result["ready"] is False
    assert result["reason"] == "worker_heartbeat_stale"
    assert result["age_seconds"] >= 31


def _launch_request() -> Request:
    return Request({
        "type": "http",
        "method": "POST",
        "path": "/api/scans/launch",
        "headers": [],
        "client": ("127.0.0.1", 1234),
        "server": ("testserver", 80),
        "scheme": "http",
    })


def _payload() -> ScanLaunchRequest:
    return ScanLaunchRequest(
        name="Test scan",
        scanner_type="nmap",
        target="127.0.0.1",
        options={},
    )


def test_launch_without_ready_worker_creates_no_records():
    db = session()
    user = User(id=1, username="analyst")

    with pytest.raises(HTTPException) as raised:
        launch_scan(_payload(), _launch_request(), db, user)

    assert raised.value.status_code == 503
    assert db.query(Scan).count() == 0
    assert db.query(BackgroundJob).count() == 0


def test_launch_with_fresh_worker_enqueues_scan():
    db = session()
    user = User(id=1, username="analyst")
    db.add(WorkerHeartbeat(
        worker_id="worker-a",
        last_seen_at=datetime.now(timezone.utc),
        status="alive",
    ))
    db.commit()

    result = launch_scan(_payload(), _launch_request(), db, user)

    assert result["status"] == "queued"
    assert db.query(Scan).count() == 1
    assert db.query(BackgroundJob).count() == 1
