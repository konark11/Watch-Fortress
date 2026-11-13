from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models.database import Base, BackgroundJobState
from jobs.repository import (
    claim_next,
    complete,
    enqueue,
    fail_or_retry,
    request_cancel,
)


def session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def test_enqueue_is_idempotent_and_claim_persists():
    db = session()
    first = enqueue(db, job_type="rag.reindex", payload={}, idempotency_key="same")
    second = enqueue(db, job_type="rag.reindex", payload={}, idempotency_key="same")
    db.commit()
    assert first.id == second.id
    claimed = claim_next(db, "worker-a", 60)
    assert claimed and claimed.state == BackgroundJobState.RUNNING
    complete(db, claimed, {"ok": True})
    assert claimed.state == BackgroundJobState.COMPLETED


def test_cancel_before_execution_and_dead_letter():
    db = session()
    job = enqueue(db, job_type="scan.execute", payload={"scan_id": 1}, idempotency_key="scan-1", max_attempts=1)
    db.commit()
    request_cancel(db, job)
    assert job.state == BackgroundJobState.CANCELLED

    retryable = enqueue(db, job_type="scan.execute", payload={"scan_id": 2}, idempotency_key="scan-2", max_attempts=1)
    db.commit()
    claimed = claim_next(db, "worker-a", 60)
    assert claimed and claimed.id == retryable.id
    fail_or_retry(db, claimed, "worker_failure", "safe summary")
    assert claimed.state == BackgroundJobState.DEAD_LETTER
    assert claimed.error_message == "safe summary"
