from __future__ import annotations

import os
import random
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import case, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from models.database import (
    BackgroundJob,
    BackgroundJobEvent,
    BackgroundJobState,
    WorkerHeartbeat,
)
from observability import correlation_id as active_correlation_id, increment, job_events, span


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def is_postgres() -> bool:
    return os.environ.get("VULN_DATABASE_URL", "").startswith(("postgresql://", "postgresql+"))


def enqueue(
    db: Session,
    *,
    job_type: str,
    payload: dict,
    idempotency_key: str,
    creator_user_id: int | None = None,
    creator_username: str | None = None,
    scan_id: int | None = None,
    correlation_id: str | None = None,
    max_attempts: int = 3,
) -> BackgroundJob:
    existing = (
        db.query(BackgroundJob)
        .filter(
            BackgroundJob.job_type == job_type,
            BackgroundJob.idempotency_key == idempotency_key,
        )
        .first()
    )
    if existing:
        return existing
    try:
        configured_attempts = int(os.environ.get("JOB_RETRY_MAX_ATTEMPTS", str(max_attempts)))
    except ValueError:
        configured_attempts = max_attempts
    job = BackgroundJob(
        job_type=job_type,
        payload=payload,
        idempotency_key=idempotency_key,
        creator_user_id=creator_user_id,
        creator_username=creator_username,
        scan_id=scan_id,
        correlation_id=correlation_id or active_correlation_id.get() or str(uuid.uuid4()),
        max_attempts=max(1, min(configured_attempts, 10)),
        available_at=utcnow(),
        progress_message="Queued",
    )
    db.add(job)
    try:
        with db.begin_nested():
            db.flush()
    except IntegrityError:
        existing = (
            db.query(BackgroundJob)
            .filter(
                BackgroundJob.job_type == job_type,
                BackgroundJob.idempotency_key == idempotency_key,
            )
            .first()
        )
        if existing:
            return existing
        raise
    add_event(db, job, "queued", "Queued")
    increment(job_events, job.job_type, "queued")
    return job


def add_event(
    db: Session,
    job: BackgroundJob,
    state: str | BackgroundJobState,
    message: str,
    *,
    progress_pct: int | None = None,
    details: dict | None = None,
) -> None:
    db.add(BackgroundJobEvent(
        job_id=job.id,
        state=BackgroundJobState(state),
        progress_pct=progress_pct,
        message=message[:500],
        details=details,
        correlation_id=job.correlation_id,
    ))
    increment(job_events, job.job_type, str(state))


def update_progress(db: Session, job: BackgroundJob, pct: int, message: str) -> None:
    pct = max(0, min(100, int(pct)))
    job.progress_pct = pct
    job.progress_message = message[:500]
    job.updated_at = utcnow()
    add_event(db, job, job.state, message, progress_pct=pct)
    db.commit()


def claim_next(db: Session, worker_id: str, lease_seconds: int) -> BackgroundJob | None:
    now = utcnow()
    query = (
        db.query(BackgroundJob)
        .filter(
            BackgroundJob.state.in_([BackgroundJobState.QUEUED, BackgroundJobState.RETRYING]),
            BackgroundJob.available_at <= now,
            or_(BackgroundJob.lease_expires_at.is_(None), BackgroundJob.lease_expires_at <= now),
        )
        .order_by(
            case((BackgroundJob.job_type == "scan.execute", 0), else_=1),
            BackgroundJob.created_at,
            BackgroundJob.id,
        )
        .with_for_update(skip_locked=is_postgres())
    )
    job = query.first()
    if not job:
        return None
    active_correlation_id.set(job.correlation_id)
    job.state = BackgroundJobState.RUNNING
    job.attempt_count += 1
    job.started_at = job.started_at or now
    job.lease_owner = worker_id
    job.lease_expires_at = now + timedelta(seconds=lease_seconds)
    job.heartbeat_at = now
    add_event(db, job, "running", "Worker claimed job", progress_pct=job.progress_pct)
    db.commit()
    return job


def heartbeat(db: Session, job: BackgroundJob, worker_id: str, lease_seconds: int) -> None:
    if job.lease_owner != worker_id:
        raise RuntimeError("Job lease is no longer owned by this worker")
    now = utcnow()
    job.heartbeat_at = now
    job.lease_expires_at = now + timedelta(seconds=lease_seconds)
    worker = db.query(WorkerHeartbeat).filter(WorkerHeartbeat.worker_id == worker_id).first()
    if worker:
        worker.last_seen_at = now
        worker.updated_at = now
    db.commit()


def request_cancel(db: Session, job: BackgroundJob) -> None:
    job.cancellation_requested_at = utcnow()
    if job.state in (BackgroundJobState.QUEUED, BackgroundJobState.RETRYING):
        job.state = BackgroundJobState.CANCELLED
        job.completed_at = utcnow()
        add_event(db, job, "cancelled", "Cancellation requested before execution")
    else:
        add_event(db, job, job.state, "Cancellation requested; worker will stop at its next safe checkpoint")
    db.commit()


def complete(db: Session, job: BackgroundJob, result_summary: dict | None = None) -> None:
    job.state = BackgroundJobState.COMPLETED
    job.result_summary = result_summary
    job.progress_pct = 100
    job.progress_message = "Completed"
    job.completed_at = utcnow()
    job.lease_owner = None
    job.lease_expires_at = None
    add_event(db, job, "completed", "Completed", progress_pct=100)
    db.commit()


def fail_or_retry(db: Session, job: BackgroundJob, code: str, message: str) -> None:
    if job.attempt_count < job.max_attempts:
        delay = min(300, 2 ** max(0, job.attempt_count - 1)) + random.uniform(0, 1)
        job.state = BackgroundJobState.RETRYING
        job.available_at = utcnow() + timedelta(seconds=delay)
        job.error_code = code[:80]
        job.error_message = message[:500]
        job.lease_owner = None
        job.lease_expires_at = None
        add_event(db, job, "retrying", "Retry scheduled", details={"error_code": job.error_code})
    else:
        job.state = BackgroundJobState.DEAD_LETTER
        job.error_code = code[:80]
        job.error_message = message[:500]
        job.completed_at = utcnow()
        job.lease_owner = None
        job.lease_expires_at = None
        add_event(db, job, "dead_letter", "Moved to dead letter", details={"error_code": job.error_code})
    db.commit()


def recover_expired(db: Session) -> int:
    now = utcnow()
    jobs = (
        db.query(BackgroundJob)
        .filter(
            BackgroundJob.state == BackgroundJobState.RUNNING,
            BackgroundJob.lease_expires_at < now,
        )
        .all()
    )
    for job in jobs:
        fail_or_retry(db, job, "worker_lease_expired", "Worker lease expired; job recovered")
    return len(jobs)
