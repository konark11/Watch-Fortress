from __future__ import annotations

import argparse
import json
import logging
import os
import socket
import sys
import time
import uuid
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from models.database import (
    BackgroundJobState,
    Scan,
    ScanStatus,
    SessionLocal,
    WorkerHeartbeat,
    now_utc,
)
from core.ingestion import ingest_scan_result
from jobs.repository import (
    add_event,
    claim_next,
    complete,
    fail_or_retry,
    heartbeat,
    recover_expired,
    utcnow,
    update_progress,
)
from scanners.orchestrator import run_scan
from scanners.base import ScannerCancelled
from observability import extract_job_context, span, safe_log, observe, job_duration, scan_duration, indexing_duration, retention_duration

logger = logging.getLogger("watch_fortress.worker")


def _record_worker_heartbeat(db, worker_id: str) -> None:
    heartbeat = db.query(WorkerHeartbeat).filter(WorkerHeartbeat.worker_id == worker_id).first()
    if heartbeat:
        heartbeat.last_seen_at = now_utc()
        heartbeat.updated_at = now_utc()
        heartbeat.status = "alive"
    else:
        db.add(WorkerHeartbeat(worker_id=worker_id, last_seen_at=now_utc(), updated_at=now_utc()))
    db.commit()


class JobCancelled(Exception):
    pass


def _safe_payload(job) -> dict:
    payload = job.payload or {}
    if not isinstance(payload, dict):
        raise ValueError("job_payload_invalid")
    if job.job_type == "scan.execute":
        required = ("scan_id", "scanner_type", "target")
        if any(not payload.get(key) for key in required):
            raise ValueError("scan_payload_incomplete")
        if len(str(payload["target"])) > 500 or len(str(payload["scanner_type"])) > 32:
            raise ValueError("scan_payload_invalid")
        options = payload.get("options", {})
        if not isinstance(options, dict) or any(
            any(marker in str(key).lower() for marker in ("secret", "password", "token", "api_key", "credential"))
            for key in options
        ):
            raise ValueError("scan_options_invalid")
        payload["options"] = {
            key: value for key, value in options.items()
            if key in {
                "profile", "severity_profile", "tags", "timeout_seconds",
                "automatic_scan",
                "poll_interval_seconds", "script_name", "extra_args", "template_uuid",
                "concurrency", "rate_limit", "resolve_dns", "timeout",
            }
        }
    elif job.job_type == "report.generate":
        if payload.get("report_type") not in {"executive", "technical", "compliance"}:
            raise ValueError("report_type_invalid")
        if payload.get("report_format") not in {"pdf", "html", "docx", "json"}:
            raise ValueError("report_format_invalid")
    elif job.job_type == "rag.reindex":
        allowed = {"source_type", "source_id", "scan_id", "document_id", "full"}
        if any(key not in allowed for key in payload):
            raise ValueError("rag_reindex_payload_invalid")
        if payload.get("full") and os.environ.get("RAG_FULL_REINDEX_ENABLED", "0").lower() not in {"1", "true", "yes"}:
            raise ValueError("rag_full_reindex_disabled")
    elif job.job_type == "assistant.retention_purge":
        if set(payload) - {"batch_size"}:
            raise ValueError("retention_payload_invalid")
        if int(payload.get("batch_size", 100)) < 1:
            raise ValueError("retention_batch_invalid")
    return payload


def _check_cancelled(db, job) -> None:
    db.refresh(job)
    if job.cancellation_requested_at:
        raise JobCancelled()


def _is_cancel_requested(db, job) -> bool:
    db.refresh(job)
    db.refresh(db.get(Scan, job.scan_id)) if job.scan_id else None
    return bool(job.cancellation_requested_at)


def _execute_scan(db, job, payload: dict, worker_id: str) -> dict:
    scan = db.get(Scan, int(payload["scan_id"]))
    if not scan:
        raise ValueError("scan_not_found")
    if scan.status == ScanStatus.CANCELLED:
        raise JobCancelled()
    scan.status = ScanStatus.RUNNING
    scan.started_at = scan.started_at or utcnow()
    db.commit()
    last_persisted = [0, 0.0]

    def progress(pct: int, message: str, findings_count: Optional[int] = None) -> None:
        _check_cancelled(db, job)
        now = time.monotonic()
        findings_changed = findings_count is not None and findings_count != scan.findings_count
        if pct < 100 and pct - last_persisted[0] < 5 and now - last_persisted[1] < 2 and not findings_changed:
            return
        last_persisted[:] = [pct, now]
        heartbeat(db, job, worker_id, int(os.environ.get("JOB_LEASE_SECONDS", "300")))
        scan.progress_pct = max(0, min(100, pct))
        if findings_count is not None:
            scan.findings_count = findings_count
        db.commit()
        update_progress(db, job, pct, message)

    scan_options = dict(payload.get("options") if isinstance(payload.get("options"), dict) else {})
    scan_options["_cancel_check"] = lambda: _is_cancel_requested(db, job)
    result = run_scan(
        scan.id,
        str(payload["scanner_type"]),
        str(payload["target"]),
        scan_options,
        progress,
    )
    _check_cancelled(db, job)
    raw_output = result.get("raw_output", "")
    output_dir = os.path.join(os.path.dirname(__file__), "..", "data", "job_outputs")
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.abspath(os.path.join(output_dir, f"{job.public_id}.txt"))
    with open(output_path, "w", encoding="utf-8") as output_file:
        output_file.write(str(raw_output))
    scan.raw_output_path = output_path
    scan.progress_pct = 95
    scan.status = ScanStatus.RUNNING
    scan.finished_at = None
    db.commit()
    from jobs.repository import enqueue
    ingest_job = enqueue(
        db,
        job_type="scan.ingest",
        payload={"scan_id": scan.id, "raw_output_path": output_path, "filename": result.get("filename", "")},
        idempotency_key=f"scan-ingest:{scan.id}",
        creator_user_id=job.creator_user_id,
        creator_username=job.creator_username,
        scan_id=scan.id,
        correlation_id=job.correlation_id,
    )
    db.commit()
    return {"scan_id": scan.id, "ingest_job_id": ingest_job.public_id}


def _ingest_scan(db, job, payload: dict) -> dict:
    scan = db.get(Scan, int(payload.get("scan_id", 0)))
    path = payload.get("raw_output_path")
    if not scan or not path or not os.path.isfile(path):
        raise ValueError("scan_output_not_found")
    with open(path, encoding="utf-8", errors="replace") as input_file:
        raw_output = input_file.read()
    summary = ingest_scan_result(db, scan, raw_output, str(payload.get("filename", "")))
    scan.progress_pct = 100
    scan.status = ScanStatus.COMPLETED
    scan.finished_at = utcnow()
    from jobs.repository import enqueue
    reindex_job = enqueue(
        db,
        job_type="rag.reindex",
        payload={"scan_id": scan.id},
        idempotency_key=f"rag-reindex:scan:{scan.id}",
        creator_user_id=job.creator_user_id,
        creator_username=job.creator_username,
        scan_id=scan.id,
        correlation_id=job.correlation_id,
    )
    db.commit()
    try:
        os.remove(path)
    except OSError:
        logger.warning("job output cleanup failed job_id=%s", job.public_id)
    return {"ingested": summary, "reindex_job_id": reindex_job.public_id}


def _handle(db, job, worker_id: str) -> dict:
    payload = _safe_payload(job)
    if job.job_type == "scan.execute":
        return _execute_scan(db, job, payload, worker_id)
    if job.job_type == "scan.ingest":
        return _ingest_scan(db, job, payload)
    if job.job_type == "rag.reindex":
        from rag.indexing.service import index_incremental
        scope = {
            key: payload[key] for key in ("source_type", "source_id", "scan_id", "document_id")
            if payload.get(key) is not None
        } or None
        return index_incremental(db, scope=scope, full=bool(payload.get("full")))
    if job.job_type == "assistant.retention_purge":
        from assistant.retention import purge_expired
        batch_size = int(payload.get("batch_size", 100))
        return purge_expired(db, batch_size=max(1, min(batch_size, 1000)))
    if job.job_type == "report.generate":
        from reports.generator import generate_report
        report = generate_report(
            db, str(payload["report_type"]), str(payload["report_format"]),
            scope_asset_ids=payload.get("scope_asset_ids"),
            compliance_framework=payload.get("compliance_framework"),
            generated_by=job.creator_username or "system",
        )
        return {"report_id": report.id}
    raise ValueError("unsupported_job_type")


def run_once(worker_id: str | None = None) -> bool:
    worker_id = worker_id or f"{socket.gethostname()}-{uuid.uuid4()}"
    db = SessionLocal()
    try:
        _record_worker_heartbeat(db, worker_id)
        recover_expired(db)
        job = claim_next(db, worker_id, int(os.environ.get("JOB_LEASE_SECONDS", "300")))
        if not job:
            return False
        extract_job_context({"correlation_id": job.correlation_id})
        logger.info("job claimed job_id=%s job_type=%s attempt=%s correlation_id=%s", job.public_id, job.job_type, job.attempt_count, job.correlation_id)
        try:
            started = time.monotonic()
            with span("job.execute", job_type=job.job_type, attempt=job.attempt_count):
                result = _handle(db, job, worker_id)
            complete(db, job, result)
            observe(job_duration, time.monotonic() - started, job.job_type, "completed")
            if job.job_type == "scan.execute":
                observe(scan_duration, time.monotonic() - started, "success")
            elif job.job_type == "rag.reindex":
                observe(indexing_duration, time.monotonic() - started)
            elif job.job_type == "assistant.retention_purge":
                observe(retention_duration, time.monotonic() - started)
        except (JobCancelled, ScannerCancelled):
            scan = db.get(Scan, job.scan_id) if job.scan_id else None
            if scan:
                scan.status = ScanStatus.CANCELLED
                scan.finished_at = utcnow()
            job.state = BackgroundJobState.CANCELLED
            job.completed_at = utcnow()
            add_event(db, job, "cancelled", "Cancellation completed at a safe checkpoint")
            db.commit()
        except Exception as exc:
            db.rollback()
            job = db.get(type(job), job.id)
            if job.job_type in {"scan.execute", "scan.ingest"} and job.attempt_count >= job.max_attempts:
                scan = db.get(Scan, job.scan_id) if job.scan_id else None
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.error_message = str(exc)[:500] if str(exc) else f"{type(exc).__name__} while processing job"
                    scan.finished_at = utcnow()
            fail_or_retry(db, job, "worker_failure", f"{type(exc).__name__}: {str(exc)[:400]}" if str(exc) else f"{type(exc).__name__} while processing job")
            observe(job_duration, time.monotonic() - started, job.job_type, "failed")
            logger.error(
                "job failed job_id=%s job_type=%s attempt=%s correlation_id=%s",
                job.public_id, job.job_type, job.attempt_count, job.correlation_id,
            )
        return True
    finally:
        db.close()


def main() -> None:
    if os.environ.get("JOB_WORKER_ENABLED", "1").lower() in {"0", "false", "no"}:
        logger.info("worker disabled by configuration")
        return
    parser = argparse.ArgumentParser(description="Run Watch Fortress durable jobs")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    if args.once:
        run_once()
        return
    poll = float(os.environ.get("JOB_POLL_INTERVAL_SECONDS", "2"))
    while True:
        if not run_once():
            time.sleep(poll)


if __name__ == "__main__":
    main()
