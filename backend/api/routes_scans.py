from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Request
from sqlalchemy.orm import Session

from models.database import (
    get_db, Scan, ScannerType, ScanStatus, User,
    BackgroundJob, BackgroundJobState, BackgroundJobEvent,
)
from auth.security import get_current_user, require_permission
from auth.audit import log_action
from api.schemas import ScanLaunchRequest
from scanners.orchestrator import get_progress, scanner_availability
from core.ingestion import ingest_scan_result
from jobs.repository import enqueue, request_cancel

router = APIRouter()


def _safe_scan_options(options: dict) -> dict:
    allowed = {
        "profile", "severity_profile", "tags", "timeout_seconds",
        "automatic_scan", "poll_interval_seconds", "script_name", "extra_args", "template_uuid",
    }
    return {
        key: value for key, value in options.items()
        if key in allowed and not any(
            marker in key.lower() for marker in ("secret", "password", "token", "api_key", "credential")
        )
    }


@router.get("/scanner-availability")
def scanner_status(_: User = Depends(get_current_user)):
    return scanner_availability()


@router.get("")
def list_scans(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    scans = db.query(Scan).order_by(Scan.id.desc()).limit(200).all()
    return {"scans": [
        {
            "id": s.id, "name": s.name, "scanner_type": s.scanner_type.value, "target": s.target,
            "status": s.status.value, "progress_pct": s.progress_pct, "started_at": s.started_at,
            "finished_at": s.finished_at, "created_by": s.created_by, "findings_count": s.findings_count,
            "error_message": s.error_message,
        }
        for s in scans
    ]}


@router.get("/{scan_id}/progress")
def scan_progress(scan_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    job = db.query(BackgroundJob).filter(
        BackgroundJob.scan_id == scan_id
    ).order_by(BackgroundJob.id.desc()).first()
    if job:
        return {
            "scan_id": scan_id, "status": scan.status.value, "job_id": job.public_id,
            "pct": job.progress_pct, "message": job.progress_message or "Queued",
            "job_state": job.state.value,
        }
    return {"scan_id": scan_id, "status": scan.status.value, **get_progress(scan_id)}


@router.post("/launch")
def launch_scan(
    payload: ScanLaunchRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("scan.launch")),
):
    try:
        scanner_type = ScannerType(payload.scanner_type)
    except ValueError:
        raise HTTPException(400, f"Invalid scanner_type. Must be one of {[s.value for s in ScannerType]}")

    scan = Scan(
        name=payload.name, scanner_type=scanner_type, target=payload.target,
        status=ScanStatus.PENDING, created_by=user.username,
    )
    db.add(scan)
    db.flush()
    job = enqueue(
        db, job_type="scan.execute",
        payload={"scan_id": scan.id, "scanner_type": scanner_type.value,
                 "target": payload.target, "options": _safe_scan_options(payload.options)},
        idempotency_key=f"scan-execute:{scan.id}",
        creator_user_id=user.id, creator_username=user.username, scan_id=scan.id,
    )
    db.commit()
    log_action(
        db, user, "scan.launch", target=f"scan:{scan.id}",
        details=f"{scanner_type.value} -> {payload.target}",
        ip_address=request.client.host if request.client else "",
    )
    return {"scan_id": scan.id, "job_id": job.public_id, "status": "queued"}


@router.post("/import")
async def import_scan(
    request: Request,
    scanner_type: str = Form(...),
    name: str = Form("Imported scan"),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("scan.launch")),
):
    try:
        st = ScannerType(scanner_type)
    except ValueError:
        raise HTTPException(400, f"Invalid scanner_type. Must be one of {[s.value for s in ScannerType]}")
    raw_bytes = await file.read()
    raw_text = raw_bytes.decode("utf-8", errors="ignore")
    scan = Scan(
        name=name, scanner_type=st, target=file.filename or "uploaded file",
        status=ScanStatus.COMPLETED, started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc), created_by=user.username,
    )
    db.add(scan)
    db.flush()
    summary = ingest_scan_result(db, scan, raw_text, file.filename or "")
    reindex_job = enqueue(
        db, job_type="rag.reindex", payload={"scan_id": scan.id},
        idempotency_key=f"rag-reindex:scan:{scan.id}",
        creator_user_id=user.id, creator_username=user.username, scan_id=scan.id,
    )
    db.commit()
    log_action(
        db, user, "scan.import", target=f"scan:{scan.id}",
        details=f"{scanner_type} file={file.filename}",
        ip_address=request.client.host if request.client else "",
    )
    return {"scan_id": scan.id, "reindex_job_id": reindex_job.public_id, **summary}


@router.post("/{scan_id}/cancel")
def cancel_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("scan.cancel")),
):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    job = db.query(BackgroundJob).filter(
        BackgroundJob.scan_id == scan_id,
        BackgroundJob.job_type == "scan.execute",
        BackgroundJob.state.in_([
            BackgroundJobState.QUEUED, BackgroundJobState.RUNNING,
            BackgroundJobState.RETRYING,
        ]),
    ).order_by(BackgroundJob.id.desc()).first()
    if job:
        request_cancel(db, job)
        scan.status = ScanStatus.CANCELLED
        scan.finished_at = datetime.now(timezone.utc)
        scan.error_message = "Scan cancellation requested."
        db.commit()
        status = "cancellation_requested"
    else:
        status = scan.status.value
        if scan.status in (ScanStatus.PENDING, ScanStatus.RUNNING):
            scan.status = ScanStatus.CANCELLED
            scan.finished_at = datetime.now(timezone.utc)
            scan.error_message = "Scan cancelled."
            db.commit()
            status = "cancelled"
    log_action(db, user, "scan.cancel", target=f"scan:{scan_id}")
    return {"ok": True, "status": status}


@router.get("/jobs/{public_id}")
def get_job(public_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    job = db.query(BackgroundJob).filter(BackgroundJob.public_id == public_id).first()
    if not job:
        raise HTTPException(404, "Job not found")
    if user.role.value != "administrator" and job.creator_user_id != user.id:
        raise HTTPException(403, "You cannot access this job")
    events = db.query(BackgroundJobEvent).filter(
        BackgroundJobEvent.job_id == job.id
    ).order_by(BackgroundJobEvent.id.desc()).limit(50).all()
    return {
        "job_id": job.public_id, "job_type": job.job_type, "state": job.state.value,
        "scan_id": job.scan_id, "progress_pct": job.progress_pct,
        "progress_message": job.progress_message, "error_code": job.error_code,
        "error_message": job.error_message,
        "events": [
            {"state": event.state.value, "progress_pct": event.progress_pct,
             "message": event.message, "timestamp": event.timestamp}
            for event in reversed(events)
        ],
    }


@router.post("/jobs/{public_id}/cancel")
def cancel_job(
    public_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("scan.cancel")),
):
    job = db.query(BackgroundJob).filter(BackgroundJob.public_id == public_id).first()
    if not job:
        raise HTTPException(404, "Job not found")
    if user.role.value != "administrator" and job.creator_user_id != user.id:
        raise HTTPException(403, "You cannot cancel this job")
    if job.state in (
        BackgroundJobState.COMPLETED, BackgroundJobState.FAILED,
        BackgroundJobState.DEAD_LETTER, BackgroundJobState.CANCELLED,
    ):
        raise HTTPException(409, "Job is no longer cancellable")
    request_cancel(db, job)
    log_action(db, user, "job.cancel.request", target=f"job:{job.public_id}")
    return {"job_id": job.public_id, "status": "cancellation_requested"}
