from __future__ import annotations
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Request
from sqlalchemy.orm import Session

from models.database import get_db, Scan, ScannerType, ScanStatus, User, SessionLocal
from auth.security import get_current_user, require_permission
from auth.audit import log_action
from api.schemas import ScanLaunchRequest
from scanners.orchestrator import launch_scan_background, get_progress, scanner_availability
from core.ingestion import ingest_scan_result

router = APIRouter()


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
    live = get_progress(scan_id)
    return {"scan_id": scan_id, "status": scan.status.value, **live}


@router.post("/launch")
def launch_scan(payload: ScanLaunchRequest, request: Request, db: Session = Depends(get_db), user: User = Depends(require_permission("scan.launch"))):
    try:
        scanner_type = ScannerType(payload.scanner_type)
    except ValueError:
        raise HTTPException(400, f"Invalid scanner_type. Must be one of {[s.value for s in ScannerType]}")

    scan = Scan(
        name=payload.name, scanner_type=scanner_type, target=payload.target,
        status=ScanStatus.RUNNING, started_at=datetime.now(timezone.utc), created_by=user.username,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    def on_complete(scan_id: int, result: dict | None, error: str | None):
        inner_db = SessionLocal()
        try:
            s = inner_db.get(Scan, scan_id)
            if error:
                s.status = ScanStatus.FAILED
                s.error_message = error
            else:
                s.status = ScanStatus.COMPLETED
                summary = ingest_scan_result(inner_db, s, result["raw_output"], result.get("filename", ""))
                s.error_message = None
            s.finished_at = datetime.now(timezone.utc)
            inner_db.commit()
        finally:
            inner_db.close()

    launch_scan_background(scan.id, scanner_type.value, payload.target, payload.options, on_complete)

    log_action(db, user, "scan.launch", target=f"scan:{scan.id}", details=f"{scanner_type.value} -> {payload.target}",
               ip_address=request.client.host if request.client else "")

    return {"scan_id": scan.id, "status": "launched"}


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

    # scanner_type stays exactly what the user selected, including "import"
    # for the auto-detect path - parsers/registry.py sniffs the actual
    # format from content, but the Scan record honestly reflects that this
    # was an auto-detected import rather than a self-declared scanner type.
    scan = Scan(
        name=name, scanner_type=st,
        target=file.filename or "uploaded file", status=ScanStatus.COMPLETED,
        started_at=datetime.now(timezone.utc), finished_at=datetime.now(timezone.utc), created_by=user.username,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    summary = ingest_scan_result(db, scan, raw_text, file.filename or "")

    log_action(db, user, "scan.import", target=f"scan:{scan.id}", details=f"{scanner_type} file={file.filename}",
               ip_address=request.client.host if request.client else "")

    return {"scan_id": scan.id, **summary}


@router.post("/{scan_id}/cancel")
def cancel_scan(scan_id: int, db: Session = Depends(get_db), user: User = Depends(require_permission("scan.cancel"))):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    scan.status = ScanStatus.CANCELLED
    scan.finished_at = datetime.now(timezone.utc)
    db.commit()
    log_action(db, user, "scan.cancel", target=f"scan:{scan_id}")
    return {"ok": True}
