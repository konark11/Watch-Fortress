from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
import os

from models.database import get_db, ReportJob, User
from auth.security import get_current_user, require_permission
from auth.audit import log_action
from api.schemas import ReportRequest
from reports.generator import generate_report

router = APIRouter()


@router.post("/generate")
def generate(payload: ReportRequest, db: Session = Depends(get_db), user: User = Depends(require_permission("report.generate"))):
    if payload.report_type not in ("executive", "technical", "compliance"):
        raise HTTPException(400, "report_type must be executive, technical, or compliance")
    if payload.report_format not in ("pdf", "html", "docx", "json"):
        raise HTTPException(400, "report_format must be pdf, html, docx, or json")
    if payload.report_type == "compliance" and not payload.compliance_framework:
        raise HTTPException(400, "compliance_framework is required for compliance reports (PCI-DSS, ISO27001, or NIST_CSF)")

    job = generate_report(
        db, payload.report_type, payload.report_format,
        scope_asset_ids=payload.scope_asset_ids, compliance_framework=payload.compliance_framework,
        generated_by=user.username,
    )
    log_action(db, user, "report.generate", target=f"report:{job.id}", details=f"{payload.report_type}/{payload.report_format}")
    return {"report_id": job.id, "download_url": f"/api/reports/{job.id}/download"}


@router.get("")
def list_reports(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    jobs = db.query(ReportJob).order_by(ReportJob.id.desc()).limit(100).all()
    return {"reports": [
        {
            "id": j.id, "report_type": j.report_type.value, "report_format": j.report_format.value,
            "scope_description": j.scope_description, "generated_by": j.generated_by,
            "generated_at": j.generated_at, "compliance_framework": j.compliance_framework,
        }
        for j in jobs
    ]}


@router.get("/{report_id}/download")
def download_report(report_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    job = db.get(ReportJob, report_id)
    if not job or not job.file_path or not os.path.exists(job.file_path):
        raise HTTPException(404, "Report file not found")
    media_types = {"pdf": "application/pdf", "html": "text/html", "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "json": "application/json"}
    return FileResponse(job.file_path, media_type=media_types.get(job.report_format.value, "application/octet-stream"), filename=os.path.basename(job.file_path))
