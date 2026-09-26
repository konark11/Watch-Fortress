from __future__ import annotations
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from models.database import get_db, AuditLog, User
from auth.security import require_permission

router = APIRouter()


@router.get("")
def list_audit_log(limit: int = 200, offset: int = 0, db: Session = Depends(get_db), _: User = Depends(require_permission("audit.view"))):
    entries = db.query(AuditLog).order_by(AuditLog.id.desc()).offset(offset).limit(limit).all()
    return {"entries": [
        {
            "id": e.id, "username": e.username, "action": e.action, "target": e.target,
            "details": e.details, "ip_address": e.ip_address, "timestamp": e.timestamp,
        }
        for e in entries
    ]}
