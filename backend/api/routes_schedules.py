from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from models.database import get_db, ScanSchedule, ScannerType, ScheduleFrequency, User, AuditLog
from auth.security import get_current_user, require_permission
from auth.audit import log_action
from api.schemas import ScheduleCreate
from scheduling.scheduler import sync_schedule, remove_schedule

router = APIRouter()


@router.get("")
def list_schedules(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    schedules = db.query(ScanSchedule).all()
    return {"schedules": [
        {
            "id": s.id, "name": s.name, "scanner_type": s.scanner_type.value, "target": s.target,
            "frequency": s.frequency.value, "cron_expression": s.cron_expression, "enabled": s.enabled,
            "rescan_on_remediation": s.rescan_on_remediation, "last_run": s.last_run, "next_run": s.next_run,
        }
        for s in schedules
    ]}


@router.post("")
def create_schedule(payload: ScheduleCreate, db: Session = Depends(get_db), user: User = Depends(require_permission("schedule.write"))):
    try:
        scanner_type = ScannerType(payload.scanner_type)
        frequency = ScheduleFrequency(payload.frequency)
    except ValueError as e:
        raise HTTPException(400, str(e))
    if frequency == ScheduleFrequency.CUSTOM_CRON and not payload.cron_expression:
        raise HTTPException(400, "cron_expression is required when frequency is custom_cron")

    schedule = ScanSchedule(
        name=payload.name, scanner_type=scanner_type, target=payload.target, frequency=frequency,
        cron_expression=payload.cron_expression, rescan_on_remediation=payload.rescan_on_remediation,
        created_by=user.username,
    )
    db.add(schedule)
    db.commit()
    db.refresh(schedule)
    sync_schedule(schedule)
    log_action(db, user, "schedule.create", target=f"schedule:{schedule.id}", details=f"{scanner_type.value} {frequency.value} -> {payload.target}")
    return {"id": schedule.id}


@router.patch("/{schedule_id}/toggle")
def toggle_schedule(schedule_id: int, db: Session = Depends(get_db), user: User = Depends(require_permission("schedule.write"))):
    schedule = db.get(ScanSchedule, schedule_id)
    if not schedule:
        raise HTTPException(404, "Schedule not found")
    schedule.enabled = not schedule.enabled
    db.commit()
    if schedule.enabled:
        sync_schedule(schedule)
    else:
        remove_schedule(schedule.id)
    log_action(db, user, "schedule.toggle", target=f"schedule:{schedule_id}", details=f"enabled={schedule.enabled}")
    return {"ok": True, "enabled": schedule.enabled}


@router.delete("/{schedule_id}")
def delete_schedule(schedule_id: int, db: Session = Depends(get_db), user: User = Depends(require_permission("schedule.write"))):
    schedule = db.get(ScanSchedule, schedule_id)
    if not schedule:
        raise HTTPException(404, "Schedule not found")
    remove_schedule(schedule_id)
    db.delete(schedule)
    db.commit()
    log_action(db, user, "schedule.delete", target=f"schedule:{schedule_id}")
    return {"ok": True}
