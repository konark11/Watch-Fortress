"""
Continuous Scan Scheduling.

Uses APScheduler's BackgroundScheduler rather than Celery+Redis: it runs
in-process (no broker, no separate worker service to deploy), which keeps
the platform startable as a single process - the same "portable first"
philosophy used throughout. A Celery+Redis deployment is a natural
production upgrade path for very large fleets (see README) but isn't
required to get real scheduled scanning working.

Frequencies: daily / weekly / monthly / custom_cron, matching the spec.
Auto-rescan after remediation: when a Vulnerability's status is set to
"remediated" and its ScanSchedule has rescan_on_remediation enabled, a
one-off follow-up scan of that asset is queued to confirm the fix.
"""
from __future__ import annotations
from datetime import datetime, timezone
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy.orm import Session

from models.database import SessionLocal, ScanSchedule, ScheduleFrequency, Scan, ScannerType, ScanStatus
from scanners.orchestrator import launch_scan_background
from core.ingestion import ingest_scan_result

_scheduler = BackgroundScheduler()
_job_ids: dict[int, str] = {}


def _cron_trigger_for(schedule: ScanSchedule) -> CronTrigger:
    if schedule.frequency == ScheduleFrequency.DAILY:
        return CronTrigger(hour=2, minute=0)  # 02:00 local - low-traffic default
    if schedule.frequency == ScheduleFrequency.WEEKLY:
        return CronTrigger(day_of_week="sun", hour=2, minute=0)
    if schedule.frequency == ScheduleFrequency.MONTHLY:
        return CronTrigger(day=1, hour=2, minute=0)
    if schedule.frequency == ScheduleFrequency.CUSTOM_CRON and schedule.cron_expression:
        return CronTrigger.from_crontab(schedule.cron_expression)
    return CronTrigger(hour=2, minute=0)


def _run_scheduled_scan(schedule_id: int):
    db: Session = SessionLocal()
    try:
        schedule = db.get(ScanSchedule, schedule_id)
        if not schedule or not schedule.enabled:
            return
        scan = Scan(
            name=f"Scheduled: {schedule.name}",
            scanner_type=schedule.scanner_type,
            target=schedule.target,
            status=ScanStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            created_by="scheduler",
            schedule_id=schedule.id,
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
                    ingest_scan_result(inner_db, s, result["raw_output"], result.get("filename", ""))
                s.finished_at = datetime.now(timezone.utc)
                inner_db.commit()
            finally:
                inner_db.close()

        launch_scan_background(scan.id, schedule.scanner_type.value, schedule.target, {}, on_complete)

        schedule.last_run = datetime.now(timezone.utc)
        db.commit()
    finally:
        db.close()


def sync_schedule(schedule: ScanSchedule):
    """(Re)register a schedule's APScheduler job to match its current
    frequency/enabled state. Call this after any create/update/delete."""
    existing_job_id = _job_ids.get(schedule.id)
    if existing_job_id:
        try:
            _scheduler.remove_job(existing_job_id)
        except Exception:
            pass
        del _job_ids[schedule.id]

    if not schedule.enabled:
        return

    job = _scheduler.add_job(
        _run_scheduled_scan, trigger=_cron_trigger_for(schedule), args=[schedule.id],
        id=f"schedule-{schedule.id}-{datetime.now().timestamp()}", replace_existing=True,
    )
    _job_ids[schedule.id] = job.id


def remove_schedule(schedule_id: int):
    job_id = _job_ids.pop(schedule_id, None)
    if job_id:
        try:
            _scheduler.remove_job(job_id)
        except Exception:
            pass


def trigger_rescan_on_remediation(db: Session, asset_id: int, schedule_id: int | None):
    """Called when a Vulnerability's status is set to 'remediated'. If the
    originating schedule has rescan_on_remediation enabled, queue an
    immediate one-off confirmation scan of that asset."""
    if not schedule_id:
        return
    schedule = db.get(ScanSchedule, schedule_id)
    if not schedule or not schedule.rescan_on_remediation:
        return
    from models.database import Asset
    asset = db.get(Asset, asset_id)
    if not asset:
        return
    scan = Scan(
        name=f"Remediation confirmation: {asset.ip_address}",
        scanner_type=schedule.scanner_type,
        target=asset.ip_address,
        status=ScanStatus.RUNNING,
        started_at=datetime.now(timezone.utc),
        created_by="auto-rescan",
        schedule_id=schedule.id,
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
                ingest_scan_result(inner_db, s, result["raw_output"], result.get("filename", ""))
            s.finished_at = datetime.now(timezone.utc)
            inner_db.commit()
        finally:
            inner_db.close()

    launch_scan_background(scan.id, schedule.scanner_type.value, asset.ip_address, {}, on_complete)


def start_scheduler():
    if not _scheduler.running:
        _scheduler.start()


def load_all_schedules():
    """Called once at app startup to register every enabled ScanSchedule
    already in the database with APScheduler (schedules persist across
    restarts in the DB; the in-memory job registration does not, so this
    rebuilds it)."""
    db = SessionLocal()
    try:
        for schedule in db.query(ScanSchedule).filter(ScanSchedule.enabled == True).all():  # noqa: E712
            sync_schedule(schedule)
    finally:
        db.close()
