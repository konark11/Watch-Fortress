"""Durable schedule dispatcher.

The API never owns a timer. A single ``python -m scheduling.dispatcher``
process claims due schedules and enqueues durable scan jobs. ``sync_schedule``
is retained as a compatibility no-op for the existing schedule API.
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone

from apscheduler.triggers.cron import CronTrigger
from sqlalchemy import text

from models.database import (
    SessionLocal, ScanSchedule, ScheduleFrequency, Scan, ScanStatus,
)
from jobs.repository import enqueue, is_postgres


def _cron_trigger_for(schedule: ScanSchedule) -> CronTrigger:
    if schedule.frequency == ScheduleFrequency.DAILY:
        return CronTrigger(hour=2, minute=0)
    if schedule.frequency == ScheduleFrequency.WEEKLY:
        return CronTrigger(day_of_week="sun", hour=2, minute=0)
    if schedule.frequency == ScheduleFrequency.MONTHLY:
        return CronTrigger(day=1, hour=2, minute=0)
    if schedule.frequency == ScheduleFrequency.CUSTOM_CRON and schedule.cron_expression:
        return CronTrigger.from_crontab(schedule.cron_expression)
    return CronTrigger(hour=2, minute=0)


def sync_schedule(schedule: ScanSchedule) -> None:
    """Compatibility hook; durable dispatch reads schedules from PostgreSQL."""
    if schedule.enabled and schedule.next_run is None:
        schedule.next_run = _cron_trigger_for(schedule).get_next_fire_time(
            None, datetime.now(timezone.utc)
        )


def remove_schedule(schedule_id: int) -> None:
    return None


def trigger_rescan_on_remediation(db, asset_id: int, schedule_id: int | None):
    """Enqueue a durable confirmation scan after remediation."""
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
        status=ScanStatus.PENDING,
        created_by="auto-rescan",
        schedule_id=schedule.id,
    )
    db.add(scan)
    db.flush()
    enqueue(
        db, job_type="scan.execute",
        payload={"scan_id": scan.id, "scanner_type": schedule.scanner_type.value,
                 "target": asset.ip_address, "options": {}},
        idempotency_key=f"remediation:{schedule.id}:{asset.id}:{scan.id}",
        creator_username="auto-rescan", scan_id=scan.id,
    )
    db.commit()


def dispatch_due() -> int:
    db = SessionLocal()
    try:
        if is_postgres():
            locked = db.execute(text("SELECT pg_try_advisory_lock(:key)"), {"key": 874221}).scalar()
            if not locked:
                return 0
        now = datetime.now(timezone.utc)
        dispatched = 0
        schedules = (
            db.query(ScanSchedule)
            .filter(ScanSchedule.enabled == True)
            .filter((ScanSchedule.next_run.is_(None)) | (ScanSchedule.next_run <= now))
            .with_for_update(skip_locked=is_postgres())
            .all()
        )
        for schedule in schedules:
            scan = Scan(
                name=f"Scheduled: {schedule.name}",
                scanner_type=schedule.scanner_type,
                target=schedule.target,
                status=ScanStatus.PENDING,
                created_by="scheduler",
                schedule_id=schedule.id,
            )
            db.add(scan)
            db.flush()
            job = enqueue(
                db, job_type="scan.execute",
                payload={"scan_id": scan.id, "scanner_type": schedule.scanner_type.value,
                         "target": schedule.target, "options": {}},
                idempotency_key=f"schedule:{schedule.id}:{now.date()}:{scan.id}",
                creator_username="scheduler", scan_id=scan.id,
            )
            schedule.last_run = now
            schedule.next_run = _cron_trigger_for(schedule).get_next_fire_time(now, now)
            dispatched += 1
        if os.environ.get("ASSISTANT_RETENTION_PURGE_ENABLED", "true").lower() in {"1", "true", "yes"}:
            enqueue(
                db, job_type="assistant.retention_purge",
                payload={"batch_size": int(os.environ.get("ASSISTANT_RETENTION_PURGE_BATCH_SIZE", "100"))},
                idempotency_key=f"assistant-retention-purge:{now.date()}",
                creator_username="scheduler",
            )
        db.commit()
        return dispatched
    finally:
        db.close()


def start_scheduler() -> None:
    return None


def load_all_schedules() -> None:
    return None


def main() -> None:
    interval = float(os.environ.get("SCHEDULER_POLL_INTERVAL_SECONDS", "30"))
    while True:
        dispatch_due()
        time.sleep(interval)


if __name__ == "__main__":
    main()
