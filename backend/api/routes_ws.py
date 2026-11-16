from __future__ import annotations

import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from models.database import BackgroundJob, Scan, SessionLocal

router = APIRouter()


@router.websocket("/ws/scans/{scan_id}")
async def scan_progress_ws(websocket: WebSocket, scan_id: int):
    """Stream persisted job progress; no process-local progress state."""
    await websocket.accept()
    try:
        last_sent = None
        while True:
            db = SessionLocal()
            try:
                job = db.query(BackgroundJob).filter(
                    BackgroundJob.scan_id == scan_id
                ).order_by(BackgroundJob.id.desc()).first()
                scan = db.get(Scan, scan_id)
                progress = {
                    "pct": job.progress_pct if job else 0,
                    "message": job.progress_message if job else "Queued",
                    "job_state": job.state.value if job else "queued",
                    "job_id": job.public_id if job else None,
                    "findings_count": scan.findings_count if (scan and scan.findings_count is not None) else 0,
                }
            finally:
                db.close()
            if progress != last_sent:
                await websocket.send_json(progress)
                last_sent = progress
            if progress["job_state"] in {"completed", "failed", "cancelled", "dead_letter"}:
                break
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        pass
