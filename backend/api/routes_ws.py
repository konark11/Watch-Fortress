from __future__ import annotations
import asyncio
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from scanners.orchestrator import get_progress

router = APIRouter()


@router.websocket("/ws/scans/{scan_id}")
async def scan_progress_ws(websocket: WebSocket, scan_id: int):
    """Streams {"pct": int, "message": str} updates for a running scan
    every second until it reaches 100%. The dashboard's "Monitor scan
    progress in real time" panel connects here after launching a scan."""
    await websocket.accept()
    try:
        last_sent = None
        while True:
            progress = get_progress(scan_id)
            if progress != last_sent:
                await websocket.send_json(progress)
                last_sent = progress
            if progress.get("pct", 0) >= 100:
                break
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        pass
