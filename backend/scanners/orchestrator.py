"""
Scanner registry + orchestrator.

The orchestrator runs each scan in a background thread (simple, portable,
no separate worker process required - important for the "single portable
process" / air-gapped deployment goal). Progress updates are pushed into an
in-memory dict keyed by scan_id that the WebSocket endpoint
(api/routes_ws.py) polls and streams to connected dashboard clients.

For a heavier production deployment the spec's Celery+Redis stack is the
natural next step (see README) - this thread-based orchestrator is what
lets the whole platform run from one process with zero extra services,
matching the same "portable first" philosophy as the SOC Log Analytics
platform.
"""
from __future__ import annotations
import threading
import traceback
from datetime import datetime, timezone
from typing import Callable

from scanners.nmap_scanner import NmapScanner
from scanners.nuclei_scanner import NucleiScanner
from scanners.openvas_scanner import OpenVASScanner
from scanners.nessus_scanner import NessusScanner
from scanners.custom_scanner import CustomScriptScanner

REGISTRY = {
    "nmap": NmapScanner(),
    "nuclei": NucleiScanner(),
    "openvas": OpenVASScanner(),
    "nessus": NessusScanner(),
    "custom": CustomScriptScanner(),
}

_progress_store: dict[int, dict] = {}


def get_progress(scan_id: int) -> dict:
    return _progress_store.get(scan_id, {"pct": 0, "message": "Not started"})


def scanner_availability() -> dict:
    return {name: backend.is_available() for name, backend in REGISTRY.items()}


def launch_scan_background(scan_id: int, scanner_type: str, target: str, options: dict, on_complete: Callable[[int, dict | None, str | None], None]):
    thread = threading.Thread(
        target=_run_scan,
        args=(scan_id, scanner_type, target, options, on_complete),
        daemon=True,
    )
    thread.start()


def _run_scan(scan_id: int, scanner_type: str, target: str, options: dict, on_complete: Callable):
    backend = REGISTRY.get(scanner_type)
    if backend is None:
        on_complete(scan_id, None, f"Unknown scanner type: {scanner_type}")
        return

    def progress_cb(pct: int, message: str):
        _progress_store[scan_id] = {"pct": pct, "message": message, "updated_at": datetime.now(timezone.utc).isoformat()}

    try:
        _progress_store[scan_id] = {"pct": 0, "message": "Queued"}
        result = backend.launch(target, options, on_progress=progress_cb)
        on_complete(scan_id, result, None)
    except Exception as e:
        traceback.print_exc()
        _progress_store[scan_id] = {"pct": 100, "message": f"Failed: {e}"}
        on_complete(scan_id, None, str(e))
