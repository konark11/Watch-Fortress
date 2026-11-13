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

def get_progress(scan_id: int) -> dict:
    return {"pct": 0, "message": "Progress is persisted by the job worker"}


def scanner_availability() -> dict:
    return {name: backend.is_available() for name, backend in REGISTRY.items()}


def run_scan(
    scan_id: int,
    scanner_type: str,
    target: str,
    options: dict,
    on_progress: Callable[[int, str], None],
) -> dict:
    """Run one scanner synchronously for a durable worker process."""
    backend = REGISTRY.get(scanner_type)
    if backend is None:
        raise ValueError(f"Unknown scanner type: {scanner_type}")
    return backend.launch(target, options, on_progress=on_progress)
