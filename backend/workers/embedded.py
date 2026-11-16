from __future__ import annotations

import logging
import os
import socket
import threading

from jobs.repository import is_postgres
from workers.run import run_once

logger = logging.getLogger("watch_fortress.embedded_worker")


def enabled() -> bool:
    configured = os.environ.get("JOB_EMBEDDED_WORKER_ENABLED", "true").strip().lower()
    return configured in {"1", "true", "yes"} and not is_postgres()


def start() -> threading.Event | None:
    if not enabled():
        return None

    stop_event = threading.Event()
    worker_id = os.environ.get("JOB_WORKER_ID") or f"embedded-{socket.gethostname()}"

    def run() -> None:
        poll_interval = max(0.1, float(os.environ.get("JOB_POLL_INTERVAL_SECONDS", "2")))
        while not stop_event.is_set():
            try:
                claimed = run_once(worker_id)
            except Exception:
                logger.exception("embedded worker iteration failed")
                claimed = False
            if not claimed:
                stop_event.wait(poll_interval)

    threading.Thread(
        target=run,
        name="watch-fortress-embedded-worker",
        daemon=True,
    ).start()
    logger.info("embedded job worker started worker_id=%s", worker_id)
    return stop_event


def stop(stop_event: threading.Event | None) -> None:
    if stop_event is None:
        return
    stop_event.set()
    logger.info("embedded job worker stopped")
