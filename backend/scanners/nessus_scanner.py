"""
Tenable Nessus integration via its real REST API
(https://<nessus-host>:8834/). Nessus is a licensed product with its own
scan engine; this client authenticates, creates a scan against a target,
launches it, polls status, and exports the .nessus XML report - the exact
same file format parsers/nessus_parser.py already handles for manual
uploads.

Like the OpenVAS integration, this cannot be exercised against a real
engine in this sandbox (no licensed Nessus instance available here), so
is_available() honestly reports False until NESSUS_URL + API keys are
configured and reachable, and launch() fails loudly and specifically
rather than faking success.

Configuration (environment variables):
  NESSUS_URL (e.g. https://nessus.internal.corp:8834)
  NESSUS_ACCESS_KEY, NESSUS_SECRET_KEY
  NESSUS_VERIFY_SSL (default "false" - Nessus commonly runs with a
    self-signed cert on an internal management network)
"""
from __future__ import annotations
import os
import time
import urllib.request
import urllib.error
import json
import ssl
from typing import Callable, Optional
from scanners.base import ScannerBackend

NESSUS_URL = os.environ.get("", "").rstrip("/")
NESSUS_ACCESS_KEY = os.environ.get("", "")
NESSUS_SECRET_KEY = os.environ.get("", "")
NESSUS_VERIFY_SSL = os.environ.get("NESSUS_VERIFY_SSL", "false").lower() == "true"
DEFAULT_TEMPLATE_UUID = "731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65"  # stock "Basic Network Scan"


def _ssl_context():
    if NESSUS_VERIFY_SSL:
        return ssl.create_default_context()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _request(method: str, path: str, body: Optional[dict] = None, raw: bool = False):
    url = f"{NESSUS_URL}{path}"
    headers = {
        "X-ApiKeys": f"accessKey={NESSUS_ACCESS_KEY}; secretKey={NESSUS_SECRET_KEY}",
        "Content-Type": "application/json",
    }
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, context=_ssl_context(), timeout=30) as resp:
        content = resp.read()
        return content if raw else json.loads(content)


class NessusScanner(ScannerBackend):
    scanner_type = "nessus"

    def is_available(self) -> bool:
        if not (NESSUS_URL and NESSUS_ACCESS_KEY and NESSUS_SECRET_KEY):
            return False
        try:
            _request("GET", "/server/status")
            return True
        except (urllib.error.URLError, OSError):
            return False

    def launch(self, target: str, options: dict, on_progress: Optional[Callable[[int, str], None]] = None) -> dict:
        if not (NESSUS_URL and NESSUS_ACCESS_KEY and NESSUS_SECRET_KEY):
            raise RuntimeError(
                "Nessus is not configured. Set NESSUS_URL, NESSUS_ACCESS_KEY, NESSUS_SECRET_KEY "
                "environment variables to point this platform at a real Nessus instance, "
                "or import a .nessus report via the Import feature instead."
            )

        template_uuid = options.get("template_uuid", DEFAULT_TEMPLATE_UUID)

        if on_progress:
            on_progress(5, "Creating Nessus scan")
        create_resp = _request("POST", "/scans", {
            "uuid": template_uuid,
            "settings": {"name": f"vuln-platform scan {target}", "text_targets": target},
        })
        scan_id = create_resp["scan"]["id"]

        if on_progress:
            on_progress(15, "Launching scan")
        _request("POST", f"/scans/{scan_id}/launch")

        status = "running"
        progress = 15
        while status in ("running", "pending"):
            time.sleep(options.get("poll_interval_seconds", 15))
            detail = _request("GET", f"/scans/{scan_id}")
            status = detail.get("info", {}).get("status", "running")
            progress = min(progress + 5, 90)
            if on_progress:
                on_progress(progress, f"Nessus scan status: {status}")

        if status != "completed":
            raise RuntimeError(f"Nessus scan ended with status: {status}")

        if on_progress:
            on_progress(92, "Exporting .nessus report")
        export_resp = _request("POST", f"/scans/{scan_id}/export", {"format": "nessus"})
        file_id = export_resp["file"]

        # Poll export readiness
        ready = False
        for _ in range(30):
            time.sleep(2)
            status_resp = _request("GET", f"/scans/{scan_id}/export/{file_id}/status")
            if status_resp.get("status") == "ready":
                ready = True
                break
        if not ready:
            raise RuntimeError("Nessus report export did not become ready in time")

        raw_bytes = _request("GET", f"/scans/{scan_id}/export/{file_id}/download", raw=True)

        if on_progress:
            on_progress(100, "Complete")

        return {"raw_output": raw_bytes.decode("utf-8", errors="ignore"), "filename": f"nessus_{target.replace('/', '_')}.nessus"}
