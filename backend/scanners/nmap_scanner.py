"""
Nmap scanner backend - REAL integration, not a stub. Shells out to the
system `nmap` binary and captures `-oX` XML output, which then flows
through parsers/nmap_parser.py exactly like an uploaded/imported file would.

Options supported (passed from the "Launch Scan" dashboard form):
  profile: "quick" | "full" | "service_version" | "os_detection" | "vuln_scripts"
"""
from __future__ import annotations
import shutil
import subprocess
import tempfile
import os
from typing import Callable, Optional
from scanners.base import ScannerBackend

PROFILE_FLAGS = {
    "quick": ["-T4", "-F"],
    "full": ["-T4", "-p-"],
    "service_version": ["-T4", "-sV", "--top-ports", "100"],
    "os_detection": ["-T4", "-O", "--top-ports", "50"],
    "vuln_scripts": ["-T4", "-sV", "--script", "vulners,ssl-cert", "--top-ports", "100"],
}


class NmapScanner(ScannerBackend):
    scanner_type = "nmap"

    def is_available(self) -> bool:
        return shutil.which("nmap") is not None

    def launch(self, target: str, options: dict, on_progress: Optional[Callable[[int, str], None]] = None) -> dict:
        if not self.is_available():
            raise RuntimeError("nmap binary not found on this system. Install nmap or use file import instead.")

        profile = options.get("profile", "service_version")
        flags = PROFILE_FLAGS.get(profile, PROFILE_FLAGS["service_version"])

        if on_progress:
            on_progress(5, f"Starting nmap ({profile} profile) against {target}")

        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            out_path = tmp.name

        cmd = ["nmap", *flags, "-oX", out_path, target]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=options.get("timeout_seconds", 600))
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"nmap scan against {target} timed out")

        if on_progress:
            on_progress(90, "nmap scan finished, parsing results")

        if proc.returncode != 0 and not os.path.exists(out_path):
            raise RuntimeError(f"nmap failed: {proc.stderr[:500]}")

        with open(out_path, "r", encoding="utf-8", errors="ignore") as f:
            xml_output = f.read()
        os.unlink(out_path)

        if on_progress:
            on_progress(100, "Complete")

        return {"raw_output": xml_output, "filename": f"nmap_{target.replace('/', '_')}.xml"}
