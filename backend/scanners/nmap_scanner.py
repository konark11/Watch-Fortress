"""
Nmap scanner backend - REAL integration, not a stub. Shells out to the
system `nmap` binary and captures `-oX` XML output, which then flows
through parsers/nmap_parser.py exactly like an uploaded/imported file would.

Options supported (passed from the "Launch Scan" dashboard form):
  profile: "quick" | "full" | "all_ports" | "all_ports_service_version" |
           "service_version" | "os_detection" | "vuln_scripts"
"""
from __future__ import annotations
import shutil
import subprocess
import tempfile
import os
import time
from typing import Callable, Optional
from scanners.base import ScannerBackend, ScannerCancelled

PROFILE_FLAGS = {
    "quick": ["-T4", "-n", "-F", "--min-rate", "300"],
    "full": ["-T4", "-n", "-sV", "--top-ports", "1000", "--min-rate", "300", "--host-timeout", "10m"],
    "all_ports": ["-T4", "-n", "-p-", "--min-rate", "300", "--host-timeout", "15m"],
    "all_ports_service_version": ["-T4", "-n", "-p-", "-sV", "--min-rate", "300", "--host-timeout", "15m"],
    "service_version": ["-T4", "-n", "-sV", "--top-ports", "100", "--min-rate", "300", "--host-timeout", "5m"],
    "os_detection": ["-T4", "-n", "-O", "--top-ports", "50", "--min-rate", "300", "--host-timeout", "5m"],
    "vuln_scripts": ["-T4", "-n", "-sV", "--script", "vulners,ssl-cert", "--script-timeout", "30s", "--top-ports", "100", "--min-rate", "300", "--host-timeout", "5m"],
}


class NmapScanner(ScannerBackend):
    scanner_type = "nmap"

    def is_available(self) -> bool:
        return shutil.which("nmap") is not None

    def launch(self, target: str, options: dict, on_progress: Optional[Callable[[int, str], None]] = None) -> dict:
        if not self.is_available():
            raise RuntimeError("nmap binary not found on this system. Install nmap or use file import instead.")

        profile = options.get("profile", "service_version")
        flags = list(PROFILE_FLAGS.get(profile, PROFILE_FLAGS["service_version"]))
        if options.get("resolve_dns", False) and "-n" in flags:
            flags.remove("-n")

        if on_progress:
            on_progress(5, f"Starting nmap ({profile} profile) against {target}")

        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            out_path = tmp.name

        cmd = ["nmap", *flags, "-oX", out_path, target]
        timeout_limit = options.get("timeout_seconds", 1800)
        start_time = time.monotonic()
        last_pulse = start_time
        deadline = start_time + timeout_limit

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        cancel_check = options.get("_cancel_check")
        try:
            while proc.poll() is None:
                now = time.monotonic()
                if callable(cancel_check) and cancel_check():
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
                    raise ScannerCancelled()
                if now >= deadline:
                    proc.kill()
                    proc.wait()
                    raise subprocess.TimeoutExpired(cmd, timeout_limit)
                if on_progress and (now - last_pulse) >= 5:
                    elapsed = int(now - start_time)
                    est_pct = min(85, 5 + int((elapsed / timeout_limit) * 80))
                    on_progress(est_pct, f"Nmap ({profile}) in progress against {target} ({elapsed}s elapsed)")
                    last_pulse = now
                time.sleep(0.5)
            stdout, stderr = proc.communicate()
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"nmap scan against {target} timed out")
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()

        if on_progress:
            on_progress(90, "nmap scan finished, parsing results")

        if proc.returncode != 0 and not os.path.exists(out_path):
            raise RuntimeError(f"nmap failed: {stderr[:500]}")

        with open(out_path, "r", encoding="utf-8", errors="ignore") as f:
            xml_output = f.read()
        os.unlink(out_path)

        if on_progress:
            on_progress(100, "Complete")

        return {"raw_output": xml_output, "filename": f"nmap_{target.replace('/', '_')}.xml"}
