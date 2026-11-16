"""
Nuclei scanner backend - REAL integration. Shells out to the `nuclei`
binary with `-jsonl` output, which flows through parsers/nuclei_parser.py.

Template directory resolution order:
  1. NUCLEI_TEMPLATES_DIR env var, if set
  2. ~/nuclei-templates (the default `nuclei -update-templates` location)
  3. Falls back to letting nuclei use its own default/bundled resolution

For air-gapped deployments: `nuclei-templates` is a git repo (or a
release .zip) that should be pulled down ONCE on a connected machine and
carried across the air gap alongside the platform - nuclei itself never
needs to phone home to run a scan once templates are present locally.
"""
from __future__ import annotations
import os
import shutil
import subprocess
import tempfile
import time
from typing import Callable, Optional
from scanners.base import ScannerBackend, ScannerCancelled

SEVERITY_PROFILES = {
    "critical_high": ["critical", "high"],
    "all": ["info", "low", "medium", "high", "critical"],
    "standard": ["low", "medium", "high", "critical"],
}


def _templates_dir() -> Optional[str]:
    custom = os.environ.get("NUCLEI_TEMPLATES_DIR", "")
    if custom and os.path.isdir(custom):
        return custom
    # Fall back to letting nuclei use its own default/installed template resolution
    return None


class NucleiScanner(ScannerBackend):
    scanner_type = "nuclei"

    def is_available(self) -> bool:
        return shutil.which("nuclei") is not None

    def launch(self, target: str, options: dict, on_progress: Optional[Callable[[int, str], None]] = None) -> dict:
        if not self.is_available():
            raise RuntimeError("nuclei binary not found on this system. Install nuclei or use file import instead.")

        severity_profile = options.get("severity_profile", "standard")
        severities = SEVERITY_PROFILES.get(severity_profile, SEVERITY_PROFILES["standard"])
        template_tags = options.get("tags", "")  # e.g. "cve,exposure"
        automatic_scan = bool(options.get("automatic_scan", False))
        concurrency = str(options.get("concurrency") or os.environ.get("NUCLEI_CONCURRENCY", "50"))
        rate_limit = str(options.get("rate_limit") or os.environ.get("NUCLEI_RATE_LIMIT", "300"))
        timeout = str(options.get("timeout") or os.environ.get("NUCLEI_TIMEOUT", "5"))

        if on_progress:
            on_progress(5, f"Starting nuclei against {target}")

        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
            out_path = tmp.name

        cmd = [
            "nuclei", "-u", target,
            "-c", concurrency, "-rl", rate_limit, "-timeout", timeout,
            "-jsonl", "-o", out_path, "-silent",
        ]
        if severity_profile != "all":
            cmd += ["-severity", ",".join(severities)]
        if automatic_scan:
            cmd.append("-as")
        tdir = _templates_dir()
        if tdir:
            cmd += ["-t", tdir]
        if template_tags:
            cmd += ["-tags", template_tags]

        with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as log_file:
            try:
                proc = subprocess.Popen(cmd, stdout=log_file, stderr=log_file)
                cancel_check = options.get("_cancel_check")
                timeout_limit = options.get("timeout_seconds", 1800)
                start_time = time.monotonic()
                last_pulse = start_time
                deadline = start_time + timeout_limit
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
                        if on_progress and (now - last_pulse) >= 3:
                            elapsed = int(now - start_time)
                            est_pct = min(85, 5 + int((elapsed / timeout_limit) * 80))
                            current_findings = 0
                            if os.path.exists(out_path):
                                try:
                                    with open(out_path, "r", encoding="utf-8", errors="ignore") as f:
                                        current_findings = sum(1 for line in f if line.strip())
                                except Exception:
                                    pass
                            msg = f"Nuclei scan in progress against {target} ({elapsed}s elapsed"
                            if current_findings > 0:
                                msg += f", {current_findings} finding(s) discovered"
                            msg += ")"
                            try:
                                on_progress(est_pct, msg, current_findings)
                            except TypeError:
                                on_progress(est_pct, msg)
                            last_pulse = now
                        time.sleep(0.5)
                finally:
                    if proc.poll() is None:
                        proc.kill()
                        proc.wait()
            except subprocess.TimeoutExpired:
                raise RuntimeError(f"nuclei scan against {target} timed out")

            if proc.returncode not in (0, 1):
                log_file.seek(0)
                detail = log_file.read().strip()
                raise RuntimeError(
                    f"nuclei exited with code {proc.returncode}"
                    + (f": {detail[:500]}" if detail else "")
                )

        if on_progress:
            on_progress(90, "nuclei scan finished, parsing results")

        raw_output = ""
        if os.path.exists(out_path):
            with open(out_path, "r", encoding="utf-8", errors="ignore") as f:
                raw_output = f.read()
            os.unlink(out_path)

        if on_progress:
            on_progress(100, "Complete")

        return {"raw_output": raw_output, "filename": f"nuclei_{target.replace('/', '_').replace(':', '_')}.jsonl"}
