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
from typing import Callable, Optional
from scanners.base import ScannerBackend

SEVERITY_PROFILES = {
    "critical_high": ["critical", "high"],
    "all": ["info", "low", "medium", "high", "critical"],
    "standard": ["low", "medium", "high", "critical"],
}


def _templates_dir() -> Optional[str]:
    candidates = [
        os.environ.get("NUCLEI_TEMPLATES_DIR", ""),
        os.path.expanduser("~/nuclei-templates"),
    ]
    for c in candidates:
        if c and os.path.isdir(c):
            return c
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

        if on_progress:
            on_progress(5, f"Starting nuclei against {target}")

        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
            out_path = tmp.name

        cmd = ["nuclei", "-u", target, "-jsonl", "-o", out_path, "-severity", ",".join(severities), "-silent"]
        tdir = _templates_dir()
        if tdir:
            cmd += ["-t", tdir]
        if template_tags:
            cmd += ["-tags", template_tags]

        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=options.get("timeout_seconds", 900))
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"nuclei scan against {target} timed out")

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
