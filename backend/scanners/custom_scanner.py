"""
Custom Script scanner backend.

Lets an analyst register an arbitrary local script (shell, Python, etc.)
as a "scanner" - the platform runs it with the target as an argument and
captures stdout, which is then parsed as generic CSV/JSON (see
parsers/generic_parser.py) or a specific format if the script emits
Nmap/Nessus/Nuclei-shaped output.

This intentionally runs with the SAME privileges as the platform process
- only administrators/security analysts can register custom scripts (see
auth/security.py PERMISSIONS), and script paths are restricted to a
configured scripts directory to avoid becoming an arbitrary remote code
execution primitive over the API.
"""
from __future__ import annotations
import os
import subprocess
import shlex
from typing import Callable, Optional
from scanners.base import ScannerBackend

SCRIPTS_DIR = os.environ.get("CUSTOM_SCRIPTS_DIR", os.path.join(os.path.dirname(__file__), "..", "data", "custom_scripts"))
os.makedirs(SCRIPTS_DIR, exist_ok=True)


class CustomScriptScanner(ScannerBackend):
    scanner_type = "custom"

    def is_available(self) -> bool:
        return os.path.isdir(SCRIPTS_DIR)

    def launch(self, target: str, options: dict, on_progress: Optional[Callable[[int, str], None]] = None) -> dict:
        script_name = options.get("script_name", "")
        if not script_name:
            raise RuntimeError("options.script_name is required for custom script scans")

        script_path = os.path.realpath(os.path.join(SCRIPTS_DIR, script_name))
        if not script_path.startswith(os.path.realpath(SCRIPTS_DIR)):
            raise RuntimeError("Invalid script path")
        if not os.path.isfile(script_path):
            raise RuntimeError(f"Custom script not found: {script_name} (place it in {SCRIPTS_DIR})")
        if not os.access(script_path, os.X_OK):
            raise RuntimeError(f"Custom script is not executable: {script_name} (chmod +x it)")

        if on_progress:
            on_progress(10, f"Running custom script {script_name} against {target}")

        extra_args = shlex.split(options.get("extra_args", ""))
        cmd = [script_path, target, *extra_args]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=options.get("timeout_seconds", 600))
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Custom script {script_name} timed out")

        if on_progress:
            on_progress(90, "Script finished, parsing output")

        if proc.returncode != 0:
            raise RuntimeError(f"Custom script exited with code {proc.returncode}: {proc.stderr[:500]}")

        if on_progress:
            on_progress(100, "Complete")

        return {"raw_output": proc.stdout, "filename": f"custom_{script_name}_{target.replace('/', '_')}.out"}
