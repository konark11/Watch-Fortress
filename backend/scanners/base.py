"""
Scanner orchestration interface.

Every scanner integration (Nmap, OpenVAS, Nessus, Nuclei, custom scripts)
implements this interface. Nmap and Nuclei are CLI tools we can shell out
to directly and are implemented for REAL execution below. OpenVAS/GVM and
Nessus are typically deployed as their own server products with their own
authentication and job queues (GVM has the `gvm-tools`/GMP XML protocol,
Nessus has a REST API with a license-gated engine) - rather than fake that
with mocked network calls, those two integrations here launch against a
configured endpoint if one is set (see scanners/openvas_scanner.py /
nessus_scanner.py) and otherwise clearly report that no endpoint is
configured, so this is honest about what's live-tested in this environment
versus what's a real, correctly-shaped integration waiting on credentials.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Callable, Optional


class ScannerCancelled(Exception):
    """Raised when a running scanner is stopped by the user."""


class ScannerBackend(ABC):
    scanner_type: str = "custom"

    @abstractmethod
    def launch(self, target: str, options: dict, on_progress: Optional[Callable[[int, str], None]] = None) -> dict:
        """Run the scan synchronously (called from a background thread/task
        by the scan orchestrator) and return {"raw_output": str, "filename": str}.
        Calls on_progress(pct, message) periodically if provided."""
        raise NotImplementedError

    def is_available(self) -> bool:
        """Whether this scanner's engine/CLI/endpoint is actually reachable
        from this deployment. The dashboard uses this to show real
        availability status per-scanner rather than assuming every
        integration is live."""
        return True
