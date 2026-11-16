"""
Offline vulnerability intelligence layer.

Every lookup here reads from local JSON files bundled with the platform
(backend/knowledge/data/) - no NVD API call, no internet access. This is
the "air-gapped local RAG mode" data source as well as the source of truth
for the correlation engine's CVE -> CWE -> CAPEC -> ATT&CK -> OWASP
mapping chain.

Like the offline update mechanism in the SOC Log Analytics platform, these
JSON files are designed to be refreshed from a real NVD/CISA-KEV/MITRE
export on a connected staging machine and carried across the air gap -
see knowledge/updater.py.
"""
from __future__ import annotations
import json
import os
from typing import Optional

_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
_SCRATCH_DIR = os.path.join(
    os.path.expanduser("~"), ".gemini", "antigravity-cli", "brain",
    "c9decda5-e321-4c19-97a8-ccf915ac9edd", "scratch"
)


def _load(filename: str) -> dict:
    # 1. Check for scratch-updated version if available
    basename = filename.replace(".json", "")
    for candidate_name in (f"{basename}_updated.json", f"{basename}_eval.json"):
        if _SCRATCH_DIR and os.path.isdir(_SCRATCH_DIR):
            scratch_path = os.path.join(_SCRATCH_DIR, candidate_name)
            if os.path.exists(scratch_path):
                try:
                    with open(scratch_path, "r", encoding="utf-8") as f:
                        return json.load(f)
                except Exception:
                    pass

    # 2. Check standard knowledge/data directory
    path = os.path.join(_DATA_DIR, filename)
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


class VulnKnowledgeBase:
    def __init__(self):
        self.reload()

    def reload(self):
        self.cve_db = _load("cve_db.json")
        self.cwe_db = _load("cwe_db.json")
        self.capec_db = _load("capec_db.json")
        self.attack_db = _load("attack_db.json")
        self.owasp_db = _load("owasp_db.json")
        self.cwe_to_attack = _load("cwe_to_attack.json")
        self.kev_catalog = _load("cisa_kev.json")

        # Build reverse indices once, at load time, so per-finding mapping
        # calls are O(1) dict lookups rather than repeated linear scans.
        self._cwe_to_capec: dict[str, list[str]] = {}
        for capec_id, meta in self.capec_db.items():
            for cwe in meta.get("related_cwe", []):
                self._cwe_to_capec.setdefault(cwe, []).append(capec_id)

        self._cwe_to_owasp: dict[str, list[str]] = {}
        for owasp_id, meta in self.owasp_db.items():
            for cwe in meta.get("related_cwe", []):
                self._cwe_to_owasp.setdefault(cwe, []).append(owasp_id)

    # --- single-item lookups -----------------------------------------
    def lookup_cve(self, cve_id: str) -> dict:
        return self.cve_db.get(cve_id.upper(), {})

    def lookup_cwe(self, cwe_id: str) -> dict:
        return self.cwe_db.get(cwe_id.upper(), {"name": cwe_id, "description": ""})

    def lookup_capec(self, capec_id: str) -> dict:
        return self.capec_db.get(capec_id.upper(), {"name": capec_id, "description": ""})

    def lookup_attack(self, technique_id: str) -> dict:
        return self.attack_db.get(technique_id.upper(), {"name": technique_id, "tactic": "Unknown"})

    def lookup_owasp(self, owasp_id: str) -> dict:
        if not owasp_id:
            return {"name": owasp_id or ""}
        return self.owasp_db.get(owasp_id.upper(), {"name": owasp_id})

    def is_kev(self, cve_id: str) -> Optional[dict]:
        return self.kev_catalog.get(cve_id.upper())

    # --- the full mapping chain for a set of CVE IDs -------------------
    def enrich_from_cves(self, cve_ids: list[str]) -> dict:
        """Given one or more CVE IDs from a finding, walk CVE -> CWE -> CAPEC
        -> ATT&CK -> OWASP and return everything the correlation engine and
        risk scorer need."""
        cwe_ids: set[str] = set()
        capec_ids: set[str] = set()
        attack_ids: set[str] = set()
        owasp_ids: set[str] = set()
        exploit_available = False
        kev_listed = False
        kev_details = None
        max_cvss = None
        descriptions = []

        for cve_id in cve_ids:
            cve_id = cve_id.upper()
            meta = self.lookup_cve(cve_id)
            if meta:
                cwe_ids.update(meta.get("cwe", []))
                if meta.get("exploit_available"):
                    exploit_available = True
                if meta.get("cvss_v3") is not None:
                    max_cvss = meta["cvss_v3"] if max_cvss is None else max(max_cvss, meta["cvss_v3"])
                if meta.get("description"):
                    descriptions.append(meta["description"])
            kev = self.is_kev(cve_id)
            if kev:
                kev_listed = True
                kev_details = kev

        for cwe_id in list(cwe_ids):
            capec_ids.update(self._cwe_to_capec.get(cwe_id, []))
            attack_ids.update(self.cwe_to_attack.get(cwe_id, []))
            owasp_ids.update(self._cwe_to_owasp.get(cwe_id, []))

        return {
            "cwe_ids": sorted(cwe_ids),
            "capec_ids": sorted(capec_ids),
            "attack_techniques": sorted(attack_ids),
            "owasp_categories": sorted(owasp_ids),
            "exploit_available": exploit_available,
            "kev_listed": kev_listed,
            "kev_details": kev_details,
            "max_cvss": max_cvss,
            "cve_descriptions": descriptions,
        }


# Module-level singleton - loaded once at process start, reload() is called
# by the offline-update installer when new intel data is dropped in.
kb = VulnKnowledgeBase()
