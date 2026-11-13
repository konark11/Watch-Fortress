"""
Offline Vulnerability Intelligence & Knowledge Base Updater.

Fetches and merges the latest threat intelligence datasets from official and
curated sources:
  - CISA Known Exploited Vulnerabilities (KEV) Catalog
  - MITRE ATT&CK Enterprise Techniques (STIX 2.1)
  - Common Weakness Enumeration (CWE) Catalog
  - Common Attack Pattern Enumeration and Classification (CAPEC STIX 2.1)
  - OWASP Top 10 (Web, API Security, and LLM Applications)
  - Pre-seeded Security Remediation Playbooks and Architecture Baselines

Preserves all existing mappings and entries while significantly expanding the
corpus available for semantic retrieval and embeddings.
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
import urllib.request
from typing import Any

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from knowledge.mapper import kb
from models.database import SessionLocal, KnowledgeDoc, KBCategory
from rag.document_ingestion import persist_chunks

logger = logging.getLogger("watch_fortress.knowledge_updater")
_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")

TACTIC_MAP = {
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
}

OWASP_ADDITIONS = {
    "API1:2023": {"name": "Broken Object Level Authorization (BOLA)", "related_cwe": ["CWE-284", "CWE-285", "CWE-639"]},
    "API2:2023": {"name": "Broken Authentication", "related_cwe": ["CWE-287", "CWE-306"]},
    "API3:2023": {"name": "Broken Object Property Level Authorization", "related_cwe": ["CWE-213", "CWE-915"]},
    "API4:2023": {"name": "Unrestricted Resource Consumption", "related_cwe": ["CWE-400", "CWE-770"]},
    "API5:2023": {"name": "Broken Function Level Authorization (BFLA)", "related_cwe": ["CWE-285"]},
    "API6:2023": {"name": "Unrestricted Access to Sensitive Business Flows", "related_cwe": ["CWE-799"]},
    "API7:2023": {"name": "Server Side Request Forgery (SSRF)", "related_cwe": ["CWE-918"]},
    "API8:2023": {"name": "Security Misconfiguration", "related_cwe": ["CWE-16", "CWE-200"]},
    "API9:2023": {"name": "Improper Inventory Management", "related_cwe": ["CWE-1059"]},
    "API10:2023": {"name": "Unsafe Consumption of APIs", "related_cwe": ["CWE-20"]},
    "LLM01:2025": {"name": "Prompt Injection", "related_cwe": ["CWE-77", "CWE-20"]},
    "LLM02:2025": {"name": "Sensitive Information Disclosure", "related_cwe": ["CWE-200"]},
    "LLM03:2025": {"name": "Supply Chain Vulnerabilities", "related_cwe": ["CWE-1104"]},
    "LLM04:2025": {"name": "Data and Model Poisoning", "related_cwe": ["CWE-502"]},
    "LLM05:2025": {"name": "Improper Output Handling", "related_cwe": ["CWE-79"]},
    "LLM06:2025": {"name": "Excessive Agency", "related_cwe": ["CWE-284"]},
    "LLM07:2025": {"name": "System Prompt Leakage", "related_cwe": ["CWE-200"]},
    "LLM08:2025": {"name": "Vector and Embedding Weaknesses", "related_cwe": ["CWE-284"]},
    "LLM09:2025": {"name": "Misinformation", "related_cwe": ["CWE-20"]},
    "LLM10:2025": {"name": "Unbounded Consumption", "related_cwe": ["CWE-400"]},
}

from knowledge.reference_docs import REFERENCE_DOCS

REFERENCE_PLAYBOOKS = REFERENCE_DOCS


def _load(filename: str) -> dict:
    path = os.path.join(_DATA_DIR, filename)
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _save(filename: str, data: dict[str, Any]) -> None:
    path = os.path.join(_DATA_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _fetch_url(url: str, timeout: int = 90) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": "WatchFortress-KB-Updater/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def update_cisa_kev_and_cves() -> tuple[int, int]:
    """Fetch official CISA KEV catalog and update both cisa_kev.json and cve_db.json."""
    url = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
    data = _fetch_url(url)
    vulnerabilities = data.get("vulnerabilities", [])

    cisa_kev = _load("cisa_kev.json")
    cve_db = _load("cve_db.json")

    new_kev_count = 0
    new_cve_count = 0

    for item in vulnerabilities:
        cve_id = (item.get("cveID") or "").strip().upper()
        if not cve_id:
            continue

        if cve_id not in cisa_kev:
            v_name = item.get("vulnerabilityName", "")
            s_desc = item.get("shortDescription", "")
            cisa_kev[cve_id] = {
                "date_added": item.get("dateAdded", ""),
                "due_date": item.get("dueDate", ""),
                "vendor_project": item.get("vendorProject", ""),
                "notes": f"{v_name}: {s_desc}"[:300].strip(),
            }
            new_kev_count += 1

        if cve_id not in cve_db:
            desc = item.get("shortDescription") or item.get("vulnerabilityName") or ""
            is_critical = any(
                kw in desc.lower()
                for kw in [
                    "remote code execution", " rce", "command injection",
                    "privilege escalation", "arbitrary code", "unauthenticated",
                    "pre-auth", "authentication bypass", "arbitrary command",
                ]
            )
            cvss = 9.8 if is_critical else 8.5
            severity = "critical" if is_critical else "high"
            cwes = [c.upper() for c in item.get("cwes", []) if c.upper().startswith("CWE-")]

            notes = item.get("notes", "")
            refs = [ref.strip() for ref in notes.split(";") if ref.strip().startswith("http")]

            cve_db[cve_id] = {
                "description": desc,
                "cvss_v3": cvss,
                "severity": severity,
                "cwe": cwes,
                "published": item.get("dateAdded", ""),
                "vendor": item.get("vendorProject", ""),
                "product": item.get("product", ""),
                "exploit_available": True,
                "references": refs,
            }
            new_cve_count += 1

    _save("cisa_kev.json", cisa_kev)
    _save("cve_db.json", cve_db)
    return new_kev_count, new_cve_count


def update_cwe() -> int:
    """Fetch full CWE catalog from APTRS mirror and update cwe_db.json."""
    url = "https://raw.githubusercontent.com/APTRS/APTRS-CWE/main/cwe.json"
    data = _fetch_url(url)

    cwe_db = _load("cwe_db.json")
    new_cwe_count = 0

    for item in data:
        full_name = item.get("name", "")
        desc = item.get("description", "")
        match = re.match(r"^(CWE-\d+):\s*(.*)$", full_name)
        if match:
            cwe_id = match.group(1).upper()
            cwe_name = match.group(2).strip()
            if cwe_id not in cwe_db:
                cwe_db[cwe_id] = {
                    "name": cwe_name,
                    "description": desc,
                }
                new_cwe_count += 1

    _save("cwe_db.json", cwe_db)
    return new_cwe_count


def update_capec_and_cwe_mappings() -> tuple[int, int]:
    """Fetch MITRE CAPEC STIX bundle, update capec_db.json and enrich cwe_to_attack.json."""
    url = "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json"
    data = _fetch_url(url)

    capec_db = _load("capec_db.json")
    cwe_to_attack = _load("cwe_to_attack.json")

    new_capec_count = 0
    updated_mappings = 0

    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked", False):
            continue

        capec_id = None
        related_cwes = []
        attack_techs = []

        for ref in obj.get("external_references", []):
            ext_id = (ref.get("external_id") or "").strip()
            if ext_id.startswith("CAPEC-"):
                capec_id = ext_id
            elif ext_id.startswith("CWE-"):
                related_cwes.append(ext_id)
            elif re.match(r"^T\d{4}(?:\.\d{3})?$", ext_id):
                attack_techs.append(ext_id)

        if not capec_id:
            continue

        if capec_id not in capec_db:
            capec_db[capec_id] = {
                "name": obj.get("name", ""),
                "description": obj.get("description", ""),
                "related_cwe": sorted(list(set(related_cwes))),
            }
            new_capec_count += 1
        else:
            existing = capec_db[capec_id]
            merged_cwes = sorted(list(set(existing.get("related_cwe", []) + related_cwes)))
            if merged_cwes != existing.get("related_cwe", []):
                existing["related_cwe"] = merged_cwes

        for cwe_id in related_cwes:
            if attack_techs:
                current = set(cwe_to_attack.get(cwe_id, []))
                before_len = len(current)
                current.update(attack_techs)
                if len(current) > before_len:
                    cwe_to_attack[cwe_id] = sorted(list(current))
                    updated_mappings += 1

    _save("capec_db.json", capec_db)
    _save("cwe_to_attack.json", cwe_to_attack)
    return new_capec_count, updated_mappings


def update_mitre_attack() -> int:
    """Fetch MITRE ATT&CK Enterprise STIX dataset and update attack_db.json."""
    url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    data = _fetch_url(url)

    attack_db = _load("attack_db.json")
    new_attack_count = 0

    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked", False):
            continue

        tech_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                candidate = (ref.get("external_id") or "").strip()
                if candidate.startswith("T"):
                    tech_id = candidate
                    break

        if not tech_id:
            continue

        tactic = "Unknown"
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                phase_name = phase.get("phase_name")
                if phase_name in TACTIC_MAP:
                    tactic = TACTIC_MAP[phase_name]
                    break

        if tech_id not in attack_db:
            attack_db[tech_id] = {
                "name": obj.get("name", ""),
                "tactic": tactic,
            }
            new_attack_count += 1

    _save("attack_db.json", attack_db)
    return new_attack_count


def update_owasp() -> int:
    """Enrich OWASP database with API Security and LLM Top 10 categories."""
    owasp_db = _load("owasp_db.json")
    added = 0
    for key, val in OWASP_ADDITIONS.items():
        if key not in owasp_db:
            owasp_db[key] = val
            added += 1

    _save("owasp_db.json", owasp_db)
    return added


def seed_reference_playbooks() -> int:
    """Seed comprehensive reference playbooks into KnowledgeDoc with deterministic embeddings."""
    db = SessionLocal()
    seeded_count = 0
    try:
        existing_titles = {doc.title for doc in db.query(KnowledgeDoc.title).all()}
        for playbook in REFERENCE_PLAYBOOKS:
            title = playbook["title"]
            if title in existing_titles:
                continue

            doc = KnowledgeDoc(
                title=title,
                category=playbook["category"],
                content=playbook["content"].strip(),
                tags=playbook["tags"],
                created_by="system_seeder",
            )
            db.add(doc)
            db.flush()

            persist_chunks(
                db=db,
                document=doc,
                text=doc.content,
                filename=f"{doc.category.value}_{title[:20].lower().replace(' ', '_')}.md",
                content_type="text/markdown",
            )
            db.commit()
            seeded_count += 1
    finally:
        db.close()
    return seeded_count


def update_all(include_playbooks: bool = True) -> dict[str, int]:
    """Execute all intelligence updates and reload the in-memory knowledge base."""
    cisa_kev_new, cve_new = update_cisa_kev_and_cves()
    cwe_new = update_cwe()
    capec_new, cwe_mapping_updates = update_capec_and_cwe_mappings()
    attack_new = update_mitre_attack()
    owasp_new = update_owasp()

    kb.reload()

    playbooks_seeded = seed_reference_playbooks() if include_playbooks else 0

    return {
        "cve_new": cve_new,
        "cisa_kev_new": cisa_kev_new,
        "cwe_new": cwe_new,
        "capec_new": capec_new,
        "attack_new": attack_new,
        "owasp_new": owasp_new,
        "cwe_mappings_updated": cwe_mapping_updates,
        "playbooks_seeded": playbooks_seeded,
    }


if __name__ == "__main__":
    print("Beginning Knowledge Base expansion from official online feeds...")
    results = update_all()
    print("Update complete! Results:")
    for k, v in results.items():
        print(f"  {k}: {v}")
    print(
        f"Total in-memory KB: {len(kb.cve_db)} CVEs, {len(kb.attack_db)} ATT&CK, "
        f"{len(kb.cwe_db)} CWEs, {len(kb.capec_db)} CAPECs, {len(kb.owasp_db)} OWASP categories"
    )
