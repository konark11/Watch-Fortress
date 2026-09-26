"""
Builds the retrievable document corpus for the RAG assistant.

Sources (matches the spec's "retrieves information from" list):
  - CVE Database, NVD-equivalent data  -> knowledge/data/cve_db.json
  - MITRE ATT&CK                        -> knowledge/data/attack_db.json
  - CWE                                 -> knowledge/data/cwe_db.json
  - CAPEC                               -> knowledge/data/capec_db.json
  - OWASP                               -> knowledge/data/owasp_db.json
  - Internal documentation              -> KnowledgeDoc table (playbooks,
                                            write-ups, remediation guides,
                                            policies, lessons learned)

"Vendor advisories" are represented by the `references` field already
present on each CVE record; a real deployment would extend this corpus
builder to also pull in locally-mirrored vendor bulletins the same way
KnowledgeDoc entries are pulled in today - see knowledge/updater.py for
how new offline intel gets added without code changes.

Each corpus entry is a flat {id, source, title, text} dict - simple and
inspectable, since the retriever needs raw text, not embeddings.
"""
from __future__ import annotations
from sqlalchemy.orm import Session
from knowledge.mapper import kb
from models.database import KnowledgeDoc


def build_corpus(db: Session | None = None) -> list[dict]:
    docs: list[dict] = []

    for cve_id, meta in kb.cve_db.items():
        docs.append({
            "id": f"cve:{cve_id}",
            "source": "CVE",
            "title": f"{cve_id} - {meta.get('product', '')}",
            "text": (
                f"{cve_id}: {meta.get('description', '')} "
                f"Vendor: {meta.get('vendor', '')}. Product: {meta.get('product', '')}. "
                f"CVSS v3: {meta.get('cvss_v3', 'unknown')}. Severity: {meta.get('severity', 'unknown')}. "
                f"Published: {meta.get('published', 'unknown')}. "
                f"Known actively exploited: {'yes' if kb.is_kev(cve_id) else 'no'}. "
                f"Related CWEs: {', '.join(meta.get('cwe', []))}."
            ),
        })

    for cwe_id, meta in kb.cwe_db.items():
        docs.append({
            "id": f"cwe:{cwe_id}",
            "source": "CWE",
            "title": f"{cwe_id} - {meta.get('name', '')}",
            "text": f"{cwe_id} ({meta.get('name', '')}): {meta.get('description', '')}",
        })

    for capec_id, meta in kb.capec_db.items():
        docs.append({
            "id": f"capec:{capec_id}",
            "source": "CAPEC",
            "title": f"{capec_id} - {meta.get('name', '')}",
            "text": f"{capec_id} ({meta.get('name', '')}): {meta.get('description', '')}",
        })

    for tech_id, meta in kb.attack_db.items():
        docs.append({
            "id": f"attack:{tech_id}",
            "source": "MITRE ATT&CK",
            "title": f"{tech_id} - {meta.get('name', '')}",
            "text": f"MITRE ATT&CK {tech_id} ({meta.get('name', '')}) belongs to the {meta.get('tactic', '')} tactic.",
        })

    for owasp_id, meta in kb.owasp_db.items():
        docs.append({
            "id": f"owasp:{owasp_id}",
            "source": "OWASP",
            "title": f"{owasp_id} - {meta.get('name', '')}",
            "text": f"OWASP Top 10 {owasp_id}: {meta.get('name', '')}.",
        })

    if db is not None:
        for kdoc in db.query(KnowledgeDoc).all():
            docs.append({
                "id": f"kb:{kdoc.id}",
                "source": f"Internal KB ({kdoc.category.value})",
                "title": kdoc.title,
                "text": f"{kdoc.title}: {kdoc.content}",
            })

    return docs
