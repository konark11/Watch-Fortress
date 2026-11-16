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

Each corpus entry is a flat {id, source, title, text} dict. The vector
retriever embeds this text once when the index is built.
"""
from __future__ import annotations
from sqlalchemy.orm import Session
from knowledge.mapper import kb
from models.database import Asset, Finding, KnowledgeChunk, KnowledgeDoc, Scan, Vulnerability


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
            "metadata": {"document_type": "CVE", "severity": str(meta.get("severity", "unknown")).lower()},
        })

    for cwe_id, meta in kb.cwe_db.items():
        docs.append({
            "id": f"cwe:{cwe_id}",
            "source": "CWE",
            "title": f"{cwe_id} - {meta.get('name', '')}",
            "text": f"{cwe_id} ({meta.get('name', '')}): {meta.get('description', '')}",
            "metadata": {"document_type": "CWE"},
        })

    for capec_id, meta in kb.capec_db.items():
        docs.append({
            "id": f"capec:{capec_id}",
            "source": "CAPEC",
            "title": f"{capec_id} - {meta.get('name', '')}",
            "text": f"{capec_id} ({meta.get('name', '')}): {meta.get('description', '')}",
            "metadata": {"document_type": "CAPEC"},
        })

    for tech_id, meta in kb.attack_db.items():
        docs.append({
            "id": f"attack:{tech_id}",
            "source": "MITRE ATT&CK",
            "title": f"{tech_id} - {meta.get('name', '')}",
            "text": f"MITRE ATT&CK {tech_id} ({meta.get('name', '')}) belongs to the {meta.get('tactic', '')} tactic.",
            "metadata": {"document_type": "MITRE ATT&CK"},
        })

    for owasp_id, meta in kb.owasp_db.items():
        docs.append({
            "id": f"owasp:{owasp_id}",
            "source": "OWASP",
            "title": f"{owasp_id} - {meta.get('name', '')}",
            "text": f"OWASP Top 10 {owasp_id}: {meta.get('name', '')}.",
            "metadata": {"document_type": "OWASP"},
        })

    if db is not None:
        for kdoc in db.query(KnowledgeDoc).all():
            chunks = db.query(KnowledgeChunk).filter(KnowledgeChunk.document_id == kdoc.id).order_by(KnowledgeChunk.chunk_index).all()
            if not chunks:
                docs.append({
                    "id": f"kb:{kdoc.id}",
                    "source": f"Internal KB ({kdoc.category.value})",
                    "title": kdoc.title,
                    "metadata": {"document_type": "Internal KB", "document_id": kdoc.id},
                    "text": f"{kdoc.title}: {kdoc.content}",
                })
            for chunk in chunks:
                metadata = chunk.metadata_json or {}
                if metadata.get("indexed") is False:
                    continue
                docs.append({
                    "id": f"kb-chunk:{chunk.id}",
                    "source": f"Internal KB ({kdoc.category.value})",
                    "title": f"{kdoc.title} (chunk {chunk.chunk_index + 1})",
                    "text": chunk.content,
                    "embedding": chunk.embedding,
                    "metadata": {
                        "document_type": "Internal KB",
                        "document_id": kdoc.id,
                        "embedding": metadata.get("embedding"),
                        **metadata,
                    },
                })

        # Keep completed scan evidence in the same retrievable corpus as the
        # security reference data. This lets the assistant answer questions
        # about what the platform actually found, rather than only explain
        # generic CVE/CWE concepts.
        # Completion time is the source of truth for recency; IDs can be
        # allocated before a background scan finishes.
        for scan in (
            db.query(Scan)
            .order_by(Scan.finished_at.desc(), Scan.id.desc())
            .all()
        ):
            findings = list(scan.findings)
            hosts = sorted({finding.asset_ip for finding in findings if finding.asset_ip})
            finding_lines = []
            for finding in findings:
                cves = ", ".join(finding.cve_ids or []) or "none"
                finding_lines.append(
                    f"{finding.title} on {finding.asset_ip or 'unknown host'}"
                    f" (severity: {finding.severity.value}, port: {finding.port_number or 'n/a'}, "
                    f"CVEs: {cves}). Description: {finding.description or 'not provided'} "
                    f"Remediation: {finding.solution or 'not provided'}"
                )

            clean_target = scan.target.split("://")[-1].split("/")[0].split(":")[0].strip().lower()
            asset = db.query(Asset).filter(
                (Asset.ip_address.ilike(clean_target)) | (Asset.hostname.ilike(clean_target))
            ).first()
            if not asset and clean_target:
                asset = db.query(Asset).filter(
                    (Asset.hostname.ilike(f"%{clean_target}%")) | (Asset.ip_address.ilike(f"%{clean_target}%"))
                ).first()
            port_lines = []
            if asset and asset.ports:
                port_lines = [
                    f"{p.port_number}/{p.protocol} ({p.service_name or 'unknown'}{' ' + p.product if p.product else ''}{' ' + p.version if p.version else ''})".strip()
                    for p in asset.ports
                ]
            ports_summary = f"Discovered open ports on {scan.target}: {', '.join(port_lines)}." if port_lines else "Discovered open ports: none recorded."

            docs.append({
                "id": f"scan:{scan.id}",
                "source": "Completed scan",
                "title": f"{scan.name} - {scan.target}",
                "text": (
                    f"Scan {scan.name} targeted {scan.target}. Scanner: {scan.scanner_type.value}. "
                    f"Status: {scan.status.value}. Findings: {scan.findings_count}. "
                    f"Hosts with findings: {', '.join(hosts) or 'none'}. "
                    f"{ports_summary} "
                    f"Completed: {scan.finished_at or 'unknown'}. "
                    f"Finding details: {' '.join(finding_lines) or 'No findings were reported.'}"
                ),
                "metadata": {"document_type": "Completed scan", "scan_id": scan.id},
            })

        for finding in db.query(Finding).order_by(Finding.id.desc()).all():
            vulnerability = db.get(Vulnerability, finding.vulnerability_id) if finding.vulnerability_id else None
            docs.append({
                "id": f"finding:{finding.id}",
                "source": "Scan finding",
                "title": finding.title,
                "text": (
                    f"Finding from {finding.scanner_source.value} scan {finding.scan_id}: "
                    f"{finding.title} on {finding.asset_ip or 'unknown host'}, "
                    f"port {finding.port_number or 'n/a'}, severity {finding.severity.value}, "
                    f"CVEs: {', '.join(finding.cve_ids or []) or 'none'}. "
                    f"Description: {finding.description or 'not provided'}. "
                    f"Remediation: {finding.solution or 'not provided'}. "
                    f"Correlated vulnerability: {vulnerability.canonical_title if vulnerability else 'none'}."
                ),
                "metadata": {
                    "document_type": "Scan finding",
                    "severity": finding.severity.value,
                    "port": finding.port_number,
                    "cves": finding.cve_ids or [],
                    "vm": finding.asset_ip,
                    "scan_id": finding.scan_id,
                },
            })

        for asset in db.query(Asset).all():
            ports = ", ".join(
                f"{port.port_number}/{port.protocol} {port.service_name or ''} {port.product or ''} {port.version or ''}".strip()
                for port in asset.ports
            ) or "none recorded"
            docs.append({
                "id": f"asset:{asset.id}",
                "source": "Scanned asset",
                "title": f"{asset.ip_address} - {asset.hostname or 'unnamed host'}",
                "text": (
                    f"Scanned asset {asset.ip_address}, hostname {asset.hostname or 'unknown'}, "
                    f"OS {asset.os_name or 'unknown'}, internet exposed: {asset.internet_exposed}. "
                    f"Criticality: {asset.criticality.value}. Open or discovered ports and services: {ports}."
                ),
                "metadata": {"document_type": "Scanned asset", "vm": asset.ip_address},
            })

    return docs
