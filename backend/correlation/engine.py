"""
Vulnerability Correlation Engine.

Takes the raw per-scanner Findings that ingestion just wrote to the DB and
merges the ones that represent the SAME underlying vulnerability - possibly
reported by two or three different scanners with different titles/wording -
into a single Vulnerability record.

Matching strategy (in priority order):
  1. Same asset + at least one shared CVE ID -> same vulnerability.
     This is the strongest signal: two scanners citing CVE-2024-3400 on the
     same host are unambiguously describing the same flaw regardless of how
     differently each vendor titled their plugin/template.
  2. Same asset + same port + high title similarity (no CVE on either side,
     e.g. a generic "SSH weak ciphers" finding) -> same vulnerability.
  3. Otherwise -> a new Vulnerability record.

Every merge is enriched via knowledge.mapper (CVE -> CWE -> CAPEC -> ATT&CK
-> OWASP, KEV status) and scored via correlation.risk_scoring before being
written, so the Vulnerability table is always immediately queryable/
reportable without a separate enrichment pass.
"""
from __future__ import annotations
from difflib import SequenceMatcher
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from models.database import Asset, Port, Finding, Vulnerability, Severity, VulnStatus, Criticality
from knowledge.mapper import kb
from correlation.risk_scoring import compute_risk_score

TITLE_SIMILARITY_THRESHOLD = 0.72
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _title_similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


def _higher_severity(a: str, b: str) -> str:
    return a if SEVERITY_ORDER.get(a, 0) >= SEVERITY_ORDER.get(b, 0) else b


def correlate_new_findings(db: Session, finding_ids: list[int]) -> dict:
    """Run correlation for a specific batch of newly-inserted Finding rows
    (called right after ingestion). Returns a summary of how many new
    Vulnerability records were created vs. merged into existing ones."""
    created, merged = 0, 0

    for finding_id in finding_ids:
        finding: Finding = db.get(Finding, finding_id)
        if finding is None or finding.vulnerability_id is not None:
            continue

        asset = db.query(Asset).filter(Asset.ip_address == finding.asset_ip).first()
        if asset is None:
            continue

        match = _find_matching_vulnerability(db, asset.id, finding)

        if match:
            _merge_finding_into_vulnerability(db, match, finding)
            merged += 1
        else:
            vuln = _create_vulnerability_from_finding(db, asset, finding)
            finding.vulnerability_id = vuln.id
            created += 1

        db.commit()

    return {"created": created, "merged": merged}


def _find_matching_vulnerability(db: Session, asset_id: int, finding: Finding) -> Vulnerability | None:
    candidates = db.query(Vulnerability).filter(Vulnerability.asset_id == asset_id).all()

    if finding.cve_ids:
        finding_cves = set(finding.cve_ids)
        for cand in candidates:
            if finding_cves.intersection(set(cand.cve_ids or [])):
                return cand

    # Fallback: same port + similar title, and NEITHER side has a CVE
    # (if one side has a CVE and the other doesn't, they're not confidently
    # the same finding, so we deliberately do not match them here).
    if not finding.cve_ids:
        for cand in candidates:
            if cand.cve_ids:
                continue
            if finding.port_number is not None and cand.port_number != finding.port_number:
                continue
            if _title_similarity(finding.title, cand.canonical_title) >= TITLE_SIMILARITY_THRESHOLD:
                return cand

    return None


def _create_vulnerability_from_finding(db: Session, asset: Asset, finding: Finding) -> Vulnerability:
    enrichment = kb.enrich_from_cves(finding.cve_ids) if finding.cve_ids else {
        "cwe_ids": [], "capec_ids": [], "attack_techniques": [], "owasp_categories": [],
        "exploit_available": False, "kev_listed": False, "max_cvss": None,
    }

    cvss = finding.cvss_score or enrichment.get("max_cvss")
    risk = compute_risk_score(
        cvss_score=cvss,
        exploit_available=enrichment["exploit_available"],
        kev_listed=enrichment["kev_listed"],
        internet_exposed=asset.internet_exposed,
        asset_criticality=asset.criticality,
    )

    vuln = Vulnerability(
        asset_id=asset.id,
        canonical_title=finding.title,
        description=finding.description,
        severity=finding.severity,
        cvss_score=cvss,
        risk_score=risk["score"],
        cve_ids=finding.cve_ids,
        cwe_ids=enrichment["cwe_ids"],
        capec_ids=enrichment["capec_ids"],
        attack_techniques=enrichment["attack_techniques"],
        owasp_categories=enrichment["owasp_categories"],
        exploit_available=enrichment["exploit_available"],
        kev_listed=enrichment["kev_listed"],
        port_number=finding.port_number,
        remediation=finding.solution,
        status=VulnStatus.OPEN,
        source_scanners=[finding.scanner_source.value],
        contributing_finding_ids=[finding.id],
    )
    db.add(vuln)
    db.flush()
    return vuln


def _merge_finding_into_vulnerability(db: Session, vuln: Vulnerability, finding: Finding):
    finding.vulnerability_id = vuln.id

    merged_cves = sorted(set(vuln.cve_ids or []) | set(finding.cve_ids or []))
    if merged_cves != (vuln.cve_ids or []):
        vuln.cve_ids = merged_cves
        enrichment = kb.enrich_from_cves(merged_cves)
        vuln.cwe_ids = enrichment["cwe_ids"]
        vuln.capec_ids = enrichment["capec_ids"]
        vuln.attack_techniques = enrichment["attack_techniques"]
        vuln.owasp_categories = enrichment["owasp_categories"]
        vuln.exploit_available = vuln.exploit_available or enrichment["exploit_available"]
        vuln.kev_listed = vuln.kev_listed or enrichment["kev_listed"]
        if enrichment.get("max_cvss") and (vuln.cvss_score is None or enrichment["max_cvss"] > vuln.cvss_score):
            vuln.cvss_score = enrichment["max_cvss"]

    if finding.cvss_score and (vuln.cvss_score is None or finding.cvss_score > vuln.cvss_score):
        vuln.cvss_score = finding.cvss_score

    vuln.severity = _higher_severity(vuln.severity.value if hasattr(vuln.severity, "value") else vuln.severity,
                                      finding.severity.value if hasattr(finding.severity, "value") else finding.severity)

    scanners = set(vuln.source_scanners or [])
    scanners.add(finding.scanner_source.value)
    vuln.source_scanners = sorted(scanners)

    contributing = set(vuln.contributing_finding_ids or [])
    contributing.add(finding.id)
    vuln.contributing_finding_ids = sorted(contributing)

    if not vuln.remediation and finding.solution:
        vuln.remediation = finding.solution

    vuln.last_seen = datetime.now(timezone.utc)

    # Multiple independent scanners agreeing on the same flaw is itself a
    # confidence signal worth reflecting in risk score - recompute.
    asset = db.get(Asset, vuln.asset_id)
    risk = compute_risk_score(
        cvss_score=vuln.cvss_score,
        exploit_available=vuln.exploit_available,
        kev_listed=vuln.kev_listed,
        internet_exposed=asset.internet_exposed if asset else False,
        asset_criticality=asset.criticality if asset else Criticality.MEDIUM,
    )
    multi_scanner_bonus = min(5.0, (len(scanners) - 1) * 5.0)
    vuln.risk_score = min(100.0, risk["score"] + multi_scanner_bonus)
