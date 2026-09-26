from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from models.database import get_db, Vulnerability, Asset, VulnStatus, User, Scan
from auth.security import get_current_user, require_permission
from auth.audit import log_action
from api.schemas import VulnStatusUpdate
from scheduling.scheduler import trigger_rescan_on_remediation

router = APIRouter()


@router.get("")
def list_vulnerabilities(
    severity: str | None = None,
    status: str | None = None,
    asset_id: int | None = None,
    search: str | None = None,
    limit: int = 200,
    offset: int = 0,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    query = db.query(Vulnerability)
    if severity:
        query = query.filter(Vulnerability.severity == severity)
    if status:
        query = query.filter(Vulnerability.status == status)
    if asset_id:
        query = query.filter(Vulnerability.asset_id == asset_id)
    if search:
        query = query.filter(Vulnerability.canonical_title.ilike(f"%{search}%"))

    total = query.count()
    vulns = query.order_by(Vulnerability.risk_score.desc()).offset(offset).limit(limit).all()

    out = []
    for v in vulns:
        asset = db.get(Asset, v.asset_id)
        out.append({
            "id": v.id, "title": v.canonical_title, "severity": v.severity.value,
            "cvss_score": v.cvss_score, "risk_score": v.risk_score,
            "cve_ids": v.cve_ids, "cwe_ids": v.cwe_ids, "capec_ids": v.capec_ids,
            "attack_techniques": v.attack_techniques, "owasp_categories": v.owasp_categories,
            "exploit_available": v.exploit_available, "kev_listed": v.kev_listed,
            "status": v.status.value, "source_scanners": v.source_scanners,
            "asset_ip": asset.ip_address if asset else None, "asset_id": v.asset_id,
            "port": v.port_number, "first_seen": v.first_seen, "last_seen": v.last_seen,
            "assigned_to": v.assigned_to,
        })
    return {"vulnerabilities": out, "total": total}


@router.get("/{vuln_id}")
def get_vulnerability(vuln_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    v = db.get(Vulnerability, vuln_id)
    if not v:
        raise HTTPException(404, "Vulnerability not found")
    asset = db.get(Asset, v.asset_id)
    from models.database import Finding
    contributing = db.query(Finding).filter(Finding.id.in_(v.contributing_finding_ids or [])).all()
    return {
        "id": v.id, "title": v.canonical_title, "description": v.description,
        "severity": v.severity.value, "cvss_score": v.cvss_score, "risk_score": v.risk_score,
        "cve_ids": v.cve_ids, "cwe_ids": v.cwe_ids, "capec_ids": v.capec_ids,
        "attack_techniques": v.attack_techniques, "owasp_categories": v.owasp_categories,
        "exploit_available": v.exploit_available, "kev_listed": v.kev_listed,
        "remediation": v.remediation, "status": v.status.value, "assigned_to": v.assigned_to,
        "asset": {"id": asset.id, "ip_address": asset.ip_address, "hostname": asset.hostname} if asset else None,
        "port": v.port_number, "source_scanners": v.source_scanners,
        "first_seen": v.first_seen, "last_seen": v.last_seen,
        "contributing_findings": [
            {"id": f.id, "scanner": f.scanner_source.value, "title": f.title, "plugin_id": f.plugin_id}
            for f in contributing
        ],
    }


@router.patch("/{vuln_id}/status")
def update_status(vuln_id: int, payload: VulnStatusUpdate, db: Session = Depends(get_db), user: User = Depends(require_permission("finding.write"))):
    v = db.get(Vulnerability, vuln_id)
    if not v:
        raise HTTPException(404, "Vulnerability not found")
    try:
        new_status = VulnStatus(payload.status)
    except ValueError:
        raise HTTPException(400, f"Invalid status. Must be one of {[s.value for s in VulnStatus]}")

    old_status = v.status
    v.status = new_status
    if payload.assigned_to is not None:
        v.assigned_to = payload.assigned_to
    db.commit()

    log_action(db, user, "finding.status_change", target=f"vulnerability:{vuln_id}", details=f"{old_status.value} -> {new_status.value}")

    if new_status == VulnStatus.REMEDIATED and old_status != VulnStatus.REMEDIATED:
        # find the schedule (if any) that originally discovered a finding on this asset
        recent_scan = (
            db.query(Scan)
            .filter(Scan.target.contains((db.get(Asset, v.asset_id) or Asset()).ip_address or "___"))
            .order_by(Scan.id.desc())
            .first()
        )
        if recent_scan and recent_scan.schedule_id:
            trigger_rescan_on_remediation(db, v.asset_id, recent_scan.schedule_id)

    return {"ok": True, "status": new_status.value}
